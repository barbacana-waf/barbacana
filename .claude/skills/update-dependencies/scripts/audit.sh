#!/usr/bin/env bash
# Read-only dependency audit for the barbacana repo. Changes nothing.
#
# Reports everything that is not on its latest version, plus every open
# vulnerability signal, so the update can be done in one pass:
#   1. Go toolchain (go.mod `go` directive)
#   2. Every module listed in go.mod (direct AND indirect)
#   3. Pinned tools in versions.mk
#   4. SHA-pinned GitHub Actions in .github/
#   5. Open Dependabot alerts, code-scanning alerts and Dependabot PRs
#   6. Local scans: govulncheck and trivy fs WITHOUT --ignore-unfixed
#
# Minimum release age: a version published less than MIN_AGE_HOURS ago (default
# 24) is never proposed. Status words:
#   OUTDATED  a newer version old enough to take exists (the target is shown)
#   HELD      newer versions exist but all are younger than MIN_AGE_HOURS
#   YOUNG     the version pinned right now is younger than MIN_AGE_HOURS
#
# Usage: [MIN_AGE_HOURS=24] audit.sh [repo-root]   (default: git toplevel of the cwd)
# Needs: go, gh (authenticated), jq, curl; trivy optional.

set -uo pipefail

ROOT="${1:-$(git rev-parse --show-toplevel)}"
cd "$ROOT" || exit 1
REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo barbacana-waf/barbacana)"

MIN_AGE_HOURS="${MIN_AGE_HOURS:-24}"
NOW="$(date -u +%s)"

hdr() { printf '\n== %s ==\n' "$1"; }
norm() { echo "${1#v}"; }

# Whole hours since an RFC 3339 timestamp; "?" when there is none.
age_h() {
	case "$1" in "" | null | "?") echo "?"; return ;; esac
	jq -rn --arg t "$1" --argjson now "$NOW" \
		'(($now - ($t | sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z") | fromdateiso8601)) / 3600) | floor'
}
old_enough() { [ "$1" != "?" ] && [ "$1" -ge "$MIN_AGE_HOURS" ]; }
newer() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]; }

# GitHub repo releases: prints "<eligible> <latest> <latest-age-h> <current-age-h>".
# latest = highest plain-semver, non-prerelease release (skips side tags such as
# codeql-action's codeql-bundle-*); eligible = highest one at least
# MIN_AGE_HOURS old, or NONE. Falls back to tags, which carry no date.
gh_pick() {
	local repo="$1" cur="$2" rows latest lage cage elig tag ts
	rows="$(gh api "repos/$repo/releases?per_page=50" \
		--jq '.[] | select(.prerelease|not) | "\(.tag_name) \(.published_at)"' 2>/dev/null |
		grep -E '^v?[0-9]+(\.[0-9]+)* ' | sort -V -r -k1,1)"
	if [ -z "$rows" ]; then
		latest="$(gh api "repos/$repo/tags?per_page=100" --jq '.[].name' 2>/dev/null |
			grep -E '^v?[0-9]+(\.[0-9]+)*$' | sort -V | tail -1)"
		echo "${latest:-NONE} ${latest:-NONE} ? ?"
		return
	fi
	latest="${rows%% *}"
	lage="$(age_h "$(echo "$rows" | head -1 | cut -d' ' -f2)")"
	cage="$(age_h "$(echo "$rows" | awk -v c="$cur" '$1 == c || $1 == "v" c || "v" $1 == c { print $2; exit }')")"
	elig=NONE
	while read -r tag ts; do
		old_enough "$(age_h "$ts")" && { elig="$tag"; break; }
	done <<<"$rows"
	echo "$elig $latest $lage $cage"
}

# Go module: prints "<eligible> <latest> <latest-age-h>". Walks tagged versions
# down from @latest until one is MIN_AGE_HOURS old. Modules with no tags
# (pseudo-versions only) give NONE when @latest is too young.
mod_pick() {
	local j latest lage v
	j="$(GOFLAGS=-mod=mod go list -m -json "$1@latest" 2>/dev/null)" || { echo "NONE NONE ?"; return; }
	latest="$(jq -r .Version <<<"$j")"
	lage="$(age_h "$(jq -r .Time <<<"$j")")"
	if old_enough "$lage"; then echo "$latest $latest $lage"; return; fi
	for v in $(GOFLAGS=-mod=mod go list -m -versions "$1" 2>/dev/null | tr ' ' '\n' | tail -n +2 | sort -V -r); do
		[ "$v" = "$latest" ] && continue
		if old_enough "$(age_h "$(GOFLAGS=-mod=mod go list -m -json "$1@$v" 2>/dev/null | jq -r .Time)")"; then
			echo "$v $latest $lage"
			return
		fi
	done
	echo "NONE $latest $lage"
}

# One status line from a pick: report <name> <current> <eligible> <latest> <latest-age> <current-age> <how-to-update>
report() {
	local name="$1" cur="$2" elig="$3" latest="$4" lage="$5" cage="$6" how="$7"
	local young=""
	if [ "$cage" != "?" ] && ! old_enough "$cage"; then
		young=1
		echo "YOUNG    $name $cur is ${cage}h old (< ${MIN_AGE_HOURS}h): roll back unless it fixes an open advisory"
	fi
	if [ "$latest" = NONE ] || [ -z "$latest" ] || [ "$latest" = null ]; then
		echo "UNKNOWN  $name $cur   (could not resolve latest)"
	elif [ "$(norm "$cur")" = "$(norm "$latest")" ]; then
		[ -z "$young" ] && echo "ok       $name $cur"
	elif [ "$elig" != NONE ] && newer "$(norm "$elig")" "$(norm "$cur")"; then
		local note=""
		[ "$(norm "$elig")" != "$(norm "$latest")" ] && note=" (latest $latest is ${lage}h old, held)"
		echo "OUTDATED $name $cur -> $elig$note   $how"
	else
		echo "HELD     $name $cur; newer $latest is ${lage}h old (< ${MIN_AGE_HOURS}h)"
	fi
}

# --- 1. Go toolchain ---------------------------------------------------------
hdr "Go toolchain"
cur_go="$(go mod edit -json | jq -r .Go)"
latest_go="$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -1)"
if [ "go$cur_go" = "$latest_go" ]; then
	echo "ok       go $cur_go"
else
	echo "OUTDATED go $cur_go -> ${latest_go#go}   (go mod edit -go=${latest_go#go})"
fi

# --- 2. go.mod modules ---------------------------------------------------------
hdr "go.mod modules (direct + indirect)"
mods="$(go mod edit -json | jq -r '.Require[].Path')"
targets=""
# shellcheck disable=SC2086
out="$(go list -m -u -json $mods 2>/dev/null |
	jq -r '"\(.Path) \(.Version) \(.Time // "?") \(.Update.Version // "-") \(.Update.Time // "?")"' |
	while read -r path ver vt upd ut; do
		cage="$(age_h "$vt")"
		[ "$upd" = - ] && { old_enough "$cage" || [ "$cage" = "?" ] || report "$path" "$ver" "$ver" "$ver" "$cage" "$cage" ""; continue; }
		if old_enough "$(age_h "$ut")"; then
			report "$path" "$ver" "$upd" "$upd" "$(age_h "$ut")" "$cage" ""
		else
			read -r elig latest lage <<<"$(mod_pick "$path")"
			report "$path" "$ver" "$elig" "$latest" "$lage" "$cage" ""
		fi
	done | grep -v '^ok ' || true)"
if [ -n "$out" ]; then
	echo "$out"
	targets="$(echo "$out" | awk '$1 == "OUTDATED" { printf " %s@%s", $2, $5 }')"
	[ -n "$targets" ] && echo "         update with: go get$targets && go mod tidy"
else
	echo "ok       all $(echo "$mods" | wc -l | tr -d ' ') modules on latest"
fi

# --- 3. versions.mk ------------------------------------------------------------
hdr "versions.mk"
# KEY|kind|source   kind: mod = Go module path, gh = GitHub repo
sources='CADDY_VERSION|mod|github.com/caddyserver/caddy/v2
CORAZA_VERSION|mod|github.com/corazawaf/coraza/v3
CORAZA_CADDY_VERSION|mod|github.com/corazawaf/coraza-caddy/v2
CRS_VERSION|gh|coreruleset/coreruleset
KO_VERSION|gh|ko-build/ko
COSIGN_VERSION|gh|sigstore/cosign
CRANE_VERSION|gh|google/go-containerregistry
GOLANGCI_LINT_VERSION|gh|golangci/golangci-lint
GOVULNCHECK_VERSION|mod|golang.org/x/vuln
CYCLONEDX_GOMOD_VERSION|gh|CycloneDX/cyclonedx-gomod
HURL_VERSION|gh|Orange-OpenSource/hurl
GO_FTW_VERSION|gh|coreruleset/go-ftw
GOTESTWAF_VERSION|gh|wallarm/gotestwaf'
grep -E '^[A-Z_]+=' versions.mk | while IFS='=' read -r key val; do
	[ "$key" = BARBACANA_VERSION ] && continue # written only by the release workflow
	line="$(echo "$sources" | grep "^$key|" || true)"
	if [ -z "$line" ]; then
		echo "UNKNOWN  $key=$val   (no source mapped in audit.sh; check by hand and add it)"
		continue
	fi
	kind="$(echo "$line" | cut -d'|' -f2)"
	src="$(echo "$line" | cut -d'|' -f3)"
	if [ "$kind" = mod ]; then
		read -r elig latest lage <<<"$(mod_pick "$src")"
		cage="$(age_h "$(GOFLAGS=-mod=mod go list -m -json "$src@$val" 2>/dev/null | jq -r .Time)")"
	else
		read -r elig latest lage cage <<<"$(gh_pick "$src" "$val")"
	fi
	report "$key=" "$val" "$elig" "$latest" "$lage" "$cage" "($src)" | sed -E 's/ ([A-Z_]+=) / \1/'
	# Libraries that are also in go.mod must match it.
	if [ "$kind" = mod ] && grep -q "^[[:space:]]*$src " go.mod; then
		inmod="$(go list -m -f '{{.Version}}' "$src")"
		[ "$inmod" != "$val" ] && echo "DRIFT    $key=$val but go.mod has $src $inmod"
	fi
done

# --- 4. GitHub Actions -----------------------------------------------------------
hdr "GitHub Actions (SHA-pinned)"
grep -rhoE 'uses: [A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}( # v?[0-9][^ ]*)?' .github |
	sed -E 's/uses: //' | sort -u | while read -r ref _ tag; do
	action="${ref%@*}"
	gh_repo="$(echo "$action" | cut -d/ -f1-2)"
	read -r elig latest lage cage <<<"$(gh_pick "$gh_repo" "$tag")"
	if [ -z "$tag" ]; then
		echo "UNKNOWN  $action (no '# vX' comment; latest $latest)"
	else
		report "$action" "$tag" "$elig" "$latest" "$lage" "$cage" "(sha: gh api repos/$gh_repo/commits/$elig --jq .sha)"
	fi
done | sort -u

# --- 5. GitHub alerts and bot PRs ---------------------------------------------------
hdr "Dependabot alerts (open)"
gh api "repos/$REPO/dependabot/alerts?state=open&per_page=100" --jq '.[] |
	"#\(.number) [\(.security_advisory.severity)] \(.dependency.package.name) \(.security_vulnerability.vulnerable_version_range) fixed:\(.security_vulnerability.first_patched_version.identifier // "NONE") \(.security_advisory.ghsa_id) \(.security_advisory.summary)"' 2>&1 |
	grep . || echo "none"

hdr "Code-scanning alerts (open)"
gh api "repos/$REPO/code-scanning/alerts?state=open&per_page=100" --jq '.[] |
	"#\(.number) [\(.rule.security_severity_level // .rule.severity)] \(.tool.name) \(.rule.id) \(.most_recent_instance.location.path)"' 2>&1 |
	grep . || echo "none"

hdr "Open Dependabot PRs"
gh pr list --repo "$REPO" --author app/dependabot --state open --json number,title --jq '.[] | "#\(.number) \(.title)"' 2>&1 |
	grep . || echo "none"

# --- 6. Local scans -------------------------------------------------------------------
hdr "govulncheck (reachability, Go vuln DB)"
gv="$(grep '^GOVULNCHECK_VERSION=' versions.mk | cut -d= -f2)"
go run "golang.org/x/vuln/cmd/govulncheck@${gv:-latest}" -show verbose ./... 2>&1 |
	grep -E '^(Vulnerability #|  Module:|    Found in:|    Fixed in:|Your code is affected)' || true

hdr "trivy fs (all severities, unfixed included)"
if command -v trivy >/dev/null; then
	trivy fs -q --scanners vuln --skip-dirs .claude --format json . 2>/dev/null |
		jq -r '[.Results[]?.Vulnerabilities[]?] | unique_by(.VulnerabilityID + .PkgName) | .[] |
			"[\(.Severity)] \(.PkgName) \(.InstalledVersion) fixed:\(.FixedVersion // "NONE") \(.VulnerabilityID)"' |
		grep . || echo "none"
else
	echo "trivy not installed; skipped"
fi
