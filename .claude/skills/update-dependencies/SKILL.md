---
name: update-dependencies
description: "Update every Barbacana dependency to its latest version at least 24 hours old and clear vulnerability alerts in one pass: Go toolchain, all go.mod modules, versions.mk tools (CRS, ko, cosign, golangci-lint, hurl, go-ftw, ...), and SHA-pinned GitHub Actions, then triage open Dependabot and code-scanning alerts. Use this whenever the user mentions a CVE, GHSA, vulnerability, Dependabot or code-scanning alert, Trivy or govulncheck finding, an outdated or bumped package, a Dependabot PR, or asks to upgrade, bump or refresh dependencies — even if they name only one package. Fixing a single CVE is never just one bump: run the whole audit."
disable-model-invocation: true
---

# Update dependencies

Barbacana is a security product, so "on the latest version" has to be true for
everything, not just the package an alert named. This skill exists because a
single-CVE fix once bumped only `golang.org/x/net` and was reported as "the very
latest". Hours later Dependabot bumped two other direct modules and two Actions,
and raised three alerts that the fix should already have surfaced. The rule that
follows from it: **audit everything, update everything, re-audit until clean,
and only then say "latest"**.

## Minimum release age: 24 hours

"Latest" means the newest release **published at least 24 hours ago**. This
rule is a defence against supply-chain attacks. A malicious release, pushed
through a hijacked maintainer account, a compromised CI or a re-pointed tag,
is usually caught and yanked within its first day, and taking releases only
after that window keeps Barbacana out of it. `audit.sh` applies this to
go.mod modules, versions.mk and GitHub Actions (`MIN_AGE_HOURS`, default 24),
using the Go proxy's version time and GitHub's release `published_at`:

- `OUTDATED a -> b` already targets the newest version that is old enough. A
  `(latest X is Nh old, held)` note means a newer one exists but is too young.
- `HELD` means every newer version is too young. Leave it and report it.
- `YOUNG` means the pin itself is too young, usually because an earlier pass
  took it. Roll it back to the previous version.

**The one exception is a bump that fixes an open advisory** (CVE, GHSA, GO-…).
Don't leave a known vulnerability in place to wait out the clock. Take the
fixed version and name it, with its age, in the report.

The Go toolchain isn't age-checked, because go.dev/VERSION carries no date.
Check the release date on https://go.dev/doc/devel/release before bumping it.

## 1. Audit (read-only)

```bash
.claude/skills/update-dependencies/scripts/audit.sh
```

It takes about a minute and changes nothing. It reports, in order:

| Section | What it checks | Why it is separate |
|---|---|---|
| Go toolchain | `go` directive in go.mod vs go.dev | the toolchain pin lives in go.mod (see `docs/design/build.md`) |
| go.mod modules | every `require`, direct and indirect | `go list -m -u` on a few names is how things get missed |
| versions.mk | pinned tools and CRS | **Dependabot does not watch versions.mk**; nothing else will tell you |
| GitHub Actions | SHA pins vs the `# vX.Y.Z` comment | Dependabot does this weekly, so you can get there first |
| Dependabot / code-scanning alerts, Dependabot PRs | GitHub's view | covers advisories the local scanners miss |
| govulncheck, trivy fs | local scans | trivy runs **without** `--ignore-unfixed`, unlike `make scan-deps` |

Anything marked `UNKNOWN` means the script couldn't decide. Resolve it by hand,
and if it's a new versions.mk key, add its source to the `sources` table in
`audit.sh` so the next run covers it.

Also look at the latest bot commits (`git log --author='dependabot' -5 --stat`).
They show what the bot found that the last manual pass didn't. If a bump there
wasn't caught by the audit, extend the script.

## 2. Update everything the audit flagged

Work from the repo root and don't stop at the minimum fixed version. Go to the
newest release that is at least 24 hours old: the target the audit prints, not
`@latest`.

- **Go toolchain**: `go mod edit -go=<latest>`. CI reads it via `go-version-file`.
- **Go modules**: run the `go get … && go mod tidy` line the audit prints under
  the go.mod section. Don't use `go get -u`: it ignores release age. Then
  re-run the go.mod section of the audit. A bump can drag in a dependency
  version that is too young, which shows as `YOUNG`. Roll it back with
  `go get <module>@<previous version>`, taking the version from
  `git diff HEAD -- go.mod`. If go refuses because another module requires it,
  keep it and report why. If a module is still `OUTDATED`, an upstream module
  is holding it back. Try `go get <module>@<target>` and, if tidy or build
  fails, leave it and report the reason.
- **versions.mk**: edit the value. Keep `CADDY_VERSION`, `CORAZA_VERSION` and
  `CORAZA_CADDY_VERSION` equal to go.mod; the audit flags `DRIFT`. Never touch
  `BARBACANA_VERSION`: only the release workflow writes it.
- **CRS** (`CRS_VERSION`): also update `rules/CRS_SHA256`. Verify the release
  tag's signature before pinning the new checksum (the CHANGELOG records this
  as "tag signature verified"). If you can't verify it, stop and tell the user.
  `make rules` prints the new checksum on mismatch. A CRS bump changes detection
  behaviour, so it needs the blackbox and FTW tests, not just unit tests.
- **GitHub Actions**: replace the SHA and the comment together, using the
  command the audit prints:
  `gh api repos/<owner>/<repo>/commits/<tag> --jq .sha`. Update every file
  that uses the action, including `.github/actions/`.

## 3. Verify

```bash
make simulate-ci
```

This is what CI runs. Use `make -k` so one failure doesn't hide the rest. If
part of it can't run locally (Docker, network), run at least
`make lint vet tidy test build govulncheck` and say which targets were skipped.
If you bumped go-ftw, gotestwaf or CRS, also run `make test-ftw test-gotestwaf`.

Reading the results:

- `make tidy` always fails on an uncommitted go.mod, because it diffs against
  HEAD. Check tidiness yourself: copy go.mod and go.sum, run `go mod tidy`, and
  compare.
- **Don't blame the bump, and don't wave a failure away, without a baseline.**
  Run the failing targets in a throwaway worktree of HEAD
  (`git worktree add --detach <scratch>/base HEAD`, copy `.cache/crs`, then
  run `make <target>`) and diff the failing test names. If they're the same,
  the failure was already there. Report it as such, not as fixed or caused.
  Then remove the worktree. Blackbox and ratelimit tests return 502 inside a
  sandboxed shell. Ask the user to run them, or rely on CI.
- `TestFTW` passes even when go-ftw exits 1. Check
  `tests/ftw/reports/ftw-report.txt` for `Error:` lines, which mean go-ftw
  stopped partway through and the later CRS tests never ran.

Then run the audit again. It must show no `OUTDATED`, no `DRIFT` and no
`YOUNG` (apart from advisory fixes) before you claim anything is current.
Anything still behind, including every `HELD` line, goes in the report with its
reason.

Run `graphify update .` from the project root afterwards, as CLAUDE.md asks.

## 4. Triage the alerts that remain

For each remaining Dependabot, code-scanning, trivy or govulncheck finding:

1. **Fixed by this update?** Code-scanning alerts on `ko-app/barbacana` come
   from scanning the published image, so they close only after a new image is
   built. Say that rather than calling them fixed.
2. **No fixed version** (`fixed:NONE`)? Find who pulls it in
   (`go mod why -m <module>`, `go mod graph | grep <module>`) and whether the
   newest version of that parent still requires it. Then check reachability:
   govulncheck symbol results, and whether the code path is configured at all
   (for example, Caddy's PKI or ACME server modules come in only through
   `modules/standard` in `main.go`). The Go vuln DB can lag GitHub advisories,
   so "govulncheck found 0" alone doesn't prove anything.
3. **Record the decision** in `osv-scanner.toml`, following the existing entry:
   the id, plus a `reason` that says why it's unfixable, how you checked it
   isn't reachable, and what would change that.
4. **Dismissing** a GitHub alert is visible outside the repo. Propose it, with
   the reason text, and let the user do it or approve it.

## 5. CHANGELOG

Add entries under `## [Unreleased]` in `CHANGELOG.md`, following the existing
style:

- `### Security`: bumps that fix a CVE or GHSA. Name the advisory and the
  affected component, e.g.
  `` Bumped `golang.org/x/net` v0.61.0 → v0.62.0, fixing CVE-… in the `x/net/html` parser. ``
- `### Changed`: other notable bumps (toolchain, Caddy, Coraza, CRS, and a
  one-line roll-up for the rest, e.g. "Bumped 24 Go modules and 3 test tools to
  latest").

## 6. Report

Keep it short and lead with the answer. Cover:

- what was bumped (counts, plus the notable ones)
- the result of `simulate-ci` (or which targets ran)
- the final audit status, and anything still behind and why (`HELD` releases
  younger than 24 hours, and any advisory fix taken despite being younger)
- alerts left open, each with its classification and proposed action

Don't commit or push. The user reviews the diff first.
