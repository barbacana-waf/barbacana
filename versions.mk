# Single source of truth for pinned versions.
# Consumed by: Makefile (via `include`), CI workflows (`cat versions.mk >> $GITHUB_ENV`),
# and scripts/fetch-crs.sh (via `source`).
#
# The Go toolchain version is pinned in go.mod, not here.
# Format: KEY=value with no spaces — valid Make, Bash, and GITHUB_ENV syntax.

BARBACANA_VERSION=v0.8.0
CADDY_VERSION=v2.11.4
CORAZA_VERSION=v3.7.0
CORAZA_CADDY_VERSION=v2.5.0
CRS_VERSION=v4.27.0
KO_VERSION=v0.18.1
COSIGN_VERSION=v3.0.6
CRANE_VERSION=v0.21.6
GOLANGCI_LINT_VERSION=v2.12.2
GOVULNCHECK_VERSION=v1.3.0
CYCLONEDX_GOMOD_VERSION=v1.10.0
HURL_VERSION=8.0.1
GO_FTW_VERSION=v2.4.0
GOTESTWAF_VERSION=v0.5.8
