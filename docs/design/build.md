# Build

> **When to read**: changing the build, the image pipeline, the CI pipeline, or the release process; bumping Caddy/Coraza/CRS versions. **Not needed for**: writing Go code for a protection.

Barbacana ships as one artifact: a multi-arch OCI image containing a single Go binary with the CRS ruleset embedded. The image is built with [ko](https://ko.build) — no Dockerfile, no container runtime required during build. Everything in this document serves that single output.

## Pinned versions — single source of truth

Version bumps happen in **exactly two places**, never more:

1. **`go.mod`** — the Go toolchain version (`go` directive) and every Go dependency (`require` blocks).
2. **`versions.mk`** — everything else: third-party tools (ko, cosign, golangci-lint, trivy-action), the OWASP CRS release, the ko base image digest. A single `KEY=value` file sourced by the Makefile, CI workflows, and shell scripts.

GitHub Action major pins (`@v4`, `@v5`, etc.) live in the workflow files themselves and are bumped by Dependabot like any other GitHub-native pin. They are not duplicated in `versions.mk` because `actions/setup-go@v5` is not a version *we* compile or ship — it's a CI dependency with its own supported-majors policy.

### `versions.mk`

```makefile
# Single source of truth for pinned versions.
# Consumed by: Makefile (via `include`), CI workflows (`cat versions.mk >> $GITHUB_ENV`),
# and cmd/tools/rules (via readCRSVersion).
#
# The Go toolchain version is pinned in go.mod, not here.
# Format: KEY=value with no spaces — valid Make, Bash, and GITHUB_ENV syntax.

BARBACANA_VERSION=v0.1.0
CADDY_VERSION=v2.11.2
CORAZA_VERSION=v3.3.3
CORAZA_CADDY_VERSION=v2.5.0
CRS_VERSION=v4.25.0
KO_VERSION=v0.18.1
COSIGN_VERSION=v3.0.6
GOLANGCI_LINT_VERSION=v2.11.4
```

The file uses the `KEY=value` format with no whitespace around `=`. That narrow subset is simultaneously valid Makefile syntax (`include` works), Bash syntax (`source` works), and the line format GitHub Actions expects for `$GITHUB_ENV`. No normalization step is needed.

### Current values

| Component | Version | Pinned in |
|---|---|---|
| Barbacana | `v0.1.0` | `versions.mk` (`BARBACANA_VERSION`) — only ever written by the `release` workflow, which also creates the matching git tag |
| Go toolchain | `1.26.2` | `go.mod` (`go` directive) |
| Caddy | `v2.11.2` | `go.mod` (require); mirrored in `versions.mk` (`CADDY_VERSION`) for documentation/scripts |
| Coraza | `v3.3.3` | `go.mod` (require); mirrored in `versions.mk` |
| coraza-caddy | `v2.5.0` | `go.mod` (require); mirrored in `versions.mk` |
| OWASP CRS | `v4.25.0` | `versions.mk` (`CRS_VERSION`) |
| ko | `v0.18.1` | `versions.mk` (`KO_VERSION`) |
| cosign | `v3.0.6` | `versions.mk` (`COSIGN_VERSION`) |
| golangci-lint | `v2.11.4` | `versions.mk` (`GOLANGCI_LINT_VERSION`) |
| GitHub action: `actions/checkout` | `@v4` | workflow yaml (Dependabot-managed) |
| GitHub action: `actions/setup-go` | `@v5` | workflow yaml (Dependabot-managed) |
| GitHub action: `golangci/golangci-lint-action` | `@v7` | workflow yaml |
| GitHub action: `ko-build/setup-ko` | `@v0.8` | workflow yaml |
| GitHub action: `sigstore/cosign-installer` | `@v4.1.1` | workflow yaml |
| GitHub action: `aquasecurity/trivy-action` | `@v0.35.0` | workflow yaml |
| GitHub action: `github/codeql-action/upload-sarif` | `@v3` | workflow yaml |

### How each consumer reads the file

- **Go source code / go-module-pinned deps**: `go.mod` is authoritative. CI resolves the toolchain via `actions/setup-go@v5` with `go-version-file: go.mod`. No version string is duplicated in any workflow.
- **Makefile**: `include versions.mk` at the top; targets reference `$(CRS_VERSION)`, `$(KO_VERSION)`, etc.
- **CI workflows**: a single first step per job — `cat versions.mk >> "$GITHUB_ENV"` — exposes every pin as an environment variable to subsequent steps. Steps then use `${{ env.KO_VERSION }}` or `$KO_VERSION`.
- **Shell scripts**: `source versions.mk` at the top.
- **`cmd/tools/rules`**: parses `CRS_VERSION=...` from `versions.mk` directly using the Go standard library.

Bumping a pinned tool therefore means editing `versions.mk` and opening a PR. No workflow file, no Makefile target, and no script needs to change.

Pinning is additionally enforced by checksum: the CRS tarball is verified against a SHA-256 committed in `rules/CRS_SHA256`. A CRS version bump requires updating both `versions.mk` and the checksum file; a mismatch fails the build.

**Barbacana's own version lives in `versions.mk` (`BARBACANA_VERSION`), but only CI is allowed to write it.** The release workflow (`.github/workflows/release.yml`) is the sole producer: it bumps `BARBACANA_VERSION`, commits, and creates the matching annotated `vX.Y.Z` tag in one run. Because the commit and the tag are created together by the same job, the two values cannot drift and no cross-check is needed. Developer-machine builds (`make build`) stamp the binary with whatever `BARBACANA_VERSION` currently is in the file; no environment variable is required for the happy path.

## Binary layout: no xcaddy

Caddy is imported directly from a committed `main.go` (and `cmd/`). There is no code generation step at build time. This has two consequences:

- Any change to the set of Caddy modules we ship is a source change in `main.go` (explicit `_ "..."` imports), reviewed in a PR.
- `ko` operates on a plain Go module: `go build` produces the binary, `ko build` wraps it in an OCI image.

The committed `main.go` imports:

```go
import (
    _ "github.com/caddyserver/caddy/v2/modules/standard"
    _ "github.com/corazawaf/coraza-caddy/v2"
    // barbacana's own Caddy modules:
    _ "github.com/barbacana-waf/barbacana/internal/protections/protocol"
    _ "github.com/barbacana-waf/barbacana/internal/protections/headers"
    _ "github.com/barbacana-waf/barbacana/internal/protections/openapi"
    _ "github.com/barbacana-waf/barbacana/internal/protections/request"
    _ "github.com/barbacana-waf/barbacana/internal/protections/crs"
)
```

These blank imports let the Caddy module loader register handlers. Barbacana's own packages follow the **no `init()`** rule (see `conventions.md`); the blank import is only for the Caddy side's module registration.

## CRS rules + `//go:embed`

- Rules live under `rules/` in the repo **only during build**. Locally, `make rules` fetches them; CI runs the same script.
- `rules/` is in `.gitignore` with a carve-out for `rules/CRS_SHA256` (the pinned checksum) and `rules/.gitkeep`.
- `internal/protections/crs/embed.go`:

  ```go
  package crs

  import "embed"

  //go:embed rules/*.conf rules/*.data crs-setup.conf
  var FS embed.FS
  ```

  Path note: the embed directive is relative to the Go package. The fetch script copies `rules/` and `crs-setup.conf` into that package's directory before `go build` or `ko build` runs.
- At runtime, Coraza is initialized from `FS`. There is no filesystem lookup; the binary is self-contained.

## ko configuration

`.ko.yaml` at repo root:

```yaml
defaultBaseImage: gcr.io/distroless/static-debian13:nonroot

defaultPlatforms:
  - linux/amd64
  - linux/arm64
  - linux/arm/v7
  - linux/ppc64le
  - linux/s390x

builds:
  - id: barbacana
    main: ./
    env:
      - CGO_ENABLED=0
    flags:
      - -trimpath
    ldflags:
      - -s
      - -w
      - -X github.com/barbacana-waf/barbacana/internal/version.Version={{.Env.VERSION}}
      - -X github.com/barbacana-waf/barbacana/internal/version.Commit={{.Env.COMMIT}}
      - -X github.com/barbacana-waf/barbacana/internal/version.CRSVersion={{.Env.CRS_VERSION}}
```

Notes:
- `defaultBaseImage` is distroless static, non-root. No shell, no package manager.
- `defaultPlatforms` covers the architectures the project commits to. Adding a platform is a minor-version concern.
- Health and readiness are expressed as Kubernetes probes against `/healthz` and `/readyz` (see the Helm chart in `deliverables.md`). There is no image-level healthcheck directive.

## Publishing to GitHub Packages

The OCI registry is GitHub Packages (`ghcr.io/barbacana-waf/barbacana`). Publishing is done by ko, authenticated via the GitHub Actions token for the workflow (`packages: write` permission). Version-sensitive values come from `versions.mk`; only per-release fields (`VERSION`, `COMMIT`) are supplied per invocation.

```
source versions.mk
export KO_DOCKER_REPO=ghcr.io/barbacana-waf/barbacana
export VERSION=${BARBACANA_VERSION}
export COMMIT=$(git rev-parse --short HEAD)
# BARBACANA_VERSION and CRS_VERSION are already exported by `source versions.mk`

ko build \
  --platform=all \
  --sbom=spdx \
  --sbom-dir=./sbom \
  --tags=${VERSION},latest \
  --image-refs=./image.refs \
  .
```

Flags:
- `--platform=all` honours the `defaultPlatforms` list in `.ko.yaml`, producing a multi-arch manifest index under a single tag.
- `--sbom=spdx` writes an SPDX SBOM per platform into `--sbom-dir`. One aggregate SBOM is also produced for the index. (ko v0.18.1 does not support CycloneDX; the flag is silently ignored. Reassess if ko adds native CycloneDX output or if a downstream consumer asks for it — at that point, generate it out-of-band with syft.)
- `--tags` attaches the listed tags to the pushed index. Immutable `vX.Y.Z` plus rolling `latest`; intermediate rolling tags (`vX.Y`, `vX`) are added by a follow-up `crane` step in CI (see pipeline below).
- `--image-refs` writes the published digest(s) to a file. The downstream signing and scanning steps read this file so they sign the exact digest ko produced, not a tag that could race.

The registry env var's legacy name (`KO_DOCKER_REPO`) is a ko upstream concern; the registry it points at is GitHub Packages.

## Signing: cosign keyless (CI-only)

Signing runs **only** in the CI workflow. It uses cosign's keyless flow with the GitHub Actions OIDC token — there are no long-lived keys to distribute, and the flow cannot be reproduced on a developer workstation because it depends on a workflow-issued OIDC identity. The `cosign sign` and `cosign attest` invocations live inside `.github/workflows/ci.yml` (see below) and nowhere else: no Makefile target, no local script. Attempting to run them locally would either fail (no OIDC token) or produce a signature bound to the developer's own identity, which is not the identity consumers verify against.

What the CI step produces:

- A signature over the exact image index digest, stored in the Sigstore transparency log (Rekor) and as an OCI 1.1 referrer alongside the image.
- A signed SPDX SBOM attestation over the same digest.

### Verification (for consumers)

Consumers of the image verify it against the workflow identity. This command *is* reproducible anywhere — it only reads public artifacts from the registry and Rekor.

```
cosign verify \
  --certificate-identity-regexp "^https://github.com/barbacana-waf/barbacana/.github/workflows/ci.yml@refs/tags/v" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/barbacana-waf/barbacana:v1.2.3
```

The SBOM attestation is verified the same way with `cosign verify-attestation --type spdxjson ...`.

## Vulnerability scanning: trivy

Two flows, both using Aqua's `trivy-action`.

**PR flow (`ci.yml`)** — scans the image built for the pull request, fails the check on any `CRITICAL` or `HIGH` vulnerability:

```yaml
- name: Scan image (PR gate)
  uses: aquasecurity/trivy-action@0.24.0
  with:
    image-ref: ${{ steps.ko.outputs.image-ref }}
    severity: CRITICAL,HIGH
    exit-code: "1"
    ignore-unfixed: true
    vuln-type: os,library
    format: table
```

**Daily scan (`security.yml`)** — runs on a cron, scans the currently-published `latest` tag, uploads SARIF to the GitHub Security tab so results appear under *Code scanning alerts* for the repo:

```yaml
name: security-scan
on:
  schedule:
    - cron: "0 6 * * *"      # daily at 06:00 UTC
  workflow_dispatch:

permissions:
  contents: read
  security-events: write      # required to upload SARIF

jobs:
  trivy:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Scan published image
        uses: aquasecurity/trivy-action@v0.35.0
        with:
          image-ref: ghcr.io/barbacana-waf/barbacana:latest
          format: sarif
          output: trivy-results.sarif
          severity: CRITICAL,HIGH,MEDIUM
          ignore-unfixed: true
      - name: Upload results to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-results.sarif
          category: trivy
```

Findings on `latest` are therefore visible to maintainers continuously, even between releases, via the GitHub Security tab.

## Makefile

```makefile
# All pinned third-party versions come from a single file.
include versions.mk

.PHONY: help build test test-integration lint vet tidy \
        rules rules-clean \
        image image-publish scan \
        validate defaults run clean

# BARBACANA_VERSION comes from versions.mk. Override only for local smoke tests.
VERSION ?= $(BARBACANA_VERSION)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
REPO    ?= ghcr.io/barbacana-waf/barbacana

help:
	@awk 'BEGIN{FS":.*##"} /^[a-zA-Z_-]+:.*##/{printf "  %-20s %s\n",$$1,$$2}' $(MAKEFILE_LIST)

build: rules ## Build the barbacana binary locally
	CGO_ENABLED=0 go build \
	  -trimpath \
	  -ldflags "-s -w \
	    -X github.com/barbacana-waf/barbacana/internal/version.Version=$(VERSION) \
	    -X github.com/barbacana-waf/barbacana/internal/version.Commit=$(COMMIT) \
	    -X github.com/barbacana-waf/barbacana/internal/version.CRSVersion=$(CRS_VERSION)" \
	  -o ./barbacana ./

test: ## Run unit tests with race detector
	go test -race ./...

test-integration: build ## Run integration tests (requires built binary)
	go test -tags=integration -race ./internal/pipeline/...

lint: ## Run golangci-lint (version pinned in versions.mk)
	@command -v golangci-lint >/dev/null || { \
	  echo "golangci-lint not installed; expected $(GOLANGCI_LINT_VERSION)"; exit 1; }
	golangci-lint run ./...

vet: ## Run go vet
	go vet ./...

tidy: ## Ensure go.mod/go.sum are clean
	go mod tidy
	git diff --exit-code -- go.mod go.sum

rules: ## Fetch CRS, extract curated rules, install FTW test corpus
	go run ./cmd/tools/rules

rules-clean: ## Remove installed CRS rule artifacts and tarball cache
	rm -rf internal/protections/crs/rules internal/protections/crs/crs-setup.conf tests/ftw/crs-tests .cache/crs

image: rules ## Build the multi-arch image locally (does not push)
	KO_DOCKER_REPO=$(REPO) \
	VERSION=$(VERSION) COMMIT=$(COMMIT) CRS_VERSION=$(CRS_VERSION) \
	ko build --local --platform=linux/amd64,linux/arm64 .

image-publish: rules ## Build + push the multi-arch image with SPDX SBOM
	KO_DOCKER_REPO=$(REPO) \
	VERSION=$(VERSION) COMMIT=$(COMMIT) CRS_VERSION=$(CRS_VERSION) \
	ko build \
	  --platform=all \
	  --sbom=spdx --sbom-dir=./sbom \
	  --tags=$(VERSION),latest \
	  --image-refs=./image.refs \
	  .

scan: ## Scan the published image with trivy; fail on CRITICAL/HIGH
	trivy image --severity CRITICAL,HIGH --exit-code 1 --ignore-unfixed $(REPO):$(VERSION)

validate: build ## Validate the example config
	./barbacana --config configs/example.yaml --validate

run: build ## Run locally with the example config
	./barbacana --config configs/example.yaml

clean: ## Remove build outputs
	rm -f ./barbacana
	rm -rf ./sbom ./image.refs
```

`cmd/tools/rules` is a single Go program (standard library only) that handles fetching, checksum verification, extraction of CRS rule files into `internal/protections/crs/rules/`, extraction of curated PL2/PL3 rules into `curated-rules.conf`, and installation of the go-ftw regression-test corpus. It parses `CRS_VERSION` directly from `versions.mk`, caches the tarball under `.cache/crs/`, and is offline-resilient: a cache hit with the pinned SHA-256 skips the network entirely. See `docs/design/security-evaluation.md` for the extraction semantics (including the `tx.inbound_anomaly_score_pl2/3 → pl1` rewrite).

`internal/protections/crs/rules/`, `internal/protections/crs/crs-setup.conf`, and `tests/ftw/crs-tests/` are **derived artifacts** — gitignored, regenerated from the pinned tarball by `make rules`. The source of truth is the pin (`versions.mk` + `rules/CRS_SHA256`) plus `internal/protections/crs/curated/`. A fresh clone needs network access on first build to fetch the tarball; subsequent builds reuse the cache under `.cache/crs/`. `make rules` is an order-only prerequisite of the Go build targets.

## CI pipeline (GitHub Actions)

Two workflows live in `.github/workflows/`: `ci.yml` for PRs and tags, `security.yml` for daily security scans.

### Reusable `load-versions` composite action

To avoid repeating the version-loading step in every job, a composite action lives at `.github/actions/load-versions/action.yml`:

```yaml
name: load-versions
description: Export pinned versions from versions.mk into $GITHUB_ENV
runs:
  using: composite
  steps:
    - shell: bash
      run: |
        set -euo pipefail
        # versions.mk uses KEY=value with no spaces — safe to append directly.
        grep -E '^[A-Z_][A-Z0-9_]*=' versions.mk >> "$GITHUB_ENV"
```

Every job that needs a pinned version runs `- uses: ./.github/actions/load-versions` once after checkout and then references `${{ env.KO_VERSION }}`, `${{ env.GOLANGCI_LINT_VERSION }}`, etc.

### `.github/workflows/ci.yml`

```yaml
name: ci

on:
  push:
    branches: [main]
    tags: ["v*"]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  lint:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/load-versions
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod      # Go version pinned in go.mod only
          cache: true
      - uses: golangci/golangci-lint-action@v7
        with:
          version: ${{ env.GOLANGCI_LINT_VERSION }}
          args: --timeout=5m
      - run: go vet ./...
      - run: go mod tidy && git diff --exit-code -- go.mod go.sum

  test:
    needs: [lint]
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true
      - run: go test -race ./...

  integration:
    needs: [test]
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true
      - run: make rules
      - run: make build
      - run: make test-integration

  image:
    needs: [integration]
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      packages: write          # publish to GitHub Packages (ghcr.io)
      id-token: write          # OIDC token for cosign keyless signing
    outputs:
      image-ref: ${{ steps.ko.outputs.image-ref }}
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/load-versions
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true
      - uses: ko-build/setup-ko@v0.9
        with:
          version: ${{ env.KO_VERSION }}
      - name: Log in to GitHub Packages
        run: echo "${{ secrets.GITHUB_TOKEN }}" | ko login ghcr.io --username "${{ github.actor }}" --password-stdin
      - run: make rules

      - name: Compute tag
        id: tag
        run: |
          # BARBACANA_VERSION is already exported into $GITHUB_ENV by load-versions.
          if [ "${{ github.event_name }}" = "pull_request" ]; then
            echo "version=${BARBACANA_VERSION}-pr${{ github.event.pull_request.number }}" >> "$GITHUB_OUTPUT"
            echo "push=false" >> "$GITHUB_OUTPUT"
          elif [[ "${{ github.ref }}" == refs/tags/v* ]]; then
            TAG="${GITHUB_REF#refs/tags/}"
            if [ "${TAG}" != "${BARBACANA_VERSION}" ]; then
              echo "::error::git tag ${TAG} does not match versions.mk BARBACANA_VERSION=${BARBACANA_VERSION}" >&2
              exit 1
            fi
            echo "version=${TAG}" >> "$GITHUB_OUTPUT"
            echo "push=true" >> "$GITHUB_OUTPUT"
          else
            echo "version=${BARBACANA_VERSION}-main-${GITHUB_SHA:0:7}" >> "$GITHUB_OUTPUT"
            echo "push=true" >> "$GITHUB_OUTPUT"
          fi

      - name: Build image + SPDX SBOM
        id: ko
        env:
          KO_DOCKER_REPO: ghcr.io/barbacana-waf/barbacana
          VERSION: ${{ steps.tag.outputs.version }}
          COMMIT: ${{ github.sha }}
          # BARBACANA_VERSION and CRS_VERSION are already in the env thanks to load-versions
        run: |
          set -euo pipefail
          ARGS=(--platform=all --sbom=spdx --sbom-dir=./sbom --tags="${VERSION}" --image-refs=./image.refs)
          if [ "${{ steps.tag.outputs.push }}" = "false" ]; then
            ARGS+=(--local)
          fi
          if [[ "${{ github.ref }}" == refs/tags/v* ]]; then
            ARGS+=(--tags="${VERSION},latest")
          fi
          ko build "${ARGS[@]}" .
          echo "image-ref=$(cat image.refs)" >> "$GITHUB_OUTPUT"

      - name: Trivy scan (PR gate — fail on CRITICAL/HIGH)
        if: github.event_name == 'pull_request'
        uses: aquasecurity/trivy-action@v0.35.0
        with:
          image-ref: ${{ steps.ko.outputs.image-ref }}
          severity: CRITICAL,HIGH
          exit-code: "1"
          ignore-unfixed: true
          vuln-type: os,library
          format: table

      - name: Cosign keyless sign (tag releases only)
        if: steps.tag.outputs.push == 'true' && startsWith(github.ref, 'refs/tags/v')
        uses: sigstore/cosign-installer@v4.1.1
        with:
          cosign-release: ${{ env.COSIGN_VERSION }}
      - name: Sign image + attest SBOM
        if: steps.tag.outputs.push == 'true' && startsWith(github.ref, 'refs/tags/v')
        run: |
          cosign sign --yes "${{ steps.ko.outputs.image-ref }}"
          cosign attest --yes \
            --predicate ./sbom/barbacana-index.spdx.json \
            --type spdxjson \
            "${{ steps.ko.outputs.image-ref }}"

      - name: Upload SBOM as build artifact
        if: steps.tag.outputs.push == 'true'
        uses: actions/upload-artifact@v4
        with:
          name: sbom-spdx
          path: sbom/
```

### `.github/workflows/security.yml`

```yaml
name: security-scan

on:
  schedule:
    - cron: "0 6 * * *"          # daily at 06:00 UTC
  workflow_dispatch:

permissions:
  contents: read
  security-events: write          # required to upload SARIF to the Security tab

jobs:
  trivy-latest:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Trivy scan of :latest
        uses: aquasecurity/trivy-action@v0.35.0
        with:
          image-ref: ghcr.io/barbacana-waf/barbacana:latest
          format: sarif
          output: trivy-results.sarif
          severity: CRITICAL,HIGH,MEDIUM
          ignore-unfixed: true
      - name: Upload SARIF to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-results.sarif
          category: trivy-daily
```

Stage summary for `ci.yml`: **lint** → **test** → **integration** → **image** (ko build with SPDX SBOM; on PR: trivy gate fails the check on CRITICAL/HIGH; on tag: cosign keyless sign + SBOM attestation).

Stage summary for `security.yml`: runs daily (cron) or on demand. Scans the currently-published `:latest` image and surfaces findings in the GitHub Security tab as code-scanning alerts.

### Bumping a version

| To bump | Edit | Side effects |
|---|---|---|
| Barbacana (this project's own version) | not edited by hand — run the `release` workflow (Actions → release → Run workflow) and pick a bump type | CI rewrites `versions.mk`, commits, and pushes the matching `vX.Y.Z` tag; the tag push then triggers `ci.yml` to build and publish |
| Go toolchain | `go.mod` (`go` directive) | CI picks it up via `go-version-file: go.mod`; no workflow change |
| A Go dependency (Caddy, Coraza, ...) | `go.mod` + `go mod tidy` | mirror the new value into `versions.mk` for documentation consistency |
| CRS | `versions.mk` (`CRS_VERSION`) + `rules/CRS_SHA256` | `make rules` re-fetches; the checksum file proves the new tarball |
| ko / cosign / golangci-lint | `versions.mk` | picked up by every job via `load-versions` |
| A GitHub Action major (e.g. `actions/checkout@v4` → `@v5`) | the workflow file itself | Dependabot usually opens this PR |

## Running locally

The happy path from a clean clone:

```
git clone https://github.com/barbacana-waf/barbacana.git
cd barbacana
make rules         # fetches CRS and verifies checksum
make build         # produces ./barbacana
make test          # runs unit tests
./barbacana --config configs/example.yaml
```

The example config proxies `:8080` to `http://localhost:8000`. Health is served on `:8081/healthz`, metrics on `:9090/metrics`.

To produce a local multi-arch image tarball without publishing:

```
make image VERSION=dev
```

## Release process

Releases are a single click in GitHub Actions. `versions.mk` is only ever written by CI for releases — developers never edit `BARBACANA_VERSION` by hand, and nobody creates git tags manually.

1. Go to **Actions → release → Run workflow**.
2. Pick `patch`, `minor`, or `major` for the `bump` input.
3. Run.

The `release` workflow (`.github/workflows/release.yml`) then:

- Reads the current `BARBACANA_VERSION` from `versions.mk`, parses it as `vMAJOR.MINOR.PATCH`, and computes the next version in pure bash (increment the chosen field, zero out the lower ones).
- Rewrites `BARBACANA_VERSION` in `versions.mk` with `sed`.
- Commits as `github-actions[bot]` with message `release: vX.Y.Z`.
- Creates an annotated tag `vX.Y.Z` with message `vX.Y.Z`.
- Pushes the commit and the tag to the default branch.

The tag push triggers `ci.yml`, which runs the usual lint → test → integration → image stages. The image job consumes the git tag directly as the image version — there is no separate `BARBACANA_VERSION`/tag equality check, because the release workflow is now the only producer of both and they cannot drift. On the tag build, CI publishes the multi-arch image to `ghcr.io/barbacana-waf/barbacana:vX.Y.Z` (and `:latest`), attaches the SPDX SBOM, signs the image and attests the SBOM with cosign keyless, and uploads the SBOM as a workflow artifact.

Follow-ups after CI goes green:

- Create a GitHub Release pointing to the tag; the SBOM workflow artifact can be attached for convenience, but the attested copy in the registry is authoritative.
- Helm chart release happens in the separate chart repository referenced in `deliverables.md`.
