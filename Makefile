# All pinned third-party versions come from a single file.
include versions.mk

.PHONY: help build test test-integration test-minimal test-blackbox test-e2e test-ftw test-gotestwaf image-test lint vet tidy \
        rules rules-clean \
        image image-publish sbom sign attest verify verify-attestation scan scan-deps govulncheck \
        validate render-config run clean \
        tools tools-security simulate-ci

# BARBACANA_VERSION comes from versions.mk. Override only for local smoke tests.
VERSION ?= $(BARBACANA_VERSION)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
REPO    ?= ghcr.io/barbacana-waf/barbacana

# Pinned dev tools live under ./bin so they don't pollute the user's global
# GOBIN. Tools are installed with `go install` — no curl | sh.
LOCALBIN         := $(CURDIR)/bin
GOLANGCI_LINT    := $(LOCALBIN)/golangci-lint
KO               := $(LOCALBIN)/ko
GOVULNCHECK      := $(LOCALBIN)/govulncheck
GO_FTW           := $(LOCALBIN)/go-ftw
GOTESTWAF        := $(LOCALBIN)/gotestwaf
CYCLONEDX_GOMOD  := $(LOCALBIN)/cyclonedx-gomod

# Stamp files encode the pinned version; bumping a version in versions.mk
# invalidates the stamp and triggers a reinstall on next use.
GOLANGCI_LINT_STAMP   := $(LOCALBIN)/.golangci-lint-$(GOLANGCI_LINT_VERSION)
KO_STAMP              := $(LOCALBIN)/.ko-$(KO_VERSION)
GOVULNCHECK_STAMP     := $(LOCALBIN)/.govulncheck-$(GOVULNCHECK_VERSION)
GO_FTW_STAMP          := $(LOCALBIN)/.go-ftw-$(GO_FTW_VERSION)
GOTESTWAF_STAMP       := $(LOCALBIN)/.gotestwaf-$(GOTESTWAF_VERSION)
CYCLONEDX_GOMOD_STAMP := $(LOCALBIN)/.cyclonedx-gomod-$(CYCLONEDX_GOMOD_VERSION)

$(LOCALBIN):
	@mkdir -p $@

$(GOLANGCI_LINT_STAMP): | $(LOCALBIN)
	@rm -f $(LOCALBIN)/.golangci-lint-* $(GOLANGCI_LINT)
	@echo ">> installing golangci-lint $(GOLANGCI_LINT_VERSION) into $(LOCALBIN)"
	GOBIN=$(LOCALBIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@touch $@

$(GOLANGCI_LINT): $(GOLANGCI_LINT_STAMP)

$(KO_STAMP): | $(LOCALBIN)
	@rm -f $(LOCALBIN)/.ko-* $(KO)
	@echo ">> installing ko $(KO_VERSION) into $(LOCALBIN)"
	GOBIN=$(LOCALBIN) go install github.com/google/ko@$(KO_VERSION)
	@touch $@

$(KO): $(KO_STAMP)

$(GOVULNCHECK_STAMP): | $(LOCALBIN)
	@rm -f $(LOCALBIN)/.govulncheck-* $(GOVULNCHECK)
	@echo ">> installing govulncheck $(GOVULNCHECK_VERSION) into $(LOCALBIN)"
	GOBIN=$(LOCALBIN) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	@touch $@

$(GOVULNCHECK): $(GOVULNCHECK_STAMP)

$(GO_FTW_STAMP): | $(LOCALBIN)
	@rm -f $(LOCALBIN)/.go-ftw-* $(GO_FTW)
	@echo ">> installing go-ftw $(GO_FTW_VERSION) into $(LOCALBIN)"
	GOBIN=$(LOCALBIN) go install github.com/coreruleset/go-ftw/v2@$(GO_FTW_VERSION)
	@touch $@

$(GO_FTW): $(GO_FTW_STAMP)

$(GOTESTWAF_STAMP): | $(LOCALBIN)
	@rm -f $(LOCALBIN)/.gotestwaf-* $(GOTESTWAF)
	@echo ">> installing gotestwaf $(GOTESTWAF_VERSION) into $(LOCALBIN)"
	GOBIN=$(LOCALBIN) go install github.com/wallarm/gotestwaf/cmd/gotestwaf@$(GOTESTWAF_VERSION)
	@touch $@

$(GOTESTWAF): $(GOTESTWAF_STAMP)

$(CYCLONEDX_GOMOD_STAMP): | $(LOCALBIN)
	@rm -f $(LOCALBIN)/.cyclonedx-gomod-* $(CYCLONEDX_GOMOD)
	@echo ">> installing cyclonedx-gomod $(CYCLONEDX_GOMOD_VERSION) into $(LOCALBIN)"
	GOBIN=$(LOCALBIN) go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@$(CYCLONEDX_GOMOD_VERSION)
	@touch $@

$(CYCLONEDX_GOMOD): $(CYCLONEDX_GOMOD_STAMP)

tools: $(GOLANGCI_LINT) $(KO) $(GOVULNCHECK) $(CYCLONEDX_GOMOD) ## Install pinned dev tools into ./bin

tools-security: $(GO_FTW) $(GOTESTWAF) ## Install pinned security scanners (go-ftw, gotestwaf) into ./bin

# E2E driver. Override IMAGE= to exercise a different artifact (e.g. a released tag).
IMAGE           ?= barbacana:test
COMPOSE_RUNTIME ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
COMPOSE         := $(COMPOSE_RUNTIME) compose

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

test-minimal: ## End-to-end smoke test against a built binary (build, serve, curl, reload, shutdown)
	./scripts/minimal-test.sh

SCENARIO ?=

test-blackbox: build ## Run black-box functional tests with Hurl (SCENARIO=name to run one, VERBOSE=1 to stream hurl + WAF logs)
	@command -v hurl >/dev/null || { echo "hurl not installed — see https://hurl.dev"; exit 1; }
	@summary=$$(mktemp); trap 'rm -f $$summary' EXIT; \
	 BLACKBOX_SUMMARY_FILE=$$summary \
	   go test -tags=blackbox ./tests/blackbox/ -count=1 $(if $(VERBOSE),-v) $(if $(SCENARIO),-run TestBlackbox/$(SCENARIO)); \
	 rc=$$?; \
	 [ -s $$summary ] && cat $$summary; \
	 exit $$rc

test-ftw: build $(GO_FTW) ## Run the CRS FTW regression suite; emits report under tests/ftw/reports/
	@[ -d tests/ftw/crs-tests ] || { echo "FTW test corpus missing — run 'make rules' first"; exit 1; }
	PATH=$(LOCALBIN):$$PATH go test -tags=ftw ./tests/ftw/ -v -count=1 -timeout=20m

test-gotestwaf: build $(GOTESTWAF) ## Run the gotestwaf attack suite; emits PDF+JSON under tests/gotestwaf/reports/
	GOTESTWAF_VERSION=$(GOTESTWAF_VERSION) PATH=$(LOCALBIN):$$PATH \
	  go test -tags=gotestwaf ./tests/gotestwaf/ -v -count=1 -timeout=25m

image-test: build ## Build the local test container image (barbacana:test)
	podman build -f tests/e2e/Containerfile -t barbacana:test .

test-e2e: ## End-to-end tests (black-box; override IMAGE= to test a different artifact)
	@[ -n "$(COMPOSE_RUNTIME)" ] || { echo "error: podman or docker required"; exit 1; }
	@if [ "$(IMAGE)" = "barbacana:test" ] && ! podman image exists barbacana:test 2>/dev/null; then \
	    $(MAKE) image-test; \
	fi
	@mkdir -p tests/e2e/reports
	@set -e; \
	  export IMAGE=$(IMAGE) HURL_VERSION=$(HURL_VERSION); \
	  trap '$(COMPOSE) -f tests/e2e/compose.yaml down --remove-orphans >/dev/null 2>&1 || true' EXIT; \
	  $(COMPOSE) -f tests/e2e/compose.yaml up \
	    --force-recreate --abort-on-container-exit --exit-code-from hurl

lint: $(GOLANGCI_LINT) ## Run golangci-lint (version pinned in versions.mk)
	$(GOLANGCI_LINT) run --timeout=5m ./...

vet: ## Run go vet
	go vet ./...

tidy: ## Ensure go.mod/go.sum are clean
	go mod tidy
	git diff --exit-code -- go.mod go.sum

rules: ## Fetch CRS, extract curated PL2/PL3 rules, install FTW corpus
	go run ./cmd/tools/rules

rules-clean: ## Remove installed CRS rule artifacts and the tarball cache
	rm -rf internal/protections/crs/rules internal/protections/crs/crs-setup.conf tests/ftw/crs-tests .cache/crs

# --- image build / publish -------------------------------------------------
# `make image` runs locally by default: single platform, loaded into the host
# Docker daemon, no registry push. CI overrides KO_LOCAL/KO_PLATFORM/KO_TAGS/REPO
# via env and invokes `image-publish` on push events. The underlying ko
# invocation is the same; only the flags differ.
#
# SBOMs are NOT generated by ko. A separate CycloneDX SBOM is produced by
# `make sbom` for release tags (see below).

IMAGE_SOURCE ?= https://github.com/barbacana-waf/barbacana
KO_PLATFORM  ?= linux/amd64
KO_TAGS      ?= $(VERSION)
KO_LOCAL     ?= --local

image: rules $(KO) ## Build the container image (KO_LOCAL/KO_PLATFORM/KO_TAGS/REPO configurable)
	KO_DOCKER_REPO=$(REPO) \
	VERSION=$(VERSION) COMMIT=$(COMMIT) CRS_VERSION=$(CRS_VERSION) \
	$(KO) build \
	  --bare $(KO_LOCAL) \
	  --platform=$(KO_PLATFORM) \
	  --sbom=none \
	  --tags=$(KO_TAGS) \
	  --image-refs=./image.refs \
	  --image-label=org.opencontainers.image.source=$(IMAGE_SOURCE) \
	  .

image-publish: KO_LOCAL :=
image-publish: KO_PLATFORM := all
image-publish: image ## Build + push the multi-arch image (no --local). Requires REPO/KO_TAGS.

SBOM_FILE := barbacana-$(VERSION).cdx.json

sbom: $(CYCLONEDX_GOMOD) ## Generate CycloneDX SBOM at $(SBOM_FILE)
	$(CYCLONEDX_GOMOD) app -main . -licenses -json -output $(SBOM_FILE)

# Keyless cosign signing requires an OIDC token, so this is mainly driven by CI.
# The target exists so the flow is reproducible and documented.
sign: ## Keyless-sign IMG=<ref> with cosign (OIDC required)
	@[ -n "$(IMG)" ] || { echo "error: IMG=<image-ref> required"; exit 1; }
	cosign sign --yes "$(IMG)"

# Attestation binds the SBOM to the image digest via a keyless-signed in-toto
# statement. Replaces attaching the SBOM to the GitHub Release: the attested
# copy travels with the image and is cryptographically verifiable, so consumers
# do not need repo access to obtain a trusted SBOM.
attest: ## Attest $(SBOM_FILE) to IMG=<ref> as a CycloneDX predicate (OIDC required)
	@[ -n "$(IMG)" ] || { echo "error: IMG=<image-ref> required"; exit 1; }
	@[ -f "$(SBOM_FILE)" ] || { echo "error: $(SBOM_FILE) missing — run 'make sbom' first"; exit 1; }
	cosign attest --yes \
	  --predicate "$(SBOM_FILE)" \
	  --type cyclonedx \
	  "$(IMG)"

# Override CERT_IDENTITY_REGEXP / CERT_OIDC_ISSUER when verifying images signed
# by a different workflow.
CERT_IDENTITY_REGEXP ?= https://github.com/barbacana-waf/barbacana/\.github/workflows/.+@refs/tags/v.*
CERT_OIDC_ISSUER     ?= https://token.actions.githubusercontent.com

verify: ## Verify IMG=<ref> cosign signature against this repo's release workflow
	@[ -n "$(IMG)" ] || { echo "error: IMG=<image-ref> required"; exit 1; }
	cosign verify \
	  --certificate-identity-regexp='$(CERT_IDENTITY_REGEXP)' \
	  --certificate-oidc-issuer=$(CERT_OIDC_ISSUER) \
	  "$(IMG)"

verify-attestation: ## Verify IMG=<ref> CycloneDX SBOM attestation against this repo's release workflow
	@[ -n "$(IMG)" ] || { echo "error: IMG=<image-ref> required"; exit 1; }
	cosign verify-attestation \
	  --type cyclonedx \
	  --certificate-identity-regexp='$(CERT_IDENTITY_REGEXP)' \
	  --certificate-oidc-issuer=$(CERT_OIDC_ISSUER) \
	  "$(IMG)"

scan: ## Scan the published image with trivy; fail on CRITICAL/HIGH - against the image (pre-release gate)
	trivy image --severity CRITICAL,HIGH --exit-code 1 --ignore-unfixed $(REPO):$(VERSION)

scan-deps: ## Scan Go dependencies with trivy; fail on CRITICAL/HIGH (pre-release gate) - against the repo - scans only direct dependencies
	trivy fs --scanners vuln --severity CRITICAL,HIGH --exit-code 1 --ignore-unfixed .

govulncheck: $(GOVULNCHECK) ## Scan Go code for known vulns reachable from our call graph (Go vuln DB; fails only on reachable)
	$(GOVULNCHECK) ./...

validate: build ## Validate the example config
	./barbacana --config configs/example.yaml --validate

CFG ?= configs/example.yaml

render-config: build ## Print compiled Caddy JSON for CFG (default: configs/example.yaml)
	./barbacana --config $(CFG) --render-config

run: build ## Run locally with the example config
	./barbacana --config configs/example.yaml

## Run all CI checks locally (no image, no publish)
simulate-ci: rules lint vet tidy test build test-integration test-blackbox scan-deps govulncheck


clean: ## Remove build outputs
	rm -f ./barbacana ./barbacana-*.cdx.json
	rm -rf ./sbom ./image.refs
