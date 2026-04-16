# All pinned third-party versions come from a single file.
include versions.mk

.PHONY: help build test test-integration test-minimal test-blackbox test-e2e image-test lint vet tidy \
        rules rules-clean \
        image image-publish scan \
        validate defaults run clean

# BARBACANA_VERSION comes from versions.mk. Override only for local smoke tests.
VERSION ?= $(BARBACANA_VERSION)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
REPO    ?= ghcr.io/barbacana-waf/barbacana

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

test-blackbox: build ## Run black-box functional tests with Hurl (SCENARIO=name to run one)
	@command -v hurl >/dev/null || { echo "hurl not installed — see https://hurl.dev"; exit 1; }
	go test -tags=blackbox ./tests/blackbox/ -v -count=1 $(if $(SCENARIO),-run TestBlackbox/$(SCENARIO))

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

lint: ## Run golangci-lint (version pinned in versions.mk)
	@command -v golangci-lint >/dev/null || { \
	  echo "golangci-lint not installed; expected $(GOLANGCI_LINT_VERSION)"; exit 1; }
	golangci-lint run ./...

vet: ## Run go vet
	go vet ./...

tidy: ## Ensure go.mod/go.sum are clean
	go mod tidy
	git diff --exit-code -- go.mod go.sum

rules: ## Download + verify CRS rules into rules/
	./scripts/fetch-crs.sh

rules-clean: ## Remove downloaded CRS rules
	rm -rf rules/*.conf rules/*.data internal/protections/crs/rules

image: rules ## Build the multi-arch image locally (does not push)
	KO_DOCKER_REPO=$(REPO) \
	VERSION=$(VERSION) COMMIT=$(COMMIT) CRS_VERSION=$(CRS_VERSION) \
	ko build --local --platform=linux/amd64,linux/arm64 .

image-publish: rules ## Build + push the multi-arch image with CycloneDX SBOM
	KO_DOCKER_REPO=$(REPO) \
	VERSION=$(VERSION) COMMIT=$(COMMIT) CRS_VERSION=$(CRS_VERSION) \
	ko build \
	  --platform=all \
	  --sbom=cyclonedx --sbom-dir=./sbom \
	  --tags=$(VERSION),latest \
	  --image-refs=./image.refs \
	  .

scan: ## Scan the published image with trivy; fail on CRITICAL/HIGH
	trivy image --severity CRITICAL,HIGH --exit-code 1 --ignore-unfixed $(REPO):$(VERSION)

validate: build ## Validate the example config
	./barbacana validate configs/example.yaml

defaults: build ## Print all protections with defaults
	./barbacana defaults

run: build ## Run locally with the example config
	./barbacana serve --config configs/example.yaml

clean: ## Remove build outputs
	rm -f ./barbacana
	rm -rf ./sbom ./image.refs
