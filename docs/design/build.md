# Build

> **When to read**: changing the Dockerfile, Makefile, CI pipeline, or release process; bumping Caddy/Coraza/CRS versions. **Not needed for**: writing Go code for a protection.

Barbacana ships as one artifact: a multi-arch OCI image containing a single Go binary with the CRS ruleset embedded. Everything in this document serves that single output.

## Pinned versions

All upstream versions are pinned. Bumps are deliberate, tested, and covered by semver (see `deliverables.md`).

| Component | Version | Where pinned |
|---|---|---|
| Go | `1.22.5` | `Dockerfile` (builder stage), `go.mod` `go` directive, `.github/workflows/ci.yml` |
| Caddy | `v2.8.4` | `Dockerfile` (xcaddy flag), `go.mod` (require) |
| Coraza | `github.com/corazawaf/coraza/v3 v3.2.1` | `go.mod` |
| coraza-caddy | `github.com/corazawaf/coraza-caddy/v2 v2.0.1` | `Dockerfile` (xcaddy flag) |
| OWASP CRS | `v4.7.0` | `Dockerfile` (curl/git tag), committed checksum file |
| xcaddy | `v0.4.2` | `Dockerfile` (go install) |
| golangci-lint | `v1.59.1` | `Makefile`, `.github/workflows/ci.yml` |

Pinning is enforced by checksum: the CRS tarball is verified against a SHA-256 committed in `rules/CRS_SHA256`. A mismatch fails the build.

## Dockerfile

Multi-stage: **rules** (download + verify CRS) → **builder** (xcaddy + go build with embedded rules) → **runtime** (distroless, non-root). The builder's output is a fully static binary; the runtime image needs no Go toolchain.

```dockerfile
# syntax=docker/dockerfile:1.7

########################
# Stage 1: CRS rules
########################
FROM alpine:3.20 AS rules
ARG CRS_VERSION=v4.7.0
ARG CRS_SHA256_FILE=CRS_SHA256
WORKDIR /crs

RUN apk add --no-cache curl tar

COPY rules/${CRS_SHA256_FILE} /crs/CRS_SHA256

RUN curl -fsSL -o crs.tar.gz \
      "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz" \
 && sha256sum -c CRS_SHA256 \
 && mkdir -p /crs/out \
 && tar -xzf crs.tar.gz -C /crs/out --strip-components=1 \
 && rm crs.tar.gz

# Only ship rules + crs-setup.conf.example. No tests, no docs.
RUN mkdir -p /crs/embed/rules \
 && cp /crs/out/crs-setup.conf.example /crs/embed/crs-setup.conf \
 && cp /crs/out/rules/*.conf /crs/out/rules/*.data /crs/embed/rules/ 2>/dev/null || true

########################
# Stage 2: builder
########################
FROM golang:1.22.5-alpine3.20 AS builder

ARG CADDY_VERSION=v2.8.4
ARG CORAZA_CADDY_VERSION=v2.0.1
ARG XCADDY_VERSION=v0.4.2
ARG VERSION=dev
ARG COMMIT=unknown

WORKDIR /src

RUN apk add --no-cache git ca-certificates build-base

# Install xcaddy
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}

# Cache Go module downloads
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy source + embedded CRS rules into the tree so //go:embed picks them up
COPY . .
COPY --from=rules /crs/embed ./rules

# Build with xcaddy — this produces a single binary containing Caddy + coraza-caddy + barbacana.
# The barbacana package registers Caddy modules and embeds rules via //go:embed.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 \
    xcaddy build ${CADDY_VERSION} \
      --output /out/barbacana \
      --with github.com/corazawaf/coraza-caddy/v2@${CORAZA_CADDY_VERSION} \
      --with github.com/barbacana/barbacana=/src \
      --ldflags "-s -w -X github.com/barbacana/barbacana/internal/version.Version=${VERSION} -X github.com/barbacana/barbacana/internal/version.Commit=${COMMIT}"

########################
# Stage 3: runtime
########################
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

LABEL org.opencontainers.image.source="https://github.com/barbacana/barbacana"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /out/barbacana /usr/local/bin/barbacana
COPY configs/example.yaml /etc/barbacana/waf.yaml

USER nonroot:nonroot
EXPOSE 8080 8081 9090

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/barbacana", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/barbacana"]
CMD ["serve", "--config", "/etc/barbacana/waf.yaml"]
```

Notes:
- Distroless `static-debian12:nonroot` has no shell and no `wget`. The `HEALTHCHECK` calls a dedicated `barbacana healthcheck` subcommand that performs a local HTTP GET to `/healthz` and exits 0/1.
- CRS rules are copied into `./rules` in the build context so `//go:embed rules/**` in the barbacana package picks them up at compile time. The runtime image does not need a filesystem copy of rules.
- The binary is a single static ELF; no libc dependency.
- Multi-arch is produced by `docker buildx` (see below), not by in-Dockerfile cross-compile magic. BuildKit handles the cross-build per `--platform`.

## xcaddy command

Standalone form for local reproduction outside the Dockerfile:

```
xcaddy build v2.8.4 \
  --output ./barbacana \
  --with github.com/corazawaf/coraza-caddy/v2@v2.0.1 \
  --with github.com/barbacana/barbacana=.
```

The `--with github.com/barbacana/barbacana=.` form is a replace directive — xcaddy inserts a `replace` into the ephemeral module so the local source is used instead of a network fetch. This is how we always build: the project owns its own Caddy modules.

## CRS rules + `//go:embed`

- Rules live under `rules/` in the repo **only during build** (the Docker `rules` stage writes them; locally, `make rules` fetches them).
- `rules/` is in `.gitignore` with a carve-out for `rules/CRS_SHA256` (the pinned checksum) and `rules/.gitkeep`.
- `internal/protections/crs/embed.go`:
  ```go
  package crs

  import "embed"

  //go:embed rules/*.conf rules/*.data crs-setup.conf
  var FS embed.FS
  ```
  Path note: the embed directive is relative to the Go package. The build copies `rules/` and `crs-setup.conf` into that package's directory before `go build` runs.
- At runtime, Coraza is initialized from `FS`. There is no file system lookup; the binary is self-contained.

## Makefile

```makefile
.PHONY: help build test test-integration lint vet tidy \
        rules rules-clean \
        docker-build docker-build-multi docker-push \
        validate defaults run clean

VERSION   ?= dev
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
IMAGE     ?= ghcr.io/barbacana/barbacana
PLATFORMS ?= linux/amd64,linux/arm64

help:
	@awk 'BEGIN{FS":.*##"} /^[a-zA-Z_-]+:.*##/{printf "  %-20s %s\n",$$1,$$2}' $(MAKEFILE_LIST)

build: rules ## Build the barbacana binary locally via xcaddy
	xcaddy build v2.8.4 \
		--output ./barbacana \
		--with github.com/corazawaf/coraza-caddy/v2@v2.0.1 \
		--with github.com/barbacana/barbacana=.

test: ## Run unit tests with race detector
	go test -race ./...

test-integration: build ## Run integration tests (requires built binary)
	go test -tags=integration -race ./internal/pipeline/...

lint: ## Run golangci-lint
	golangci-lint run ./...

vet: ## Run go vet
	go vet ./...

tidy: ## Ensure go.mod/go.sum are clean
	go mod tidy
	git diff --exit-code -- go.mod go.sum

rules: ## Download + verify CRS rules into rules/ (local dev)
	./scripts/fetch-crs.sh

rules-clean: ## Remove downloaded CRS rules
	rm -rf rules/*.conf rules/*.data

docker-build: ## Build a single-arch image for local use
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		-t $(IMAGE):$(VERSION) .

docker-build-multi: ## Build multi-arch images (linux/amd64, linux/arm64)
	docker buildx build \
		--platform $(PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		-t $(IMAGE):$(VERSION) \
		.

docker-push: ## Build + push multi-arch (requires buildx builder configured)
	docker buildx build \
		--platform $(PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		-t $(IMAGE):$(VERSION) \
		--push \
		.

validate: build ## Validate the example config
	./barbacana validate configs/example.yaml

defaults: build ## Print all protections with defaults
	./barbacana defaults

run: build ## Run locally with the example config
	./barbacana serve --config configs/example.yaml

clean: ## Remove build outputs
	rm -f ./barbacana
```

## CI pipeline (GitHub Actions)

Location: `.github/workflows/ci.yml`. Stages run in order; a failure in any stage fails the build.

```yaml
name: ci

on:
  push:
    branches: [main]
    tags: ["v*"]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: "1.22.5" }
      - uses: golangci/golangci-lint-action@v6
        with: { version: v1.59.1, args: --timeout=5m }
      - run: go vet ./...
      - run: go mod tidy && git diff --exit-code -- go.mod go.sum

  test:
    needs: [lint]
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: "1.22.5" }
      - run: go test -race ./...

  build:
    needs: [test]
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: "1.22.5" }
      - run: make rules
      - run: make build
      - run: make test-integration

  docker-build:
    needs: [build]
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-qemu-action@v3
      - uses: docker/setup-buildx-action@v3
      - name: Build multi-arch image (no push on PR)
        if: github.event_name == 'pull_request'
        run: make docker-build-multi VERSION=pr-${{ github.event.pull_request.number }}

  docker-push:
    needs: [build]
    if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      packages: write
      id-token: write                    # for cosign keyless signing
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-qemu-action@v3
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - name: Tag from git tag
        id: tag
        run: echo "version=${GITHUB_REF#refs/tags/}" >> "$GITHUB_OUTPUT"
      - run: make docker-push VERSION=${{ steps.tag.outputs.version }}
      - uses: sigstore/cosign-installer@v3
      - name: Sign image (cosign keyless)
        run: cosign sign --yes ghcr.io/barbacana/barbacana:${{ steps.tag.outputs.version }}
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          image: ghcr.io/barbacana/barbacana:${{ steps.tag.outputs.version }}
          format: spdx-json
          output-file: sbom.spdx.json
      - uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.spdx.json
```

Stages summary: **lint** (golangci-lint + vet + tidy) → **test** (unit + race) → **build** (rules + xcaddy + integration) → **docker-build** on PRs, **docker-push** on tags (with cosign signature and SBOM).

## Multi-arch build

Produced with `docker buildx` using the standard QEMU emulation setup:

```
docker buildx create --use --name barbacana-builder
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/barbacana/barbacana:v1.0.0 \
  --push \
  .
```

Both platforms go under the same tag — the manifest is a multi-arch index. Pulls on any machine resolve to the correct arch automatically.

## Running locally

The happy path from a clean clone:

```
git clone https://github.com/barbacana/barbacana.git
cd barbacana
make rules         # fetches CRS and verifies checksum
make build         # produces ./barbacana
make test          # runs unit tests
./barbacana serve --config configs/example.yaml
```

The example config proxies `:8080` to `http://localhost:8000`. Health is served on `:8081/healthz`, metrics on `:9090/metrics`.

Container equivalent:

```
make docker-build
docker run --rm -p 8080:8080 -p 9090:9090 \
  -v "$PWD/configs/example.yaml:/etc/barbacana/waf.yaml:ro" \
  ghcr.io/barbacana/barbacana:dev
```

## Release process

1. Update `CHANGELOG.md` with the release notes.
2. Bump version references in documentation if the schema or CLI changed.
3. Run `make test test-integration lint` locally.
4. Create an annotated tag `vX.Y.Z` and push. The CI `docker-push` job publishes the multi-arch image, cosign signature, and SBOM.
5. Create a GitHub Release pointing to the tag; attach the SBOM.
6. Helm chart release happens in the separate chart repository referenced in `deliverables.md`.
