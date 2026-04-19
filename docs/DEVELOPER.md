# Developer Guide

Everything you need to build, test, and release Barbacana locally.

## Prerequisites

Install these once on your machine.

### Required

| Tool | Why | macOS | Linux |
|---|---|---|---|
| **Go** (see [go.mod](go.mod) for pinned version) | Build, test, vet | `brew install go` | See [go.dev/dl](https://go.dev/dl/) |
| **Make** | Task runner | Preinstalled | Preinstalled (or `apt install make`) |
| **Git** | Clone + fetch CRS rules | `brew install git` | `apt install git` |

### Required for container work

| Tool | Why | macOS | Linux |
|---|---|---|---|
| **Podman** or **Docker** | `make image-test`, `make test-e2e` | `brew install podman` | `apt install podman` |

### Required for specific targets

| Tool | Used by | Install |
|---|---|---|
| **Trivy** | `make scan`, `make scan-deps`, `make simulate-ci` | `brew install trivy` |
| **Hurl** | `make test-blackbox`, `make test-e2e` | `brew install hurl` |

Version for Hurl is pinned in [versions.mk](versions.mk) — match it if you hit compatibility issues.

### Auto-installed

`make tools` installs `golangci-lint` and `ko` into `./bin/` at versions pinned in [versions.mk](versions.mk). No manual install needed — any target that needs them will trigger install on first use.

## Common workflows

### First-time setup

```bash
git clone https://github.com/barbacana-waf/barbacana
cd barbacana
make tools      # installs golangci-lint + ko under ./bin/
make rules      # fetches + verifies CRS rules
```

### Daily dev loop

```bash
make build      # compile ./barbacana
make test       # unit tests with -race
make run        # serve against configs/example.yaml
```

### Before pushing / opening a PR

```bash
make simulate-ci
```

Runs the full CI gate locally: `rules`, `lint`, `vet`, `tidy`, `test`, `build`, `test-integration`, and `scan-deps`. No image build or publish.

## Command reference

Run `make help` for the live list. Grouped by purpose below.

### Build

| Target | What it does |
|---|---|
| `make build` | Compile `./barbacana` with version ldflags |
| `make rules` | Download + verify CRS rules into `rules/` |
| `make rules-clean` | Remove fetched CRS rules |
| `make clean` | Remove build outputs |

### Test

| Target | What it does |
|---|---|
| `make test` | Unit tests with race detector |
| `make test-integration` | Integration tests (requires built binary) |
| `make test-minimal` | End-to-end smoke test (build, serve, curl, reload, shutdown) |
| `make test-blackbox` | Black-box functional tests with Hurl. Use `SCENARIO=name` to target one |
| `make test-e2e` | Compose-based end-to-end tests. Override `IMAGE=` to test a different artifact |
| `make image-test` | Build the local test container (`barbacana:test`) |

### Quality

| Target | What it does |
|---|---|
| `make lint` | Run `golangci-lint` (pinned version) |
| `make vet` | `go vet ./...` |
| `make tidy` | `go mod tidy` and fail if `go.mod`/`go.sum` changed |

### Security

| Target | What it does |
|---|---|
| `make scan-deps` | `trivy fs` against the repo — fast Go-dep scan, no image needed |
| `make scan` | `trivy image` against the published `$(REPO):$(VERSION)` image |

### Image + release

| Target | What it does |
|---|---|
| `make image` | Build multi-arch image locally with `ko` (does not push) |
| `make image-publish` | Build + push multi-arch image with SPDX SBOM |

### Misc

| Target | What it does |
|---|---|
| `make validate` | Validate `configs/example.yaml` |
| `make defaults` | Print all protections with their defaults |
| `make tools` | Install pinned dev tools into `./bin/` |
| `make simulate-ci` | Run the full local CI gate |

## Overriding defaults

These variables can be set on the command line:

| Variable | Default | Purpose |
|---|---|---|
| `VERSION` | `$(BARBACANA_VERSION)` from `versions.mk` | Override version stamped into the binary / image |
| `COMMIT` | Current git short SHA | Override commit stamped into the binary |
| `REPO` | `ghcr.io/barbacana-waf/barbacana` | Change image registry / repo |
| `IMAGE` | `barbacana:test` | Image reference used by `test-e2e` |
| `SCENARIO` | _(empty)_ | Run a single black-box scenario |

Example:

```bash
make image REPO=localhost/barbacana VERSION=dev
make test-e2e IMAGE=localhost/barbacana:dev
make test-blackbox SCENARIO=resource-protection
```

## Pinned versions

All third-party versions live in [versions.mk](versions.mk) (single source of truth, consumed by Makefile and CI). The Go toolchain is pinned in `go.mod`. Bump versions there — the next `make tools` invocation picks up the change via stamp files.
