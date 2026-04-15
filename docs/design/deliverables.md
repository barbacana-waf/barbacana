# Deliverables

> **When to read**: working on Dockerfile, CI pipeline, Helm chart, release process, or versioning decisions. **Not needed for**: implementing protections, writing tests, or config schema work.

## Container image (primary artifact)

Multi-arch OCI image: `linux/amd64`, `linux/arm64`.

**Registry**: `ghcr.io/barbacana-waf/barbacana` (GitHub Packages)

**Tags**: `v1.2.3` (immutable), `v1.2`, `v1`, `latest`

**Contents**: single Go binary (Caddy + Coraza + barbacana module), OWASP CRS v4 embedded via `//go:embed`, default `waf.yaml`. Non-root user, minimal base (distroless or Alpine).

**Supply chain**: cosign signatures, SBOM attached, reproducible builds (pinned Go + CRS versions).


## CLI commands

Same binary as container. Usable standalone for dev and CI.

| Command | Purpose |
|---|---|
| `barbacana serve` | Start the WAF proxy (default in container) |
| `barbacana validate <config>` | Validate config without starting (CI pipelines) |
| `barbacana defaults` | Print all active protections with default values |
| `barbacana debug render-config <config>` | Output generated Caddy config (read-only) |
| `barbacana version` | Print version, Go version, CRS version |

## Documentation (separate repository)

Static site (mkdocs-material or similar). Two sections:

**Config reference** (semver applies): every protection name, config key, metric name, CLI command, ASVS mapping. Changelog with breaking change highlights.

**User guide**: quickstart (Docker Compose), Kubernetes deployment (Helm), onboarding workflow (detect-only → blocking), per-use-case examples, troubleshooting.

## Kubernetes CRDs (phase 2)

`SecurityPolicy` CRD attaching WAF config to HTTPRoute via Gateway API Policy Attachment. Controller watches HTTPRoute + SecurityPolicy, programs Caddy via Admin API. Published as optional install in Helm chart.

## Versioning

| Surface | Rule |
|---|---|
| Protection names | Semver — rename/removal is major |
| Config schema | Semver — key removal/type change is major |
| Metric names + labels | Semver — rename/label change is major |
| CLI commands + flags | Semver — removal/rename is major |
| Container image tags | Follows project semver |
| Helm chart | Independent semver, `appVersion` tracks project |
| CRS version (internal) | Pinned, updated in minor/patch |
| Caddy version (internal) | Pinned, updated in minor/patch |
| SecurityPolicy CRD | API group versioning (v1alpha1 → v1beta1 → v1) |


## Separate repositories

### Documentation

Static site with mkdocs-material. Hosted on GitHub Pages or similar. Contains config reference, user guide, and changelog.

### Helm chart

Separate chart repository: `ghcr.io/barbacana-waf/charts/barbacana`

Contents: Deployment (or DaemonSet), Service, ConfigMap for waf.yaml + routes, optional ServiceMonitor for Prometheus Operator. Documented `values.yaml`.
