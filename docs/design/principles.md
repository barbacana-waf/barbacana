# Principles

> **When to read**: designing a new feature, resolving a design ambiguity, reviewing a PR for architectural consistency, or onboarding a new contributor. **Not needed for**: implementing a specific protection (use `protections.md`), writing tests (use `testing.md`), or build tasks (use `build.md`).

## 1. Secure by default, explicit opt-out

**Decision: every protection ships enabled. The only user action is disabling.**

Users never turn protections ON. The config expresses deviations from the secure baseline via a flat `disable` list per route. If a new protection is added in a release, it is active for all users immediately. This means new protections must be safe to enable without configuration — they must not break well-formed traffic.

## 2. Stateless architecture

**Decision: no feature may require shared state between instances.**

No Redis, no database, no session store, no distributed cache. Each request is evaluated using only the request itself plus static configuration. This enables horizontal scaling with zero coordination. If a future feature genuinely requires state (e.g., session-based anomaly detection), it must be a separate optional sidecar, never part of the core request pipeline.

## 3. Path-first configuration

**Decision: the route (path + host) is the unit of ownership. All controls for a route live together.**

Config is never organized by feature. A team's CORS policy, CRS overrides, OpenAPI spec, and security header customizations all live in the same route block. In phase 2, each route loads from a separate file (`routes.d/`). In Kubernetes, each route maps to an HTTPRoute + SecurityPolicy in one namespace.

## 4. Flat exception model

**Decision: protections are identified by canonical names. Disabling uses a flat list.**

No nested booleans, no `crs.sqli.enabled: false` trees. The protection name in config (`sql-injection`) matches the protection name in Prometheus labels (`waf_requests_blocked_total{protection="sql-injection"}`) and the protection name in audit logs. One vocabulary everywhere.

## 5. Caddy is an implementation detail

**Decision: users never see, edit, or interact with Caddy configuration.**

The project's YAML compiles to Caddy JSON internally. Exposing raw Caddy config would allow users to break the security pipeline (middleware ordering, module conflicts). A `barbacana debug render-config` command outputs the generated config for troubleshooting, read-only. If someone needs raw Caddy, they should use Caddy directly.

## 6. CRS rules are an implementation detail

**Decision: users never see SecLang rule IDs or paranoia levels.**

The project maps human-readable protection names to CRS rule ranges internally. The CRS version is pinned and embedded. Protection names are the public API; rule IDs are private. The mapping is documented for advanced users and contributors but is not part of the user-facing interface.

## 7. Zero-config five-minute deploy

**Decision: the container image is the only artifact most users need.**

Pull image, set `UPSTREAM` env var or mount a minimal YAML, done. No xcaddy builds, no CRS downloads, no module compilation. The image contains everything: Go binary, embedded CRS rules, default config. The default config protects traffic immediately in detect-only mode.

## 8. Infrastructure as Code

**Decision: all configuration is declarative YAML suitable for Git.**

No imperative APIs for configuration changes. Config changes are applied by file update + reload signal. No management UI. In Kubernetes, config maps to standard Gateway API resources plus a SecurityPolicy CRD.

## 9. Team autonomy

**Decision: each team configures their routes independently.**

Phase 2 supports `routes.d/*.yaml` — one file per team. In Kubernetes, each team owns their HTTPRoute and SecurityPolicy in their namespace. Config changes to one team's routes never affect another team.

## 10. Observability is not optional

**Decision: Prometheus metrics and JSON audit logs are always on, from day one.**

Metrics use the same protection names as config. A single `/metrics` endpoint serves both Caddy-native and barbacana-specific metrics. Blocked requests produce audit log entries with enough context to diagnose without additional tooling.

## 11. Detect-only as the safe default

**Decision: global default is detect-only (log, don't block).**

Teams switch individual routes to blocking mode after validating false positives are resolved. The WAF must never break applications on first deployment.

## 12. No latency surprises

**Decision: document latency impact of every feature. Make expensive features opt-in.**

Protocol hardening and header manipulation: negligible, always on. OpenAPI validation: low, enabled when spec is provided. Response body inspection: medium (requires buffering), opt-in per route. The `waf_request_duration_overhead_seconds` metric exposes actual overhead.

## 13. Don't pretend to solve unsolvable problems

**Decision: exclude features that create a false sense of security.**

IP blocking is bypassed by VPNs. Rate limiting needs shared state. CAPTCHAs are defeated by AI. TLS fingerprinting has too many false negatives. These are excluded not because they're impossible, but because they mislead users. Cookie manipulation risks breaking applications. Virtual patching workflows are error-prone.

## 14. Semantic versioning on the public API

**Decision: protection names, config keys, metric labels, and CLI commands are versioned.**

Renaming a protection or removing a config key is a breaking change (major version bump). CRS updates and Caddy upgrades that don't change the public API are minor/patch releases.

## 15. Kubernetes Gateway API as the future

**Decision: phase 1 config schema must not conflict with future Gateway API mapping.**

The YAML structure maps cleanly to HTTPRoute + SecurityPolicy CRD resources. Gateway API integration is phase 2, but every config decision in phase 1 must be forward-compatible.

## 16. Single binary, single concern

**Decision: the WAF is a reverse proxy with security controls. Nothing else.**

Not an identity provider. Not a certificate authority (beyond Caddy ACME). Not a management UI. Not a DDoS appliance. Not a service mesh.

## 17. Go as the implementation language

**Decision: everything is Go. No exceptions.**

Caddy, Coraza, and the Gateway API ecosystem are Go. Single binary with `//go:embed` for CRS rules. Multi-arch container image.
