# Principles

> **When to read**: designing a new feature, resolving a design ambiguity, reviewing a PR for architectural consistency, or onboarding a new contributor. **Not needed for**: implementing a specific protection (use `protections.md`), writing tests (use `testing.md`), or build tasks (use `build.md`).

## 1. Secure by default, explicit opt-out

**Decision: every protection ships enabled. The only user action is disabling.**

Users never turn protections ON. The config expresses deviations from the secure baseline via a flat `disable` list per route. If a new protection is added in a release, it is active for all users immediately. This means new protections must be safe to enable without configuration — they must not break well-formed traffic.

## 2. Security first, then user experience, then developer experience

**Decision: when principles conflict, this is the priority order.**

Security is unconditional and non-negotiable. If a security feature makes the config harder to write, security wins. User experience (easy to configure, easy to understand) comes second — when a developer experience shortcut would confuse a user, UX wins. Developer experience (clean code, elegant internals) comes third. This ordering resolves every ambiguity: a secure default that's slightly harder to configure beats a convenient default that's slightly less secure.

## 3. Path-first configuration

**Decision: the route (path + host) is the unit of ownership. All controls for a route live together.**

Config is never organized by feature. A team's CORS policy, CRS overrides, OpenAPI spec, and security header customizations all live in the same route block. In phase 2, each route loads from a separate file (`routes.d/`). In Kubernetes, each route maps to an HTTPRoute + SecurityPolicy in one namespace.

## 4. Flat exception model

**Decision: protections are identified by canonical names. Disabling uses a flat list.**

No nested booleans, no `crs.sqli.enabled: false` trees. The protection name in config (`sql-injection`) matches the protection name in Prometheus labels (`waf_requests_blocked_total{protection="sql-injection"}`) and the protection name in audit logs. One vocabulary everywhere.

## 5. Caddy is an implementation detail

**Decision: users never see, edit, or interact with Caddy configuration.**

The project's YAML compiles to Caddy JSON internally. Exposing raw Caddy config would allow users to break the security pipeline (middleware ordering, module conflicts). The `--render-config` flag emits the compiled Caddy JSON read-only for troubleshooting. If someone needs raw Caddy, they should use Caddy directly.

## 6. CRS rules are an implementation detail

**Decision: users never see SecLang rule IDs or paranoia levels in the configuration interface.**

The project maps human-readable protection names to CRS rule ranges internally. The CRS version is pinned and embedded. Protection names are the public API; rule IDs are private. The mapping is documented for contributors but is not part of the user-facing config or CLI. CRS rule IDs do appear in the audit log (`matched_rules` field) for SIEM correlation — this is an observability concern, not a configuration concern.

## 7. Zero-config five-minute deploy

**Decision: the container image is the only artifact most users need.**

Pull image, set `UPSTREAM` env var or mount a minimal YAML, done. No xcaddy builds, no CRS downloads, no module compilation. The image contains everything: Go binary, embedded CRS rules, default config. The default config protects and blocks traffic immediately.

## 8. Infrastructure as Code

**Decision: all configuration is declarative YAML suitable for Git.**

No imperative APIs for configuration changes. Config changes are applied by file update + reload signal. No management UI. In Kubernetes, config maps to standard Gateway API resources plus a SecurityPolicy CRD.

## 9. Team autonomy

**Decision: each team configures their routes independently.**

Phase 2 supports `routes.d/*.yaml` — one file per team. In Kubernetes, each team owns their HTTPRoute and SecurityPolicy in their namespace. Config changes to one team's routes never affect another team.

## 10. Observability is not optional

**Decision: Structured JSON audit logs to stdout are always on. Prometheus metrics and health endpoints are opt-in — disabled by default, enabled by setting `metrics_port` and `health_port`. Production deployments (Helm, docker-compose) should always enable them.**

Audit logs stream to stdout so operators never have to wire anything up to see what the WAF is doing; every blocked or detected request carries enough context (route ID, matched protections, CRS rule IDs, CWE identifiers) to diagnose locally and correlate in a SIEM. Metrics and health ports are *surface area*, though — a hobbyist who exposes Barbacana on port 443 should not also be exposing `/metrics` (route IDs, protection names, anomaly scores) and `/healthz` (a "this is a WAF" beacon) to the internet just because they accepted defaults. Opt-in by port turns them off for that user and on for the Helm chart and docker-compose examples, which ship with the production ports wired in.

## 11. Blocking by default, detect-only mode for tuning

**Decision: the default `mode` is `blocking`. `detect_only` is an opt-in escape hatch per route, and every detect-only route logs a warning at startup.**

A WAF that ships in detect-only mode is not secure by default — it's observable by default. Principle 1 requires that the default deployment blocks attacks immediately. Teams that need to onboard gradually switch specific routes to `mode: detect_only` while they tune false positives, then switch back to `blocking` when confident. The wire value is `detect_only` (not the shorter `detect`) to make the trade-off explicit in every config review: malicious requests are observed but not blocked. The server emits a startup warning per detect-only route so operators never forget a tuning flag was left on.

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

## 18. Stateless architecture

**Decision: no feature may require shared state between instances.**

No Redis, no database, no session store, no distributed cache. Each request is evaluated using only the request itself plus static configuration. This enables horizontal scaling with zero coordination. If a future feature genuinely requires state (e.g., session-based anomaly detection), it must be a separate optional sidecar, never part of the core request pipeline.

## 19. No breaking changes without a deprecation period

**Decision: deprecated in version N, still works in N+1, removed earliest in N+2 (next major).**

Breaking changes to the public API (config keys, protection names, metric labels, CLI commands, audit log fields) must never happen silently. A deprecated feature logs a warning at startup but continues to function for at least one major version. Removal requires a major version bump. If a breaking change is strictly necessary, it must be debated and documented before implementation. The `Since` and `Deprecated` annotations in the source code are the authoritative record of version lifecycle.

## 20. Documentation is layered from simple to expert

**Decision: every user starts at the same place. Depth is progressive, never required.**

The quickstart works without understanding CRS, anomaly scoring, or CWE identifiers. Configuration docs explain what each field does without assuming security expertise. Reference docs (generated from source) provide the full detail. Security docs go deep for compliance and assessment. A user who only reads the quickstart and configuration sections can deploy and operate a production WAF. A security expert who needs to assess detection coverage can navigate to the protection catalog, CWE mappings, and the curated rule set without wading through setup instructions.