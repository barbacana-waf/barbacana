# Features

> **When to read**: planning work, checking if something is in scope, understanding what tier a feature belongs to, or deciding whether a proposed addition aligns with project goals. **Not needed for**: implementing a specific protection (use `protections.md`), understanding the request pipeline (use `architecture.md`).

## Tier 1 — MVP (build this first)

### Reverse proxy
- Auto TLS (Caddy ACME), HTTP/2, HTTP/3
- Reverse proxy with health checks, configurable backend timeout (default: 30s)
- Path rewrites: `strip_prefix`, `add_prefix`, `path` (full replace). No regex rewrites.
- Graceful reload via SIGHUP, zero downtime

### Negative security — CRS-backed protections
All enabled by default. See `protections.md` for the full canonical name list.
- SQLi, XSS (reflected + stored), RCE, LFI/RFI, PHP/Java/shell injection
- Session fixation, scanner detection, metadata leakage, XXE
- Generic injection (Node.js, SSTI, LDAP, SSI, expression language)
- Multipart attack detection
- Response data leakage (SQL, Java, PHP, IIS error patterns)

### Positive security — OpenAPI contract enforcement
- OpenAPI 3.x spec per route: path, method, content-type, query param, and body schema validation
- Unknown endpoint rejection, shadow API discovery (log undeclared paths)
- Detect-only and blocking modes per route

### Security headers
All injected by default. See `protections.md` for defaults and canonical names.
- HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- X-DNS-Prefetch-Control, COOP, COEP, CORP, Permissions-Policy, Cache-Control
- Strip: Server, X-Powered-By, X-AspNet-Version, X-Generator, X-Varnish, Via, X-Debug-Token, etc.

### CORS
- Disabled by default, opt-in per route
- Origin allowlist, method/header allowlists, max-age, preflight handling

### Protocol hardening
All enabled by default. See `protections.md` for the full list.
- Request smuggling, CRLF injection, null byte injection, method override blocking
- Double encoding detection, Unicode normalization, path normalization
- HTTP parameter pollution policy, slow request protection
- HTTP/2: CONTINUATION flood, HPACK bomb, stream concurrency limits

### Request acceptance
- Accepted content types per route — gates which parsers run (no XML parsing if route only accepts JSON)
- Allowed methods, Host header requirement
- Request size/URL/header limits
- Body parsing limits (JSON depth/keys, XML depth/entity expansion)
- File upload limits (file count, file size, allowed MIME types, double extension rejection)

### Resource protection (anti-DoS for the WAF itself)
- Max inspection size for non-file body content (default: 128KB) — CRS only evaluates this many bytes, preventing CPU exhaustion on large payloads
- Max memory buffer for body spooling (default: 128KB) — bodies above this spool to temp disk, preventing OOM
- Decompression ratio limit (default: 100:1) — rejects compressed payloads that expand beyond the ratio, preventing decompression bombs (CWE-409)
- WAF evaluation timeout (default: 50ms) — context deadline on CRS rule evaluation, kills runaway regex or ReDoS payloads

### Observability
- Prometheus `/metrics` (single endpoint, Caddy + WAF metrics merged)
- Key metrics: `waf_requests_total`, `waf_requests_blocked_total{protection}`, `waf_anomaly_score_histogram`, `waf_openapi_validation_total`, `waf_request_duration_overhead_seconds`
- Operational: `waf_config_reload_total`, `waf_crs_rules_loaded_total`, `waf_build_info`
- Structured JSON audit logs to stdout, request ID propagation

### Operational
- `/healthz` and `/readyz` endpoints
- `barbacana validate <config>` CLI
- `barbacana defaults` — print all active protections with defaults
- `barbacana debug render-config` — output generated Caddy config (read-only)
- Detect-only as global default, per-route blocking mode
- Append-only audit logs, no truncation API

### Configuration model
- Global baseline with secure defaults
- Per-route overrides (path + host matching, optional match block)
- Flat `disable` list using canonical protection names
- Three security header presets: `strict`, `moderate`, `api-only`

---

## Tier 2 — Production maturity (planned, not yet in scope)

- Per-route config from separate files (`routes.d/*.yaml`)
- Kubernetes Gateway API integration (GatewayClass + HTTPRoute + SecurityPolicy CRD)
- Hot reload via API endpoint
- Response-side: open redirect prevention, response OpenAPI validation (all opt-in)
- Sensitive data redaction in logs
- OpenTelemetry trace export, SIEM forwarding, pre-built Grafana dashboard
- Bot defense: JS challenge (opt-in, browser paths only), User-Agent anomaly detection
- Access control: JWT validation, role-based route access, mTLS
- CEL custom rules: per-route expressions evaluated against request fields, with named rules appearing in metrics and audit logs
- External HTTP callout hooks at defined pipeline stages (beforeCRS, beforeProxy, afterResponse) with configurable timeout and fail-open/fail-closed behavior
- Raw SecLang escape hatch per route (opt-in, for advanced users migrating from ModSecurity/Coraza)

## Tier 3 — AI augmentation (future)

- Auto false-positive detection from audit logs, CRS exclusion suggestions
- Embedding-based payload classification, session anomaly detection
- CVE feed monitoring, LLM-assisted rule authoring, traffic replay testing
- AI scoring as a hook target (ML sidecar called via the external hooks mechanism)

## Tier 4 — Advanced (future)

- WebSocket, gRPC, GraphQL protocol-aware inspection
- Request/response transformation, circuit breaker
- Multi-tenant config, GitOps sync, canary config deployment
- Go plugin interface for compile-time extensions (custom `Plugin` interface, build with xcaddy)

---

## Explicit non-goals (will not be implemented)

- Identity management (login flows, SSO, MFA, user databases)
- Management UI (config is YAML + Git; observability is Grafana/Prometheus)
- Volumetric DDoS protection (L3/L4 — needs network-level mitigation)
- CAPTCHA (defeated by AI solvers, hostile UX)
- Response body rewriting / script injection
- IP-based blocking/allowlisting (bypassed by VPNs)
- Rate limiting (requires shared state, violates stateless principle)
- TLS fingerprinting (too many false negatives)
- Cookie manipulation (risk of breaking applications)
- Certificate management beyond Caddy ACME
- Virtual patching UI/workflow (error-prone)
