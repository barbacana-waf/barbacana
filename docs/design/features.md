# Features

> **When to read**: planning work, checking if something is in scope, understanding what tier a feature belongs to, or deciding whether a proposed addition aligns with project goals. **Not needed for**: implementing a specific protection (use `protections.md`), understanding the request pipeline (use `architecture.md`).

## Tier 1 — MVP (build this first)

### Reverse proxy
- Auto TLS (Caddy ACME), HTTP/2, HTTP/3
- Reverse proxy with health checks, configurable backend timeout (default: 30s)
- Graceful reload via SIGHUP, zero downtime

### Negative security — CRS-backed protections
All enabled by default. See `protections.md` for the full canonical name list.
- SQLi, XSS (reflected + stored), RCE, LFI/RFI, PHP/Java/shell injection
- Session fixation, scanner detection, metadata leakage, XXE

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
- Request size/URL/header limits, allowed methods, Content-Type enforcement, Host header requirement
- HTTP/2: CONTINUATION flood, HPACK bomb, stream concurrency limits

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
- Per-route overrides (path + host matching)
- Flat `disable` list using canonical protection names
- Security header presets: `strict`, `moderate`, `api-only`

---

## Tier 2 — Production maturity (planned, not yet in scope)

- Per-route config from separate files (`routes.d/*.yaml`)
- Kubernetes Gateway API integration (GatewayClass + HTTPRoute + SecurityPolicy CRD)
- Hot reload via API endpoint
- Response-side: information leakage detection, open redirect prevention, response OpenAPI validation (all opt-in)
- Sensitive data redaction in logs
- OpenTelemetry trace export, SIEM forwarding, pre-built Grafana dashboard
- Bot defense: JS challenge (opt-in, browser paths only), User-Agent anomaly detection
- Access control: JWT validation, role-based route access, mTLS

## Tier 3 — AI augmentation (future)

- Auto false-positive detection from audit logs, CRS exclusion suggestions
- Embedding-based payload classification, session anomaly detection
- CVE feed monitoring, LLM-assisted rule authoring, traffic replay testing

## Tier 4 — Advanced (future)

- WebSocket, gRPC, GraphQL protocol-aware inspection
- Request/response transformation, circuit breaker
- Multi-tenant config, GitOps sync, canary config deployment, plugin API

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
