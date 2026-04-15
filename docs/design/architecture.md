# Architecture

> **When to read**: working on the request pipeline, understanding middleware ordering, designing how a new protection slots in, or debugging why a request was/was not evaluated. **Not needed for**: writing a single protection in isolation (use `protections.md` + `conventions.md`).

Barbacana is a thin Go module wrapping Caddy. Caddy provides the HTTP server, TLS, HTTP/2, HTTP/3, and reverse proxy. Coraza provides the CRS rule engine. Barbacana provides config compilation, the protection registry, native (non-CRS) protections, header injection/stripping, OpenAPI validation, metrics, and audit logs.

## Request lifecycle

The pipeline is a strict sequence. Every request flows through every stage in order. In blocking mode a stage may short-circuit with a block decision; later stages do not run for blocked requests. In detect-only mode the decision is recorded but the pipeline continues — see [Detect-only mode](#detect-only-mode) below.

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. TLS termination                              (Caddy)         │
│ 2. HTTP/2/3 frame limits                        (Caddy + cfg)   │
│ 3. Slow request / read timeouts                 (Caddy + cfg)   │
│ 4. Request size + URL + header limits           (request pkg)   │
│ 5. Protocol hardening                           (protocol pkg)  │
│       smuggling → CRLF → null byte → method override            │
│ 6. Input normalization                          (protocol pkg)  │
│       double-encoding → unicode NFC → path resolution           │
│ 7. Body parsing limits                          (request pkg)   │
│       JSON depth/keys → XML depth/entities                      │
│ 8. CORS preflight (if OPTIONS)                  (cors handler)  │
│ 9. File upload limits                           (request pkg)   │
│       file count → file size → MIME type → double-extension     │
│ 10. OpenAPI request validation                  (openapi pkg)   │
│       path → method → params → content-type → body              │
│ 11. CRS evaluation (request phases 1-2)         (crs pkg)       │
│ 12. Reverse proxy to upstream                   (Caddy)         │
│ 13. CRS evaluation (response phases 3-4)        (crs pkg)       │
│ 14. Security header stripping                   (headers pkg)   │
│ 15. Security header injection                   (headers pkg)   │
│ 16. Response to client                          (Caddy)         │
└─────────────────────────────────────────────────────────────────┘
```

Ordering rationale:
- Protocol hardening runs before normalization because smuggling and CRLF detection require the raw representation.
- Normalization runs before CRS so CRS sees a single canonical form (no `%253C` evading `<script>` rules).
- Body parsing limits run before OpenAPI and CRS so we never feed an unbounded payload to a parser.
- File upload limits run after generic body parsing (they reuse the same size cap) and before OpenAPI/CRS, so oversized or disallowed uploads are rejected before the multipart body is walked a second time by downstream stages.
- OpenAPI runs before CRS because contract violations are cheaper to evaluate and provide a stronger signal.
- CRS request evaluation runs immediately before the proxy. The proxy handler must never run before Coraza in the middleware chain.
- Header stripping runs before injection so injected values are not stripped by overlapping rules.

## Detect-only mode

`detect_only` (global or per-route) changes the terminal action of a block decision without changing the pipeline shape. Within a stage, when a protection produces a block decision:

| Step | Blocking mode | Detect-only mode |
|---|---|---|
| Audit log entry emitted | yes | yes (`action: "detected"`) |
| `waf_requests_blocked_total{protection=...}` incremented | yes | yes — the metric name is kept because the *detection* is what operators count |
| Subsequent pipeline stages | skipped | still run |
| Response returned | 403 (see [Error responses](#error-responses)) | handed to `next.ServeHTTP`, upstream serves normally |

Consequences:
- In detect-only mode a single request can accumulate multiple matched protections across stages. The audit log emits **one** aggregated entry at the end of the pipeline (`matched_protections` is a set), never one entry per stage.
- `action` in the audit log is `"blocked"` only when a response was actually short-circuited. `"detected"` means the upstream was called despite a match.
- Coraza is configured with `SecRuleEngine DetectionOnly` on routes where `detect_only` is true; native protections check the effective mode on the route context and fall through to `next.ServeHTTP` after recording the decision.

Detect-only is advisory to the pipeline, not to the protection itself. Protections always *evaluate* and always *record*; the mode controls only whether the recorded decision terminates the request.

## Error responses

Short-circuiting stages never write the response body themselves. They return a typed `Decision` and the pipeline's terminal handler renders it. The default rendering is:

```
HTTP/1.1 403 Forbidden
Content-Type: application/json

{"error":"blocked","request_id":"01HX4Y..."}
```

The default rendering is the secure one: a fixed 403, a fixed minimal JSON body, no headers beyond `Content-Type`, and no evaluation details. A route that does not configure `error_response` inherits exactly this.

Rules:
- `request_id` matches the ID in the audit log entry for the same request — that is the only contract between the client-visible response and the server-visible log.
- The body never names the matched protection, the CRS rule ID, or any other evaluation detail. Leaking those would turn the error response into a rule-bypass oracle.
- The status code is always `403` for protection-driven blocks. Transport-level rejections owned by Caddy (413 for size, 408 for slow-request timeout, 431 for header size) keep their native codes; those are set by stages 2–4 before the barbacana renderer runs.
- The response is produced by a single handler appended at the end of the route's handler list. Earlier handlers set the decision on the request context and call `return` without writing; the terminal renderer inspects the context and writes the response (or, if no block decision is present, is a no-op).

### Per-route custom responses

A route may override the default renderer via the `error_response` block in its config (schema in `config-schema.md`). Supported overrides:

- `status` — override the numeric status (still constrained to 4xx; 5xx is reserved for upstream failures).
- `body` — a templated JSON or text body. The only substitutions exposed are `{{.RequestID}}` and `{{.Timestamp}}`. Protection names are deliberately **not** available as a template variable.
- `headers` — extra response headers to set on blocked responses (e.g. `Retry-After` for routes behind a tarpit upstream).

Overrides can only narrow, not widen, the information the client sees. The template substitution set is closed (no access to matched protections, headers, body, or internal state), `status` cannot escalate to 5xx, and omitting any field falls back to the secure default above rather than to an empty value. The override is resolved at compile time into a pre-rendered template stored on the route, not per-request. An invalid template is a config validation error, not a runtime failure.

## Module boundaries

| Package | Responsibility | Imports |
|---|---|---|
| `main` | Wire startup: load config, register protections, build Caddy config, start server, signal handling. | `internal/*`, Caddy modules |
| `internal/config` | Parse and validate YAML. Produce a typed `Config` struct. Compile `Config` to Caddy JSON. | `gopkg.in/yaml.v3`, Caddy types |
| `internal/pipeline` | Orchestration helpers shared across protections (request context, decision objects, audit emission). Integration tests live here. | `internal/audit`, `internal/metrics` |
| `internal/protections` | The `Protection` interface and registry. Two-level hierarchy resolution. | none |
| `internal/protections/crs` | Coraza/CRS integration: rule loading, anomaly scoring, sub-protection mapping. | `coraza`, embedded `rules/` |
| `internal/protections/protocol` | Native protocol hardening + normalization protections. | `internal/protections` |
| `internal/protections/headers` | Security header injection and stripping. | `internal/protections` |
| `internal/protections/openapi` | OpenAPI 3.x contract enforcement. | `kin-openapi` (or chosen lib) |
| `internal/protections/request` | Size limits, methods, body parsing depth, multipart file upload limits (count, size, allowed types, double-extension). | `internal/protections` |
| `internal/metrics` | Prometheus registry, metric definitions, helpers. | `prometheus/client_golang` |
| `internal/audit` | Structured JSON audit log emission via slog. | `log/slog` |
| `internal/health` | `/healthz` and `/readyz` HTTP handlers. | none |
| `cmd` | CLI subcommands (`serve`, `validate`, `defaults`, `debug`, `version`). | `internal/*` |

Rules:
- `internal/*` packages must not import `main`, `cmd`, or `caddy/v2/cmd`.
- Protection packages must not import each other. Cross-protection coordination happens via the registry in `internal/protections`.
- Only `internal/config` knows about Caddy JSON. Other packages return decisions; the pipeline translates them to HTTP responses.

## Config compilation pipeline

```
waf.yaml ──► yaml.Unmarshal ──► Config struct ──► validate ──► Caddy JSON ──► Caddy
                                      │                            │
                                      └── used by registry         └── apps.http.servers.*
                                          (route → disable list)       handlers (ordered list)
```

Steps inside `internal/config`:
1. **Parse**: `yaml.v3` strict decoding. Unknown keys are errors.
2. **Defaults**: every unset field is populated from a `defaults.go` table. There is no implicit "zero means default" — the defaults pass writes the value explicitly.
3. **Validate**: every protection name in every `disable` list is checked against the live registry (both category and sub-protection names). Route paths must be absolute. Upstream URLs must parse. OpenAPI spec files must exist.
4. **Compile**: walk routes, emit a Caddy `apps.http.servers.barbacana` JSON tree. Each route becomes a Caddy `route` with an ordered handler list matching the lifecycle above. Coraza is configured per route (rule exclusions, DetectionOnly vs On).
5. **Hand to Caddy**: `caddy.Load(jsonBytes, false)` for initial start; `caddy.Load(jsonBytes, false)` again for SIGHUP reload (Caddy diffs internally, zero downtime).

The output of step 4 is what `barbacana debug render-config` prints. Users never edit it.

## Middleware ordering inside Caddy

Each route's handler list, in order:

```
1.  barbacana_request_limits      (size, URL, header counts)
2.  barbacana_protocol            (smuggling, CRLF, null-byte, method-override)
3.  barbacana_normalize           (double-encoding, unicode, path)
4.  barbacana_body_limits         (JSON/XML depth)
5.  barbacana_cors                (preflight short-circuit; non-OPTIONS pass through)
6.  barbacana_file_upload         (multipart file count/size/MIME/double-extension)
7.  barbacana_openapi             (path/method/params/body) — only if spec configured
8.  coraza                        (CRS request phases)
9.  reverse_proxy                 (the actual upstream call)
10. barbacana_response_headers    (strip + inject)
11. barbacana_error_renderer      (terminal; renders 403 JSON for block decisions, no-op otherwise)
```

`coraza` must precede `reverse_proxy`. The compiler asserts this in tests; a misordered handler list is a build-time failure.

## Protection hierarchy resolution

Two levels: **categories** (e.g. `sql-injection`) and **sub-protections** (e.g. `sql-injection-union`). Resolution at startup:

1. Each protection package calls `protections.Register(p)` from `main` (no `init()`).
2. `Register` indexes by canonical name. Categories also store the list of their sub-protection names.
3. For each route, the disable set is expanded: if `sql-injection` is disabled, the resolver adds every `sql-injection-*` sub-protection to the effective disable set.
4. The expanded set is frozen onto the route at compile time. No per-request hierarchy walking.

For CRS-backed protections: the disable set is translated to Coraza rule exclusions via `protections-crs-mapping.md`. Native protections check membership in the disable set in their handler entry point and `return next.ServeHTTP(...)` immediately if disabled.

## Metrics

All metrics are registered in `internal/metrics` at startup. `prometheus/client_golang` with the default registerer. The `/metrics` endpoint is served by Caddy's `metrics` handler, merged with the default Go process metrics.

| Metric | Type | Labels | Where incremented |
|---|---|---|---|
| `waf_build_info` | Gauge (always 1) | `version`, `go_version`, `crs_version` | startup |
| `waf_requests_total` | Counter | `route`, `action` | pipeline tail |
| `waf_requests_blocked_total` | Counter | `route`, `protection` (sub-protection) | each protection on block |
| `waf_anomaly_score_histogram` | Histogram | `route` | crs pkg after evaluation |
| `waf_openapi_validation_total` | Counter | `route`, `result` | openapi pkg |
| `waf_request_duration_overhead_seconds` | Histogram | `route` | pipeline (start − end minus proxy time) |
| `waf_security_headers_injected_total` | Counter | `route`, `header` | headers pkg |
| `waf_config_reload_total` | Counter | `result` | SIGHUP handler |
| `waf_config_reload_timestamp_seconds` | Gauge | none | SIGHUP handler |
| `waf_crs_rules_loaded_total` | Gauge | none | crs pkg startup |

Labels for `waf_requests_blocked_total` always use the **sub-protection** name. Categories are not used as label values to avoid double-counting.

## Audit log

Format: one JSON object per blocked or detected request, written to stdout via `slog`. One entry per request, never one entry per protection — fields aggregate.

```json
{
  "timestamp": "2026-04-14T10:32:11.482Z",
  "request_id": "01HX4Y...",
  "source_ip": "203.0.113.7",
  "method": "POST",
  "host": "api.example.com",
  "path": "/v1/users",
  "matched_protections": ["sql-injection", "sql-injection-auth"],
  "anomaly_score": 15,
  "action": "blocked",
  "response_code": 403
}
```

Notes:
- `matched_protections` includes both category and sub-protection names so downstream tooling can group either way.
- CRS rule IDs never appear in the audit log. They are emitted at `slog.LevelDebug` only, gated by config.
- The handler is `slog.NewJSONHandler(os.Stdout, ...)`. No log rotation, no file paths — that is the operator's concern (container stdout).
- Request ID is propagated from an inbound `X-Request-Id` header if present, otherwise generated (ULID).

## Reload semantics

`SIGHUP` triggers a config re-read. The file is parsed, validated, and compiled to Caddy JSON. If any step fails, the running config is unchanged and the failure is logged + counted in `waf_config_reload_total{result="failure"}`. If all steps succeed, `caddy.Load` is called with the new JSON and Caddy performs a zero-downtime swap.

The protection registry is **not** rebuilt on reload — only routes change. Adding a new protection requires a binary upgrade, not a config reload.

## What lives outside this pipeline

- **TLS certificates**: Caddy ACME, untouched.
- **HTTP/3**: Caddy native, configured via the same generated JSON.
- **Health endpoints**: a separate Caddy server block, not subject to the protection pipeline.
- **Metrics endpoint**: a separate Caddy server block, not subject to the protection pipeline.
