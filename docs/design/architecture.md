# Architecture

> **When to read**: working on the request pipeline, understanding middleware ordering, designing how a new protection slots in, or debugging why a request was/was not evaluated. **Not needed for**: writing a single protection in isolation (use `protections.md` + `conventions.md`).

Barbacana is a thin Go module wrapping Caddy. Caddy provides the HTTP server, TLS, HTTP/2, HTTP/3, and reverse proxy. Coraza provides the CRS rule engine. Barbacana provides config compilation, the protection registry, native (non-CRS) protections, header injection/stripping, OpenAPI validation, metrics, and audit logs.

## Request lifecycle

The pipeline is a strict sequence. Every request flows through every stage in order. In `blocking` mode a stage may short-circuit with a block decision; later stages do not run for blocked requests. In `detect_only` mode the decision is recorded but the pipeline continues — see [Detect-only mode](#detect-only-mode) below.

```
┌─────────────────────────────────────────────────────────────────┐
│  1. TLS termination                             (Caddy)         │
│  2. HTTP/2/3 frame limits                       (Caddy + cfg)   │
│  3. Slow request / read timeouts                (Caddy + cfg)   │
│  4. Request size + URL + header limits          (request pkg)   │
│  5. Input normalization                         (protocol pkg)  │
│       double-encoding → path resolution → unicode NFC           │
│  6. Protocol hardening                          (protocol pkg)  │
│       smuggling → CRLF → null byte → method override            │
│  7. Body parsing limits                         (request pkg)   │
│       JSON depth/keys → XML depth/entities                      │
│  8. Resource protection                         (request pkg)   │
│       decompression ratio → body spooling to disk               │
│  9. File upload validation                      (request pkg)   │
│       file count → file size → MIME types → double extensions   │
│ 10. CORS preflight (if OPTIONS)                 (cors handler)  │
│ 11. OpenAPI request validation                  (openapi pkg)   │
│       path → method → params → content-type → body              │
│ 12. CRS evaluation (request phases 1-2)         (crs pkg)       │
│       with evaluation timeout + max-inspection-size             │
│ 13. Reverse proxy to upstream                   (Caddy)         │
│ 14. CRS evaluation (response phases 3-4)        (crs pkg)       │
│ 15. Security header stripping                   (headers pkg)   │
│ 16. Security header injection                   (headers pkg)   │
│ 17. Response to client                          (Caddy)         │
└─────────────────────────────────────────────────────────────────┘
```

Ordering rationale:
- Normalization runs before protocol hardening because `double-encoding` detection reads `URL.RawPath`, which `path-normalization` rewrites. Once the path is canonicalised, later stages — including smuggling and CRLF detection on headers, and CRS — see a single canonical form (no `%253C` evading `<script>` rules). Protocol hardening operates primarily on headers, so it is not harmed by path normalization running first.
- Body parsing limits run before resource protection, OpenAPI, and CRS so we never feed an unbounded payload to a parser.
- Body buffering (`io.ReadAll`) happens once at the start of stage 3. If the read fails (I/O error, connection reset), `bodyBytes` stays nil and all body-dependent protections (JSON/XML depth, decompression ratio, multipart, CRS body phases) silently skip. This is a deliberate fail-open posture — blocking on I/O errors would cause spurious 403s for interrupted uploads. In practice, body read failures are rare because Caddy has already buffered the request. If fail-closed behavior is needed in the future, the body read error path in `handler.go` should return a block decision instead of falling through.
- Resource protection (decompression ratio, body spooling) runs after basic parsing limits and before CRS. Decompression bombs are detected here. Bodies exceeding the memory buffer are spooled to temp disk so CRS evaluation doesn't OOM the process.
- File upload validation runs after resource protection and before OpenAPI/CRS because multipart parsing must be bounded first.
- OpenAPI runs before CRS because contract violations are cheaper to evaluate and provide a stronger signal.
- CRS request evaluation runs immediately before the proxy, wrapped in a context deadline (`evaluation_timeout`). The proxy handler must never run before Coraza in the middleware chain.
- Header stripping runs before injection so injected values are not stripped by overlapping rules.

### Content-type gating

The `accept.content_types` field on a route controls which parsers are active. If a route only accepts `application/json`, the XML parser never runs — no XML depth checking, no XML entity expansion checking, no XML-related CRS rules. A POST with a content type not in the accept list is rejected at stage 4 before any parsing occurs. This is both a security control and a performance optimization.

## Detect-only mode

`mode` (global or per-route) is either `blocking` (default) or `detect_only`. Setting `mode: detect_only` changes the terminal action of a block decision without changing the pipeline shape. Barbacana emits a startup warning for every route configured in `detect_only` so operators are always aware that malicious requests are being observed but not blocked. Within a stage, when a protection produces a block decision:

| Step | `blocking` mode | `detect_only` mode |
|---|---|---|
| Audit log entry emitted | yes | yes (`action: "detected"`) |
| `waf_requests_blocked_total{protection=...}` incremented | yes | yes — the metric name is kept because the *detection* is what operators count |
| Subsequent pipeline stages | skipped | still run |
| Response returned | 403 (see [Error responses](#error-responses)) | handed to `next.ServeHTTP`, upstream serves normally |

Consequences:
- In `detect_only` mode a single request can accumulate multiple matched protections across stages. The audit log emits **one** aggregated entry at the end of the pipeline (`matched_protections` is a set), never one entry per stage.
- `action` in the audit log is `"blocked"` only when a response was actually short-circuited. `"detected"` means the upstream was called despite a match.
- Coraza is configured with `SecRuleEngine DetectionOnly` on routes where `mode` is `detect_only`; native protections check the effective mode on the route context and fall through to `next.ServeHTTP` after recording the decision.

`detect_only` mode is advisory to the pipeline, not to the protection itself. Protections always *evaluate* and always *record*; the mode controls only whether the recorded decision terminates the request.

### Implementation note: OpenAPI detect-only guard

Most pipeline stages check `mode` at the handler level — the protection returns a block decision and the handler decides whether to act on it. The OpenAPI validator is the exception: it checks the mode internally and returns `Allow()` when `detect_only` is active, so the handler never sees a block. This works correctly but creates an inconsistency — a refactor that removes the internal check (expecting the handler to guard it, as every other stage does) would silently break `detect_only` for OpenAPI. If the OpenAPI validator is refactored, add an explicit `if h.resolved.Mode != config.ModeDetect` guard at the handler level (stage 8 in `handler.go`) to match the pattern used by all other stages.

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

A route may override the default renderer via the `error_response` block in its config (schema in `config-schema.md`). The only field currently supported is:

- `body` — a templated JSON or text body. The substitution set is closed: only `{{.RequestID}}` and `{{.Timestamp}}` are available. Protection names, matched rules, headers, and internal state are deliberately **not** exposed as template variables.

The template is compiled once at config resolution time (`text/template`) and stored on the resolved route; invalid templates are rejected as a config validation error rather than a runtime failure. Status code and response headers are not configurable — the status code is chosen by the pipeline based on the triggering protection (403 for protection-driven blocks, 413/415/431/etc. for transport-level rejections), and only `Content-Type: application/json` is set.

## Module boundaries

| Package | Responsibility | Imports |
|---|---|---|
| `main` | Wire startup: load config, register protections, build Caddy config, start server, signal handling. | `internal/*`, Caddy modules |
| `internal/config` | Parse and validate YAML. Produce a typed `Config` struct. Compile `Config` to Caddy JSON. | `gopkg.in/yaml.v3`, Caddy types |
| `internal/pipeline` | Orchestration helpers shared across protections (request context, decision objects, mode logic, error response generation, audit emission). Integration tests live here. | `internal/audit`, `internal/metrics` |
| `internal/protections` | The `Protection` interface and registry. Two-level hierarchy resolution. | none |
| `internal/protections/crs` | Coraza/CRS integration: rule loading, anomaly scoring, sub-protection mapping, evaluation timeout enforcement. | `coraza`, embedded `rules/` |
| `internal/protections/protocol` | Native protocol hardening + normalization protections. | `internal/protections` |
| `internal/protections/headers` | Security header injection and stripping. | `internal/protections` |
| `internal/protections/openapi` | OpenAPI 3.x contract enforcement. | `kin-openapi` (or chosen lib) |
| `internal/protections/request` | Size limits, methods, content-type gating, body parsing depth, decompression ratio, memory buffer/spooling, multipart file upload limits (count, size, allowed types, double-extension). | `internal/protections` |
| `internal/metrics` | Prometheus registry, metric definitions, helpers. | `prometheus/client_golang` |
| `internal/audit` | Structured JSON audit log emission via slog. | `log/slog` |
| `internal/health` | `/healthz` and `/readyz` HTTP handlers. | none |
| `internal/version` | Build-time version info populated via ldflags. | none |
| `cmd` | CLI entry point. Flag-driven: `--config <path>` selects the config (default `/etc/barbacana/waf.yaml`); `--validate`, `--render-config`, and `--version` are mutually exclusive mode flags. Bare invocation runs the server. | `internal/*` |

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
3. **Validate**: every protection name in every `disable` list is checked against the live registry (both category and sub-protection names). Route paths must be absolute. Upstream URLs must parse. OpenAPI spec files must exist. Content types must be valid MIME types.
4. **Compile**: walk routes, emit a Caddy `apps.http.servers.barbacana` JSON tree. Each route becomes a Caddy `route` with an ordered handler list matching the lifecycle above. Coraza is configured per route (rule exclusions, DetectionOnly vs On, SecRequestBodyNoFilesLimit from `max_inspect_size`, SecRequestBodyInMemoryLimit from `max_memory_buffer`). Path rewrites compile to Caddy `rewrite` handlers. Content-type gating determines which parser handlers are included. The top-level `data_dir` key compiles to Caddy's root `storage.file_system` JSON object (`module: file_system`, `root: <data_dir>`); this is where Caddy persists TLS certificates, ACME account keys, and OCSP staples across restarts.

   The listener shape depends on the deployment mode (see `config-schema.md`):
   - **Mode 1** (`host` is set): the server listens on `:443` and `:80`, a single host matcher is attached to every route, and automatic HTTPS provisions a Let's Encrypt certificate for the configured hostname. Caddy handles the `:80` → `:443` redirect.
   - **Mode 2** (no `host`, every route has `match.hosts`): hostnames are collected from all routes, the server listens on `:443` and `:80`, and automatic HTTPS provisions one certificate per hostname with the same redirect behavior.
   - **Mode 3** (`port` is set, no `host`, no `match.hosts`): the server listens on `:<port>` with plain HTTP only. Automatic HTTPS is disabled in the compiled JSON (`automatic_https.disable: true`) so Caddy never attempts to bind `:80`/`:443` or request certificates — the expectation is that a load balancer terminates TLS upstream of this process.
5. **Hand to Caddy**: `caddy.Load(jsonBytes, false)` for initial start; `caddy.Load(jsonBytes, false)` again for SIGHUP reload (Caddy diffs internally, zero downtime).

The output of step 4 is what `barbacana --render-config` prints. Users never edit it.

## Middleware ordering inside Caddy

Each route compiles to a short, fixed Caddy handler list:

```
 1.  rewrite          (Caddy native; strip_prefix, add_prefix, path replacement — only if configured)
 2.  barbacana        (the single WAF handler; runs every protection stage internally)
 3.  reverse_proxy    (the actual upstream call)
```

`rewrite` runs before `barbacana` so OpenAPI validation and CRS evaluation see the rewritten path (the path the upstream sees), not the original external path.

Every stage from the request lifecycle above runs inside the single `barbacana` handler (`http.handlers.barbacana`, implemented in `internal/pipeline/handler.go`). The handler calls the protection packages directly in a hard-coded order — there is no per-stage Caddy module registration. The stages executed by the handler, in order, are:

```
 1.  request validation           (size, URL, header counts, methods, content-type gating)
 2.  normalization + protocol     (double-encode → path-norm → unicode-norm → smuggling → CRLF → null-byte → method-override)
 3.  body buffering               (io.ReadAll once; body restored between stages)
 4.  decompression ratio          (gzip/deflate only, resource pkg)
 5.  body parsing limits          (JSON depth/keys → XML depth/entities)
 6.  multipart file upload        (file count/size/MIME/double-extension — only if RunMultipartParser)
 7.  CORS preflight               (short-circuits OPTIONS; non-OPTIONS pass through)
 8.  OpenAPI validation           (path/method/params/body — only if spec configured)
 9.  CRS evaluation               (Coraza engine; anomaly threshold enforced here)
10.  reverse proxy                (via next.ServeHTTP; response wrapped to strip/inject headers)
11.  response header strip/inject (on WriteHeader in the responseModifier wrapper)
```

Notes:
- `barbacana` must precede `reverse_proxy` so CRS evaluation runs before the upstream is called.
- CRS response-phase evaluation is not currently wired in; only request phases run today. Response-body inspection is listed as tier-2 opt-in in `protections.md` and is not implemented.
- Content-type gating (`RunJSONParser`, `RunXMLParser`, `RunMultipartParser`, `RunFormParser`) is evaluated at config resolution time and consulted inside the `barbacana` handler on each request — parsers are not conditionally added to the Caddy handler chain.
- Slow-request and HTTP/2 hardening are configured on the Caddy server itself (`read_header_timeout`, HTTP/2 frame limits) via the compiled JSON, not as handlers.

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
| `waf_evaluation_timeout_total` | Counter | `route` | crs pkg when deadline exceeded |
| `waf_body_spooled_total` | Counter | `route` | request pkg when body spooled to disk |
| `waf_decompression_rejected_total` | Counter | `route` | request pkg when ratio exceeded |
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
  "route_id": "public-api",
  "matched_protections": ["sql-injection", "sql-injection-auth"],
  "matched_rules": [942100, 942110],
  "cwe": ["CWE-89"],
  "anomaly_score": 15,
  "action": "blocked",
  "response_code": 403
}
```

In blocking mode, `matched_rules` contains only the rules from the stage that triggered the block:

```json
{
  "matched_protections": ["sql-injection", "sql-injection-auth"],
  "matched_rules": [942100],
  "cwe": ["CWE-89"],
  "action": "blocked"
}
```

In `detect_only` mode, the same request might accumulate across all stages:

```json
{
  "matched_protections": ["sql-injection", "sql-injection-auth", "xss-script-tag"],
  "matched_rules": [942100, 941110],
  "cwe": ["CWE-89", "CWE-79"],
  "action": "detected"
}
```

Notes:
- `matched_protections` includes both category and sub-protection names so downstream tooling can group either way.
- `route_id` is the route's ID from config. Enables per-team alert filtering.
- `matched_rules` contains CRS rule IDs that fired. Only populated for CRS-backed protections. Empty list `[]` for native protections (which are fully identified by their canonical name in `matched_protections`).
- `cwe` contains deduplicated CWE identifiers from the protection's catalog entry. Enables cross-tool correlation (WAF + scanner + SAST all speak CWE), compliance reporting, risk scoring.
- CRS rule IDs appear in `matched_rules` for SIEM correlation. They never appear in error responses to clients.
- The handler is `slog.NewJSONHandler(os.Stdout, ...)`. No log rotation, no file paths — that is the operator's concern (container stdout).
- Request ID is propagated from an inbound `X-Request-Id` header if present, otherwise generated (ULID).

## Reload semantics

`SIGHUP` triggers a config re-read. The file is parsed, validated, and compiled to Caddy JSON. If any step fails, the running config is unchanged and the failure is logged + counted in `waf_config_reload_total{result="failure"}`. If all steps succeed, `caddy.Load` is called with the new JSON and Caddy performs a zero-downtime swap.

The protection registry is **not** rebuilt on reload — only routes change. Adding a new protection requires a binary upgrade, not a config reload.

## What lives outside this pipeline

- **TLS certificate storage**: managed by Caddy at `data_dir` (default `/data/barbacana`). Certificates for all hostnames are stored in a single directory alongside ACME account keys and OCSP staples. Container deployments must mount this path as a persistent volume; otherwise every restart re-issues certificates and quickly hits Let's Encrypt rate limits. In Mode 3 the directory is unused at runtime but still defaulted so switching to auto-TLS only requires a config change, not a volume change.
- **HTTP/3**: Caddy native, configured via the same generated JSON.
- **Health endpoints**: served by a standalone `net/http` server on `health_port`, **only when `health_port > 0`**. Defaults to `0` (disabled) per principle 10. When disabled, no listener is opened and a startup info log records the fact.
- **Metrics endpoint**: served by a standalone `net/http` server on `metrics_port`, **only when `metrics_port > 0`**. Defaults to `0` (disabled). Prometheus metric *registration* happens unconditionally at startup so every protection handler can safely increment its counters — only the `/metrics` HTTP listener is gated on the port. This keeps protection call sites free of nil-checks; counters simply accumulate in memory with no observer when the port is `0`.
