# Code Walkthrough — A Reader's Orientation

**Status:** living doc, first pass 2026-04-24
**Audience:** a developer opening this codebase for the first time (or the twentieth time, after a month away)
**Intent:** after reading this, you should be able to (a) draw the module map from memory, (b) trace a request through the pipeline without grepping, and (c) know where to click when you hear "we need to add a new protection" / "CRS isn't firing on this route" / "the config won't load".

This is deliberately separate from `architecture.md`. Architecture describes the *design*; this doc describes the *code*. If the two disagree, the code is truth; please update whichever is stale.

---

## 1. The 30-second picture

Barbacana is a Go binary that embeds **Caddy** as its HTTP server, wraps it with a single Caddy middleware called `http.handlers.barbacana` (implemented in `internal/pipeline`), and uses **Coraza** to evaluate **OWASP CRS v4** rules. Everything else — YAML parsing, per-route protection orchestration, audit logging, metrics, health, cookie hardening, CORS, OpenAPI validation — is pure Go code in `internal/`.

```
┌──────────────────────────────────────────────────────────┐
│ main.go                                                  │
│   └── cmd.Execute()  (flag-based CLI, not cobra)         │
│         ├── --validate    → config load + exit           │
│         ├── --render-config → config load + print JSON   │
│         ├── --version     → print + exit                 │
│         └── (default)     → runServe()                   │
│                                                          │
│ runServe():  Load → Resolve → RegisterConfigs            │
│              → Compile → caddy.Load(JSON)                │
│              → start health/metrics (optional)           │
│              → wait for SIGHUP/SIGTERM                   │
│                                                          │
│ Caddy listens on :443/:80 (modes 1–2) or :PORT (mode 3). │
│ Each HTTP request goes through http.handlers.barbacana,  │
│ which runs the 9-stage pipeline, then hands off to       │
│ Caddy's reverse_proxy. The response passes back through  │
│ a responseModifier wrapper for header stripping,         │
│ injection, cookie hardening, CORS headers, and error     │
│ masking.                                                 │
└──────────────────────────────────────────────────────────┘
```

---

## 2. Module layout — one paragraph each

All first-party code lives under `internal/`. Third-party dependencies (Caddy, Coraza) are at the top of the dependency graph; Barbacana glues them together.

### `internal/config`
Owns the YAML schema, validation, defaults, per-route resolution, and compilation to Caddy JSON.

- **`types.go`** — the `Config` / `Global` / `Route` / `Resolved` structs and their YAML tags. `Resolved` is the fully materialized per-route view after merging globals, parsing durations/sizes, computing `TLSMode`/`AllowedOrigins`, etc.
- **`load.go`** — the entry point. Reads YAML with `KnownFields(true)` (strict; unknown keys error), applies defaults, validates.
- **`parse.go`** — YAML decoding helpers (sizes like `"1MB"`, durations like `"5s"`).
- **`defaults.go`** — fills in zero-value fields from hardcoded defaults.
- **`validate.go`** — structural and semantic validation. Enforces mutual exclusion of deployment modes 1/2/3.
- **`resolve.go`** — merges global + route config into `Resolved`. Also computes `TLSMode` and `AllowedOrigins` (used by CSRF protections).
- **`compile.go`** — produces the Caddy JSON blob consumed by `caddy.Load()`. Output is minimal: Caddy gets the reverse proxy + this middleware, nothing else.
- **`rewrite.go`** — path-rewriting helpers (strip prefix, etc.) used by Compile.

### `internal/pipeline`
The Caddy middleware. One file, `handler.go`, does most of the work.

- **`handler.go`** — `Handler` struct (Caddy module), `Provision()` to build per-route protection instances, `ServeHTTP()` to run the 9 stages, `responseModifier` wrapper, `auditCollector` for cross-stage decision accumulation.
- **`store.go`** — a package-level `map[string]*config.Resolved` populated by `RegisterConfigs()` at boot. Caddy instantiates `Handler` by cloning the struct, so only `RouteID` makes it across; `Provision` uses it as a key into this map to retrieve the full resolved config.
- **`init()`** — registers the Caddy module (`caddy.RegisterModule(Handler{})` in `handler.go:29`).

### `internal/protections`
The shared types and registry. Note: the **registry is optional** — most protections are invoked directly by the pipeline handler, not looked up through the registry. The registry exists primarily for disable-list validation.

- **`protection.go`** — the `Protection` interface (`Name() / Category() / CWE() / Evaluate()`) and the `Decision` struct (`Block / Protection / Reason / MatchedRules`).
- **`registry.go`** — a thread-safe map from canonical name to `Protection` instance. Each protection package calls `Register(reg)` on the global instance from its own `Register()` helper.
- **`catalog.go`** — the **canonical source of truth** for protection names and their sub-protection IDs (CRS rule IDs for CRS-backed ones, empty for native ones). Also the CWE map. This is a pure function, not a populated structure — it returns new maps on each call.
- **`inspection.go`** — the `InspectionPath` type and its context key. Normalization stages write to this; CRS reads from it; `r.URL` is never mutated. This is the mechanism behind "normalization is for detection, not proxying".
- **`response.go`** — helper for writing block responses (error templates, request IDs).

### `internal/protections/request`
Per-request validation that needs only headers or the raw body.

- **`request.go`** — `Validator`: methods allow-list, host-header required, URL/header length caps, content-type gating, JSON/XML body limit checks.
- **`resource.go`** — `ResourceValidator`: body size, decompression ratio limits for gzip/deflate bodies.
- **`multipart.go`** — `MultipartValidator`: file count, per-file size, double-extension detection.
- **`origin.go`** — `OriginValidator` (CSRF origin check). Stage 1b.

### `internal/protections/protocol`
Native protocol-level checks. Each implements `Protection` and is instantiated by `pipeline.Handler.Provision()` as a slice iterated in stage 2.

- **`normalization.go`** — `DoubleEncode`, `PathNorm`, `UnicodeNorm`. Must run before smuggling/CRLF/null-byte checks; order matters and is enforced in `handler.go:74-83`.
- **`protocol.go`** — `Smuggling`, `CRLF`, `NullByte`, `MethodOverrideStrip`.
- **`slowrequest.go`** — the slow-request / HTTP/2 frame-flood handler. Wired at the Caddy server level via `compile.go`, not as a pipeline stage.

### `internal/protections/headers`
Response-side middleware.

- **`headers.go`** — `Stripper` (removes upstream headers like Server, X-Powered-By) and `Injector` (adds security headers per preset: strict / moderate / permissive).
- **`cors.go`** — `CORSHandler`. Handles preflights (stage 7) and injects CORS/Vary headers on responses.
- **`cookies.go`** — `CookieHardener`. Adds `SameSite=Lax` and `Secure` (gated by `TLSMode`) to Set-Cookie headers that lack them.

### `internal/protections/openapi`
OpenAPI 3 spec validation. `NewValidator(specPath, resolved)` loads the spec at provision time; `Validate(ctx, r)` checks path/method/params/body/content-type at stage 8.

### `internal/protections/crs`
Coraza WAF integration.

- **`embed.go`** — `//go:embed rules/*.conf rules/*.data crs-setup.conf` bakes the CRS ruleset into the binary. The exported `FS` is a read-only embed.FS.
- **`crs.go`** — `Engine`. One engine per route (`Provision` calls `NewEngine(*res)`). Loads `crs-setup.conf`, removes rules corresponding to disabled sub-protections, loads all `*.conf` files in order (with `curated-rules.conf` spliced in at the right point so PL2/PL3 rules feed the anomaly aggregator).
- **`mapping.go`** — translates Coraza rule IDs back to canonical protection names. Used when audit-logging CRS matches.
- **`curated/curated.go`** — the hand-picked PL2/PL3 rules that are force-enabled on top of PL1. Their IDs and text live here so the tool in `cmd/tools/rules` can regenerate the embedded `curated-rules.conf`.

### `internal/protections/response`
Response-body inspection protections. Currently only `response-error-masking`; `response-open-redirect` and `response-openapi` are catalogued but not yet wired.

### `internal/audit`
Structured audit log emission. `Emit(ctx, Entry)` writes one `slog.InfoContext` per matched request, with timestamp, request ID, source IP, matched protections, CRS rule IDs, CWEs, anomaly score, action (`blocked` / `detected` / `masked`), and response code.

### `internal/metrics`
Prometheus counters, gauges, and histograms. `Init()` registers them on the default registerer. **Called unconditionally at startup** (even if the `/metrics` endpoint is disabled), because protection handlers and CRS reference the counters from the hot path and nil-checking every call would be noisy.

### `internal/health`
`/healthz` and `/readyz` endpoints served by a plain `net/http` server. Deliberately outside Caddy so liveness checks aren't gated by the WAF pipeline.

### `internal/version`
Version string embedded at build time via ldflags.

### `cmd/`
The CLI. Uses Go's `flag` package (not cobra).

- **`root.go`** — `Execute()` / `run()`. Parses four mutually exclusive modes: `--validate`, `--render-config`, `--version`, or default (serve).
- **`serve.go`** — `runServe()`. Orchestrates the boot sequence. Also handles SIGHUP reload.
- **`validate.go`**, **`render.go`**, **`version.go`** — the one-shot commands.
- **`tools/rules/`** — a separate binary that regenerates `curated-rules.conf` from `curated/curated.go`. Not shipped; developer tool.

---

## 3. Boot sequence

### 3.1 What `main.go` does

```go
package main

import (
    _ "github.com/caddyserver/caddy/v2/modules/standard"   // Caddy built-ins
    _ "github.com/corazawaf/coraza-caddy/v2"                // unused but safe

    _ "github.com/barbacana-waf/barbacana/internal/pipeline" // registers Caddy module
    _ "github.com/barbacana-waf/barbacana/internal/protections/*" // linker-force

    "github.com/barbacana-waf/barbacana/cmd"
)

func main() { cmd.Execute() }
```

The only `init()` in the Barbacana codebase is at `internal/pipeline/handler.go:29`, which calls `caddy.RegisterModule(Handler{})`. Without the blank import of `internal/pipeline`, Caddy would not know about our middleware. The other blank imports (`crs`, `headers`, `request`, etc.) exist because the go linker strips unreferenced packages; these keeps them linked so their catalog contributions are present.

There is no global protection registry being populated at boot. Protections are instantiated *by their owner* inside `Handler.Provision()`, per route.

### 3.2 `cmd.Execute()` → `runServe()`

The CLI (`cmd/root.go`) is a straight `flag.NewFlagSet`. Four modes, mutually exclusive. The default is serve mode, which calls `runServe(configPath)` in `cmd/serve.go:28`.

`runServe` does exactly this, in order:

```
1.  slog.SetDefault(JSON handler to stdout)
2.  metrics.Init()                               (register Prom counters)
3.  cfg, _ := config.Load(path)                  (YAML → validated Config)
4.  resolved, _ := config.Resolve(cfg)           (per-route Resolved)
5.  warnDetectOnly(resolved, logger)             (loud warning per detect-only route)
6.  pipeline.RegisterConfigs(resolved)           (populate handler lookup map)
7.  caddyJSON, _ := config.Compile(cfg, resolved) (build JSON for Caddy)
8.  caddy.Load(caddyJSON, false)                 (Caddy starts listening)
9.  (optional) start health server on HealthPort
10. (optional) start metrics server on MetricsPort
11. waitForSignals(…)                             (block until SIGTERM/SIGHUP)
```

SIGHUP triggers `reload()` (`serve.go:174`), which re-runs steps 3, 4, 6, 7, 8 and bumps `metrics.ConfigReloadTotal`. Caddy's `caddy.Load` is idempotent — passing a new JSON swaps the config without dropping connections.

### 3.3 Config loading in detail

```
config.Load(path)                      in internal/config/load.go
  ├─ os.ReadFile(path)
  ├─ yaml.NewDecoder with KnownFields(true)   (strict decode)
  ├─ applyDefaults(&c)                in defaults.go
  └─ validate(&c)                     in validate.go

config.Resolve(cfg)                    in internal/config/resolve.go
  └─ for each route:
       ├─ merge globals into route-specific fields
       ├─ parse durations ("5s") and byte sizes ("1MB")
       ├─ compute RunJSONParser / RunXMLParser / RunMultipartParser / RunFormParser
       │    from content-type gating rules
       ├─ compute TLSMode (for csrf-secure-cookies)
       └─ compute AllowedOrigins (for csrf-origin-check)

pipeline.RegisterConfigs(resolved)     in internal/pipeline/store.go
  └─ store[routeID] = &resolved[i]     (module-level map)

config.Compile(cfg, resolved)          in internal/config/compile.go
  └─ build a map[string]any tree:
       admin: disabled
       logging: json to stdout
       apps.http.servers.proxy:
         listen: [":443",":80"] or [":PORT"] (depending on mode)
         routes: one per configured route
           each route's handler chain = [barbacana, reverse_proxy]
       → json.Marshal(root)
```

### 3.4 What Caddy provisions

`caddy.Load` makes Caddy instantiate each module in the chain. For `http.handlers.barbacana`, that means:

```
Caddy does: new(Handler) → Handler.Provision(ctx)
  Provision:
    res := GetConfig(h.RouteID)            (store.go)
    h.reqValidator = request.NewValidator(*res)
    h.originValidator = request.NewOriginValidator(*res)
    h.multipartVal = request.NewMultipartValidator(*res)
    h.resourceVal = request.NewResourceValidator(*res)
    h.corsHandler = headers.NewCORSHandler(res.CORS)     (may be nil if no CORS)
    h.headerInjector = headers.NewInjector(*res)
    h.headerStripper = headers.NewStripper(*res)
    h.cookieHardener = headers.NewCookieHardener(*res)
    h.protocolChecks = [DoubleEncode, PathNorm, UnicodeNorm,
                         Smuggling, CRLF, NullByte, MethodOverrideStrip]
    h.crsEngine = crs.NewEngine(*res)       (builds Coraza WAF with embedded rules)
    h.openAPIVal = openapi.NewValidator(...) if res.OpenAPI != nil
```

Once `Provision` returns, the handler is ready to serve. All protection instances are immutable after provisioning; `ServeHTTP` only reads them.

### 3.5 How CRS rules get into Coraza

`internal/protections/crs/embed.go` does:

```go
//go:embed rules/*.conf rules/*.data crs-setup.conf
var FS embed.FS
```

At build time the Go compiler reads every file under `rules/` plus `crs-setup.conf` and bakes them into the binary. At runtime, `NewEngine`:

1. Builds `SecAction ... setvar:'tx.paranoia_level=1'` directives (paranoia is hardcoded to 1).
2. Creates a Coraza `WAFConfig` with the embedded FS as `RootFS` (needed for `@pmFromFile` directives that reference `.data` files).
3. Loads `crs-setup.conf` as a string directive.
4. Lists all rule `.conf` files in lexicographic order.
5. For each file: loads the contents as a directive. If the file is `curated-rules.conf`, first emits `SecRuleRemoveById <ids>` to strip the CRS originals (Coraza rejects duplicate IDs at parse time), then loads the curated text.
6. Iteratively compiles the final WAF.

**Each route has its own Coraza engine** (`crs.NewEngine(*res)` is called once per route in `Provision`). There is no shared engine. This means rule removal on one route doesn't affect others; it also means the memory footprint scales with the number of routes.

Paranoia level is **hardcoded to 1** (`crs.go:33`); anomaly threshold is **hardcoded to 5** (`crs.go:34`). Neither is user-configurable. The curated PL2/PL3 rules in `curated/curated.go` are the only way to extend detection beyond PL1.

---

## 4. Request lifecycle

A single HTTP request enters `Handler.ServeHTTP(w, r, next)` and flows through **9 pipeline stages plus response modification**. The full trace lives in [`internal/pipeline/handler.go:158-385`](../../internal/pipeline/handler.go#L158-L385). Every stage follows the same pattern:

```
1. Call the protection's Evaluate / Validate
2. If Decision.Block:
     a. ac.addDecision(d)         always record for audit
     b. If mode == blocking:
           bump metrics, emit audit("blocked"), writeBlock, RETURN
     c. Else (detect-only):
           slog.Debug, continue to next stage
```

### The stages

| # | Stage | Reads | Owner | Block behaviour |
|---|---|---|---|---|
| — | Setup | — | `handler.go:164-169` | Attach `InspectionPath` to context, generate request ID, start timer |
| **1** | Request validation | method, URL length, header size/count, content-type | `request.Validator` | 403 via `writeDecision` (may be 405 / 413 / 415 / 400 depending on protection) |
| **1b** | CSRF origin check | `Origin` / `Referer` vs `AllowedOrigins` | `request.OriginValidator` | 403 |
| **2** | Protocol hardening (7 checks) | raw path, headers, method | `protocol.*` | 403 |
| **3-5** | Body analysis | `io.ReadAll(r.Body)` once, then reused | `resource`, `request` JSON/XML | 403 |
| **6** | Multipart upload checks | multipart body | `request.MultipartValidator` | 403 |
| **7** | CORS preflight | OPTIONS with Origin | `headers.CORSHandler` | Short-circuit with 200 + CORS headers (not a block) |
| **8** | OpenAPI validation | path, method, params, body vs spec | `openapi.Validator` | 400 / 422 (code comes from `openAPIStatusCode(protection)`) |
| **9** | CRS evaluation | normalized path (from context), headers, body | `crs.Engine` | 403; anomaly score recorded; detect-only returns non-blocking decisions collected for audit |
| — | Detect-only audit | — | `handler.go:356-364` | If any stage matched in detect-only mode, emit one `detected` audit entry here |
| **10** | Proxy | upstream request | Caddy's `reverse_proxy` | — |
| **11** | Response modification | response headers + body | `responseModifier` wrapper | See §5 |

### The `auditCollector`

Instantiated once per request (`handler.go:168`). Its job is to **accumulate matches across stages** and emit **one audit entry per request**, even if five different protections matched.

```go
ac.addDecision(d)          // CRS / request-side
ac.addNativeDecision(d, p) // native protections where the Decision doesn't
                           // carry a CWE; looked up from the Protection
```

At the end: `h.emitAudit(ctx, r, reqID, ac, action, code)` in `handler.go:400-431` constructs an `audit.Entry` with deduplicated protection names, accumulated rule IDs, CWE union, anomaly score, action, and response code.

### Body handling

The body is read **once** at the top of stage 3 (`handler.go:226`) into a `[]byte`. It is then restored to `r.Body` before each stage that needs it and before the proxy. This means:

- Small memory overhead per request (body is held for the whole pipeline).
- CRS and JSON/XML validators can re-read the body cheaply.
- The upstream receives the body bytes **unchanged** — the normalization stages write to `InspectionPath`, not to `r.URL` or `r.Body`.

### Normalization is for detection, not proxying

`InspectionPath` is a context-scoped mutable struct. Stages 2's `DoubleEncode`, `PathNorm`, `UnicodeNorm` write normalised forms into it. Stage 9 (CRS) reads from it. `r.URL` is **never mutated**, so Caddy's reverse proxy forwards the original path bytes. This is a deliberate design choice — the upstream must see exactly what the client sent.

---

## 5. Response path

After stage 9 passes, `handler.go:375-380` wraps the `http.ResponseWriter` in a `responseModifier` and delegates to `next.ServeHTTP(rw, r)` (Caddy's reverse proxy). The proxy calls upstream, reads the response headers, calls `rw.WriteHeader(code)`, then streams bytes via `rw.Write(p)`.

The `responseModifier` intercepts both. On `WriteHeader`:

1. Runs the **header strip** (remove `Server`, `X-Powered-By`, etc.).
2. Runs the **header inject** (add `Content-Security-Policy`, `X-Content-Type-Options`, etc. per preset).
3. Hardens **Set-Cookie** headers (`SameSite=Lax`, `Secure` if `TLSMode`).
4. Injects **CORS response headers** if the route is CORS-configured (including `Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers`).
5. Decides whether to **buffer the body for error masking**: yes if the status is 4xx/5xx AND the Content-Type is text AND `response-error-masking` is not disabled.

On `Write`, if buffering is active, the modifier accumulates bytes up to `response.MaxInspectBytes` (8KB), then:
- **If the window matches a framework error marker** (Go panic, Python traceback, Java stack trace, etc.): replace the body with a generic JSON envelope, emit an audit entry with the original body preview, increment metrics.
- **If not**: flush the buffered bytes and stream the rest of the body unchanged.

See §9 of `csrf-implementation-plan.md` (if still present) or the struct comment in `handler.go:420-470` for the full state machine.

---

## 6. Cross-cutting concerns

### Detect-only mode

Set per-route or globally via `mode: detect_only`. In detect-only mode:

- Every protection still runs.
- Blocking decisions are recorded but **not enforced** — the request continues down the pipeline and reaches the upstream.
- CRS is configured with `SecRuleEngine DetectionOnly`, so it returns decisions without writing 403.
- A single audit entry with `action: "detected"` is emitted at the end of the pipeline, listing every protection that would have blocked.
- A loud warning is logged **at startup** for every detect-only route (`cmd/serve.go:108-114`). This is intentional: operators must see they are running in observation mode.

### Audit emission

Exactly **one** audit entry per request, emitted by `Handler.emitAudit` (`handler.go:400-431`). Possible `action` values:

- `blocked` — a protection fired in blocking mode. Emitted inline at the blocking stage.
- `detected` — one or more protections would have blocked, but mode is detect-only. Emitted after stage 9.
- `masked` — a 4xx/5xx error page was masked. Emitted from `responseModifier.emitMaskAudit`.
- (no entry) — nothing matched; only the `requests_total{action="allowed"}` counter bumps.

### Metrics

All counters live in `internal/metrics/metrics.go` and are populated at call sites across the pipeline. The metrics server (Caddy-independent, plain `net/http`) is **opt-in** (`metrics_port: N`). If disabled, counters still increment — they just have no exporter.

### Three deployment modes

| Mode | Config | Listeners | TLS | Compile-time check |
|---|---|---|---|---|
| 1: single host | `host: x.com` at top level | `:443` + `:80` | Caddy auto-HTTPS | enforced in `validate.go` |
| 2: multi-host | `match.hosts: [a, b]` per route | `:443` + `:80` | Caddy auto-HTTPS per host | enforced |
| 3: plain HTTP | `port: 8080` at top level | `:8080` | Terminated upstream by LB | `automatic_https: disable` in Caddy JSON |

Modes are **mutually exclusive**. `validate.go` enforces this; `Resolve` infers `TLSMode` from modes 1 and 2 (modes 1+2 → TLS, mode 3 → plain).

---

## 7. Testing layout

| Scope | Where | Build tag | Run with |
|---|---|---|---|
| Unit | alongside code (`*_test.go`) | — | `go test ./...` |
| Pipeline unit | `internal/pipeline/responsemodifier_test.go` | — | `go test ./internal/pipeline/...` |
| Pipeline integration | `internal/pipeline/integration_test.go` | `integration` | `go test -tags integration ./internal/pipeline/...` |
| Blackbox | `tests/blackbox/` | — | `make test-blackbox` or `go test ./tests/blackbox/...` |

**Blackbox harness:**
- `tests/blackbox/upstream/main.go` — a fixture HTTP server with handlers for every scenario (echo, CSRF cookie setters, error pages, etc.).
- `tests/blackbox/runner_test.go` — starts the upstream, builds Barbacana, starts it against each scenario's `config.yaml`, runs the scenario's `*.hurl` files, tears down.
- `tests/blackbox/scenarios/<name>/` — one directory per scenario: `config.yaml` + `tests/*.hurl`.

Hurl is declarative HTTP — a `.hurl` file is a sequence of requests with assertions on status, headers, and body.

---

## 8. Where to look when…

| Symptom | First place to look |
|---|---|
| Config won't load | `internal/config/validate.go`, `load.go`, `defaults.go` |
| "Unknown field" error on startup | YAML has a typo; `KnownFields(true)` in `load.go:19` is strict |
| CRS not firing | `internal/protections/crs/crs.go` (engine construction), `mapping.go` (rule ID → protection name) |
| Wrong status code on block | `internal/protections/response.go` (writeBlock / writeDecision) and `openAPIStatusCode` for OpenAPI |
| Audit fields missing | `internal/audit/audit.go` (Entry struct) and `handler.go:400` (emitAudit) |
| Metric not visible | `internal/metrics/metrics.go` (definition) and check if `metrics_port: N` is set |
| Response headers not stripped / injected | `internal/protections/headers/headers.go` (Stripper / Injector) |
| Reload not picking up changes | `cmd/serve.go:174` (reload) — ensure SIGHUP is being sent |
| "No resolved config for route X" | `pipeline.RegisterConfigs` wasn't called, or route IDs don't match between Compile and Resolve |

---

## 9. Non-obvious things worth knowing

1. **`init()` is only used once**, in `internal/pipeline/handler.go:29`. This is deliberate — the project rule is "no init functions except for Caddy module registration". All other setup is explicit in `main.go` or `runServe`.

2. **Each route has its own Coraza engine.** Not a pool. Not a shared instance. Provisioning N routes builds N Coraza WAFs. This is fine for small route counts (≤50 or so) but means memory scales linearly. If you ever see "Barbacana OOMs with 500 routes" — this is where to look.

3. **The handler lookup trick.** Caddy instantiates modules by deserializing JSON. The JSON only carries `RouteID` (a string). At provision time, `Handler.Provision` reads the module-level `store` populated by `RegisterConfigs` to get back the full `Resolved`. This is why `RegisterConfigs` must be called **before** `caddy.Load`, and why reload calls it again before each `caddy.Load`.

4. **`normalizeOrigin` and `splitHostPort` are duplicated** between `internal/config/resolve.go` and `internal/protections/request/origin.go`. They must stay in sync. Candidate cleanup.

5. **The CRS engine loads rules in lexicographic order.** `curated-rules.conf` is named to sort between `REQUEST-944` and `REQUEST-949` so its phase-2 matches feed the anomaly aggregator. Renaming it will silently break detection.

6. **Content-type gating is evaluated at config resolution time**, then consulted per request. `RunJSONParser`, `RunXMLParser`, `RunMultipartParser`, `RunFormParser` are booleans on `Resolved`, not conditional handler-chain construction.

7. **`r.URL` is never mutated.** If you find code that writes to `r.URL`, it is a bug. Normalised paths live in `InspectionPath` on the request context.

8. **Caddy's `reverse_proxy` disables compression.** `DisableCompression=true` is set in `compile.go`, so Go's transport won't add `Accept-Encoding: gzip` to upstream requests. Client↔upstream content negotiation is pass-through. Implication: if response-body inspection is ever wired (e.g., `response-openapi`), the body may already be compressed with whatever encoding the client negotiated, and the inspection stage must own decompression.

9. **`metrics.Init()` always runs**, even if the metrics endpoint is disabled. Counters still increment; nothing exposes them. This keeps the hot path free of nil-checks.

10. **The CLI is `flag`-based, not Cobra.** Four mutually exclusive modes. The minimalism is intentional (operator-friendly single binary).

---

## 10. Glossary

| Term | Meaning |
|---|---|
| **Canonical name** | The stable identifier for a protection, e.g. `sql-injection-libinjection`, `csrf-origin-check`. Used in config `disable:`, audit `matched_protections`, metrics labels. Never a CRS rule ID. |
| **Sub-protection** | A CRS rule ID (int) that contributes to a canonical protection. Exposed in audit `matched_rules` but not in user-facing config. |
| **Paranoia level** | CRS concept: increasing PL activates more rules (and more false positives). Hardcoded to 1 in Barbacana. |
| **Anomaly score** | CRS concept: per-request accumulated score from matched rules; blocking threshold. Hardcoded to 5. |
| **Curated rule** | A PL2/PL3 CRS rule force-enabled on top of PL1 because it catches common attacks with acceptable false-positive rate. Lives in `crs/curated/`. |
| **Detect-only mode** | `mode: detect_only` — run protections, log matches, do not block. |
| **Resolved** | `config.Resolved` — a single route's fully materialised configuration (globals merged, durations parsed, mode flags computed). |
| **Pipeline stage** | One of the 9 steps in `Handler.ServeHTTP`. Order is fixed; stages cannot be reordered or skipped from config. |
| **InspectionPath** | Context-scoped mutable struct used by normalization stages to communicate with CRS without mutating `r.URL`. |
| **Mode 1 / 2 / 3** | Deployment topologies — single host / multi-host / plain-HTTP-behind-LB. Mutually exclusive, enforced in `validate.go`. |

---

## Maintenance notes

- When adding a new protection, update: (1) `catalog.go`, (2) `CWEMap`, (3) the owning package's `Register` helper, (4) a stage in `handler.go`, (5) `docs/design/protections.md`, (6) a blackbox scenario.
- When changing a pipeline stage order or adding a new stage: update **this doc's §4 table**.
- When adding a new deployment mode: update §3.5 and `validate.go`'s mutual-exclusion checks.
