# Config schema

> **When to read**: changing the YAML schema, adding a config key, writing the parser, or documenting defaults. **Not needed for**: implementing a protection that has no user-facing knobs.

Barbacana is configured with a single YAML file (phase 1) or a main file plus `routes.d/*.yaml` (phase 2). Users never write Caddy config. The YAML compiles to Caddy JSON inside `internal/config`.

## Top-level structure

```yaml
version: v1alpha1              # schema version, required
host: "api.example.com"        # Mode 1: one or more hostnames, auto-TLS
                                # (also accepts a list: [a.example.com, b.example.com])
port: 8080                     # Mode 3: behind LB (mutually exclusive with host)
data_dir: "/data/barbacana"    # optional, default "/data/barbacana"
metrics_port: 9090             # optional, default 0 (disabled)
health_port: 8081              # optional, default 0 (disabled)
routes_dir: ""                 # optional, phase-2 routes.d directory (see below)

global:
  # defaults applied to every route unless the route overrides

tracing:
  # optional, off by default; see "Tracing" section below

audit_log:
  # optional, format selection for audit emission to stdout

routes:
  - # one block per route
```

Go types (`internal/config/types.go`):

```go
type Config struct {
    Version     string     `yaml:"version"`
    Hosts       HostList   `yaml:"host"`
    Port        int        `yaml:"port"`
    DataDir     string     `yaml:"data_dir"`
    MetricsPort int        `yaml:"metrics_port"`
    HealthPort  int        `yaml:"health_port"`
    RoutesDir   string     `yaml:"routes_dir"`
    Global      Global     `yaml:"global"`
    Tracing     TracingCfg `yaml:"tracing"`
    AuditLog    AuditCfg   `yaml:"audit_log"`
    Routes      []Route    `yaml:"routes"`
}
```

`HostList` (`[]string` with a custom YAML unmarshaler) is what makes `host`
accept either form: a scalar (`host: api.example.com`) decodes to a
one-element list, and a sequence (`host: [a.example.com, b.example.com]`)
decodes to the full list. An explicitly empty sequence (`host: []`) is a
validation error — silently falling back to plain-HTTP mode 3 would be a
security surprise. The wire key stays `host` singular; the Go field name
is internal.

### Required vs optional

| Field | Required | Default | Validation |
|---|---|---|---|
| `version` | yes | — | must equal `v1alpha1` |
| `host` | no | — | string or list of strings; one or more valid hostnames, each unique; mutually exclusive with `port` and with any route-level `match.hosts` |
| `port` | no | `8080` (only when no `host` and no route has `match.hosts`) | integer 1–65535; mutually exclusive with `host` and with any route-level `match.hosts` |
| `data_dir` | no | `/data/barbacana` | directory must be writable; stores TLS certificates and ACME state — mount as a persistent volume in containers |
| `metrics_port` | no | `0` (disabled) | integer 0–65535; `0` disables the listener; when non-zero, must differ from `port` and `health_port` |
| `health_port` | no | `0` (disabled) | integer 0–65535; `0` disables the listener; when non-zero, must differ from `port` and `metrics_port` |
| `routes_dir` | no | `""` (disabled) | directory containing `*.yaml` route files to load in addition to `routes:` — see "Phase 2: routes.d/*.yaml loading" below |
| `global` | no | see below | — |
| `tracing` | no | disabled | see "Tracing" section below |
| `audit_log` | no | `format: ocsf` | see "Audit log" section below |
| `routes` | yes | — | at least one route |

### Opt-in observability ports

`metrics_port` and `health_port` default to `0`, which means the corresponding listener is **never started**: no port is opened, no endpoint is served. Audit logs go to stdout regardless and are always on.

This opt-in is deliberate (principle 10). An open port is attack surface — `/metrics` exposes route IDs, protection names, and anomaly scores; `/healthz` advertises that a WAF is running. A hobbyist who forwards `:443` on their home router should not unknowingly expose two additional operational-data ports. Production deployments (Helm chart, docker-compose examples) set both ports explicitly.

When a port is `0`, the server emits an info log at startup so operators know why the endpoint is missing:

```
health endpoint disabled — set health_port to enable /healthz and /readyz
metrics endpoint disabled — set metrics_port to enable /metrics
```

### Deployment modes

Exactly one of three mutually exclusive modes is selected by the combination of `host`, `port`, and route-level `match.hosts`.

**Mode 1 — Single host, auto-TLS.** Set top-level `host` to one hostname, or to a list of hostnames. Caddy serves HTTPS on `:443`, redirects HTTP on `:80`, and provisions a Let's Encrypt certificate automatically — one certificate per listed hostname. Every route serves every listed hostname (there is no per-route hostname split in this mode — that's what Mode 2 is for). Routes must not set `match.hosts`, and `port` must not be set.

```yaml
version: v1alpha1
host: api.example.com
routes:
  - upstream: http://api:8000
```

A list form serves multiple hostnames from the same set of routes:

```yaml
version: v1alpha1
host: [example.com, example.io]
routes:
  - upstream: http://api:8000
```

**Mode 2 — Multi-host, auto-TLS.** Omit `host`. Every route supplies `match.hosts`. Caddy provisions one certificate per hostname, serves HTTPS on `:443`, and redirects HTTP on `:80`. If any route has `match.hosts`, **every** route must have `match.hosts` (routes without `match.hosts` would become ambiguous catch-alls). `port` must not be set. This is the mode to reach for when different hostnames should route to different upstreams — top-level `host` (Mode 1) shares its hostname list across every route, while `match.hosts` splits routes across hostnames.

```yaml
version: v1alpha1
routes:
  - match:
      hosts: [api.example.com]
    upstream: http://api:8000
  - match:
      hosts: [admin.example.com]
    upstream: http://admin:8000
```

**Mode 3 — Behind a load balancer, plain HTTP.** Set `port` (or leave both `host` and `port` unset to default `port` to `8080`). Caddy serves plain HTTP on the configured port; there is no TLS and no certificate provisioning. `host` must not be set and no route may use `match.hosts`.

```yaml
version: v1alpha1
port: 8080
routes:
  - upstream: http://api:8000
```

### Validation errors (modes)

Every mode constraint is a hard error, not a warning. Messages name the specific conflicting fields and, where applicable, the offending route:

```
waf.yaml:2: "host" and "port" are mutually exclusive — use "host" for auto-TLS or "port" for plain HTTP behind a load balancer

waf.yaml:3: "host" and "match.hosts" on route "api" are mutually exclusive — "host" takes one or more hostnames shared by all routes, while "match.hosts" splits routes across hostnames; use one or the other

waf.yaml:5: "port" and "match.hosts" on route "api" are mutually exclusive — "match.hosts" requires auto-TLS; remove "port" or remove "match.hosts"

waf.yaml:14: route "uploads" has no match.hosts but route "api" does — add match.hosts to route "uploads", repeating the host for multiple routes is fine, or add "host" at the top level if all routes share the same hostname(s)
```

Errors specific to the top-level `host` list itself:

```
waf.yaml:2: host: must contain at least one hostname — remove "host" entirely (or use "port") for plain HTTP

waf.yaml:2: host: "not a host!" is not a valid hostname

waf.yaml:2: host: "example.com" is listed more than once

waf.yaml:2: host: entries must not be empty strings
```

## Global section

Global section defines defaults applied to every route unless the route overrides. This distinguishes between root level configurations (e.g., `host`, `port`) that apply to the server as a whole and route-level configurations (e.g., `accept`, `mode`) that can be overridden per route.

```yaml
global:
  mode: blocking                     # "blocking" (default) or "detect_only"; see principle 11
  disable: []                        # catalog IDs (L1, L2, or leaf) disabled everywhere
  enable: []                         # catalog IDs to opt into off-by-default leaves

  # ── What the route accepts ────────────────────────────────
  accept:
    methods: [GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS]
    content_types: []                # empty = all; values are MIME types; gates which parsers run
    max_body_size: 10MB
    max_url_length: 8192
    max_header_size: 16KB
    max_header_count: 100
    require_host_header: true

  # ── How the WAF inspects ──────────────────────────────────
  # Paranoia level and anomaly threshold are not user-configurable —
  # see docs/design/architecture.md and docs/design/security-evaluation.md.
  inspection:
    evaluation_timeout: 50ms         # context deadline for rule evaluation
    max_inspect_size: 128KB          # bytes of non-file body evaluated by rules
    max_memory_buffer: 128KB         # spool to disk above this
    decompression_ratio_limit: 100   # reject if uncompressed/compressed > ratio
    json_depth: 20                   # max nesting depth for JSON bodies
    json_keys: 1000                  # max key count in JSON objects
    xml_depth: 20                    # max nesting depth for XML bodies (only if XML accepted)
    xml_entities: 100                # max entity expansions (only if XML accepted)
  # ── File uploads ──────────────────────────────────────────
  # Only active if content_types includes multipart/form-data
  multipart:
    file_limit: 10
    file_size: 10MB
    allowed_types: []                # empty = all; values are MIME types
    double_extension: true

  # ── Wire-level behavior ──────────────────────────────────
  protocol:
    slow_request_header_timeout: 10s
    slow_request_min_rate_bps: 1024
    http2_max_concurrent_streams: 100
    http2_max_continuation_frames: 32
    http2_max_decoded_header_bytes: 65536

  # ── What the response carries ─────────────────────────────
  response_headers:
    inject: {}                       # value overrides keyed by `response-headers-add-*` leaf ID
    strip_extra: []                  # additional response headers to strip

  # ── API contract ──────────────────────────────────────────
  openapi:
    shadow_api_logging: true         # log undeclared paths even when openapi-path is disabled
```

Go types:

```go
type Global struct {
    Mode            string            `yaml:"mode"`
    Disable         []string          `yaml:"disable"`
    Enable          []string          `yaml:"enable"`
    Accept          AcceptCfg         `yaml:"accept"`
    Inspection      InspectionCfg     `yaml:"inspection"`
    Multipart       MultipartCfg      `yaml:"multipart"`
    Protocol        ProtocolCfg       `yaml:"protocol"`
    ResponseHeaders ResponseHeaderCfg `yaml:"response_headers"`
    OpenAPI         OpenAPIGlobal     `yaml:"openapi"`
}
```

### Global field reference

| Path | Type | Default | Validation |
|---|---|---|---|
| `global.mode` | enum | `blocking` | one of `blocking`, `detect_only` |
| `global.disable` | []string | `[]` | every entry must resolve to a catalog ID (L1, L2, or leaf) |
| `global.enable` | []string | `[]` | every entry must resolve to a catalog ID (L1, L2, or leaf); cannot literally collide with the same-level `disable` list |
| `global.accept.methods` | []string | standard 7 | each must be a valid HTTP method |
| `global.accept.content_types` | []string | `[]` (all) | each must be valid MIME type syntax |
| `global.accept.max_body_size` | byte size | `10MB` | `> 0`, `<= 1GB` |
| `global.accept.max_url_length` | int | `8192` | `>= 512`, `<= 65536` |
| `global.accept.max_header_size` | byte size | `16KB` | `>= 4KB`, `<= 1MB` |
| `global.accept.max_header_count` | int | `100` | `>= 10`, `<= 1000` |
| `global.accept.require_host_header` | bool | `true` | — |
| `global.inspection.evaluation_timeout` | duration | `50ms` | `>= 10ms` |
| `global.inspection.max_inspect_size` | byte size | `128KB` | `> 0`, `<= 10MB` |
| `global.inspection.max_memory_buffer` | byte size | `128KB` | `> 0`, `<= 10MB` |
| `global.inspection.decompression_ratio_limit` | int | `100` | `>= 1` |
| `global.inspection.json_depth` | int | `20` | `>= 1`, `<= 1000` |
| `global.inspection.json_keys` | int | `1000` | `>= 1`, `<= 100000` |
| `global.inspection.xml_depth` | int | `20` | `>= 1`, `<= 1000` |
| `global.inspection.xml_entities` | int | `100` | `>= 0`, `<= 10000` |
| `global.multipart.file_limit` | int | `10` | `>= 1` |
| `global.multipart.file_size` | byte size | `10MB` | `> 0` |
| `global.multipart.allowed_types` | []string | `[]` (all) | MIME type syntax |
| `global.multipart.double_extension` | bool | `true` | — |
| `global.protocol.slow_request_header_timeout` | duration | `10s` | `>= 1s` |
| `global.protocol.slow_request_min_rate_bps` | int | `1024` | `>= 0` |
| `global.protocol.http2_max_concurrent_streams` | int | `100` | `>= 1` |
| `global.protocol.http2_max_continuation_frames` | int | `32` | `>= 1` |
| `global.protocol.http2_max_decoded_header_bytes` | int | `65536` | `>= 4096` |
| `global.response_headers.inject` | map[string]string | `{}` | keys must be `response-headers-add-*` leaf IDs from the catalog |
| `global.response_headers.strip_extra` | []string | `[]` | valid HTTP header names |
| `global.openapi.shadow_api_logging` | bool | `true` | — |

**Byte sizes** accept suffixes: `B`, `KB`, `MB`, `GB` (powers of 1024). Bare integers are bytes.
**Durations** use Go's `time.ParseDuration` syntax: `500ms`, `10s`, `2m`, etc.

## Route section

```yaml
routes:
  - id: public-api                   # optional, used as metric label; default: generated from match
    match:                           # optional; if omitted, matches all requests
      hosts: [api.example.com]       # optional; default: match any host
      paths: ["/v1/*"]               # optional; default: match any path
    upstream: http://backend:8000    # required
    upstream_timeout: 30s            # optional, default: 30s

    rewrite:                         # optional
      strip_prefix: /v1              # remove prefix before forwarding
      add_prefix: /api               # prepend after stripping
      path: /exact/path              # full replacement (overrides strip/add)

    mode: blocking                   # override global; optional ("blocking" or "detect_only")

    disable: []                      # catalog IDs disabled for this route only
    enable: []                       # catalog IDs to opt into off-by-default leaves for this route only

    accept:                          # any subset; unspecified fields inherit from global
      content_types: [application/json]
      methods: [GET, POST]
      max_body_size: 50MB

    inspection: {}                   # any subset; unspecified fields inherit from global
    multipart: {}                    # any subset; gated by accept.content_types
    protocol: {}                     # currently no per-route overrides; inherited from global

    response_headers:
      inject:
        response-headers-add-csp: "default-src 'self'; script-src 'self' https://cdn.example.com"
      strip_extra: []

    openapi:
      spec: /etc/barbacana/specs/public-api.yaml  # path relative to config or absolute
      strict: true                   # if true, enforce; if false, detect_only regardless of route
      disable: []                    # openapi-* sub-protections to skip

    cors:                            # CORS is opt-in per route
      allow_origins: ["https://app.example.com"]
      allow_methods: [GET, POST]
      allow_headers: [Authorization, Content-Type]
      expose_headers: []
      allow_credentials: false
      max_age: 600

    error_response:                  # optional custom block response body
      body: |
        {"error":"blocked","request_id":"{{.RequestID}}","ts":"{{.Timestamp}}"}
```

Go types:

```go
type Route struct {
    ID              string             `yaml:"id"`
    Match           *Match             `yaml:"match"`             // pointer: nil means match all
    Upstream        string             `yaml:"upstream"`
    UpstreamTimeout time.Duration      `yaml:"upstream_timeout"`
    Rewrite         *RewriteCfg        `yaml:"rewrite"`           // pointer: nil means no rewrite
    Mode            *string            `yaml:"mode"`              // pointer: nil means inherit
    Disable         []string           `yaml:"disable"`
    Enable          []string           `yaml:"enable"`
    Accept          *AcceptCfg         `yaml:"accept"`            // pointer: nil means inherit
    Inspection      *InspectionCfg     `yaml:"inspection"`        // pointer: nil means inherit
    Multipart       *MultipartCfg      `yaml:"multipart"`         // pointer: nil means inherit
    Protocol        *ProtocolCfg       `yaml:"protocol"`          // pointer: nil means inherit
    ResponseHeaders *ResponseHeaderCfg `yaml:"response_headers"`  // pointer: nil means inherit
    OpenAPI         *OpenAPIRoute      `yaml:"openapi"`
    CORS            *CORSCfg           `yaml:"cors"`
    ErrorResponse   *ErrorResponseCfg  `yaml:"error_response"`
}

type ErrorResponseCfg struct {
    Body string `yaml:"body"`          // text/template; only {{.RequestID}} and {{.Timestamp}}
}

type Match struct {
    Hosts []string `yaml:"hosts"`
    Paths []string `yaml:"paths"`
}

type RewriteCfg struct {
    StripPrefix string `yaml:"strip_prefix"`
    AddPrefix   string `yaml:"add_prefix"`
    Path        string `yaml:"path"`
}
```

### Route field reference

| Path | Type | Default | Validation |
|---|---|---|---|
| `routes[].id` | string | generated from first path | `^[a-z0-9][a-z0-9-]*$`, unique per config |
| `routes[].match` | object | match all | if present, at least one of `hosts` or `paths` must be set |
| `routes[].match.hosts` | []string | `[]` (any) | each a valid hostname or wildcard (`*.example.com`) |
| `routes[].match.paths` | []string | `[]` (any) | each starts with `/` |
| `routes[].upstream` | URL string | — (required) | valid `http://` or `https://` URL |
| `routes[].upstream_timeout` | duration | `30s` | `>= 1s`, `<= 600s` |
| `routes[].rewrite.strip_prefix` | string | none | must start with `/` |
| `routes[].rewrite.add_prefix` | string | none | must start with `/` |
| `routes[].rewrite.path` | string | none | must start with `/`; if set, `strip_prefix` and `add_prefix` are ignored |
| `routes[].mode` | string pointer | inherit from global | one of `blocking`, `detect_only` |
| `routes[].disable` | []string | `[]` | catalog IDs (L1, L2, or leaf) |
| `routes[].enable` | []string | `[]` | catalog IDs; cannot literally collide with the same route's `disable` |
| `routes[].accept.*` | | inherit from global | see global field reference |
| `routes[].inspection.*` | | inherit from global | see global field reference |
| `routes[].multipart.*` | | inherit from global | see global field reference |
| `routes[].response_headers.inject` | map | inherit (merged key-wise) | keys are `response-headers-add-*` leaf IDs |
| `routes[].openapi.spec` | filepath | none (feature off) | file must exist and parse as OpenAPI 3.x |
| `routes[].openapi.strict` | bool | `true` | — |
| `routes[].openapi.disable` | []string | `[]` | `openapi-*` sub-protection names |
| `routes[].cors.allow_origins` | []string | — (CORS off) | origins or `*` (never `*` with credentials) |
| `routes[].cors.allow_methods` | []string | `[GET]` | valid HTTP methods |
| `routes[].cors.allow_headers` | []string | `[]` | valid header names |
| `routes[].cors.expose_headers` | []string | `[]` | valid header names |
| `routes[].cors.allow_credentials` | bool | `false` | if `true`, `allow_origins` must not contain `*` |
| `routes[].cors.max_age` | int (seconds) | `600` | `>= 0`, `<= 86400` |
| `routes[].error_response.body` | string | — (use default JSON body) | Go `text/template`; only `{{.RequestID}}` and `{{.Timestamp}}` are exposed. Compiled at config-load time — a parse error fails validation. Status code and headers are not configurable; see `architecture.md` §"Error responses" |

## The `disable` and `enable` lists

Accepted values are catalog IDs at any level: an L1 family (`sql`), an L2
bucket (`sql-injection`), or a leaf (`sql-injection-union-select`). Run
`barbacana --catalog` for the full reference. Examples:

- `disable: [sql]` — disables every leaf under the `sql` family
- `disable: [sql-injection]` — disables every leaf under the L2 bucket
- `disable: [sql-injection-login-bypass]` — disables only that leaf
- `enable: [response-headers-add-csp]` — turns on a specific off-by-default leaf
- `enable: [http-compliance-character-encoding]` — turns on every off-by-default
  leaf in the bucket (e.g. `http-compliance-double-url-encoding`)
- `disable: [response-headers-add]` — skips every injected security header

Validation rejects any entry that does not resolve. The error message lists
the misspelled entry and a suggestion if one is close (Levenshtein ≤ 2).
The same literal ID may not appear in both the `disable` and `enable` list
of the *same* layer (a route's `disable` listing X and the global `enable`
listing X is fine — that's the precedence model resolving correctly; X in
both `disable` and `enable` of the same route is a config error).

### Precedence: more-specific wins

A leaf's effective state is computed by walking the four lists for that
leaf's catalog path: `global.disable`, `global.enable`, `route.disable`,
`route.enable`. The rule is **more-specific wins; route beats global on
ties**:

1. The leaf-level entry beats any L2 or L1 entry that mentions the leaf's
   path (a route's `disable: [sql-injection-union-select]` overrides the
   global `enable: [sql-injection]`).
2. The L2-level entry beats any L1 entry covering the same path.
3. At the same specificity, a route entry beats a global entry.
4. If two layers tie on specificity, route wins.

Practical consequence: the L2 enable pattern (`enable: [sql-injection]`)
turns on every off-by-default leaf in the bucket but does **not** override
a more-specific `disable: [sql-injection-comments-in-json]` if one exists.

Default-state semantics: an `enable:` entry that names a leaf already on by
default, or a `disable:` entry that names a leaf already off by default, is
a no-op rather than an error. This keeps idempotent config generation safe.

### Default-off leaves to know about

Eight leaves shipped on prior to v0.4.0 and now ship off, because each one
has no safe default value or is high-FP:

- `response-headers-add-csp`, `response-headers-add-coop`,
  `response-headers-add-coep`, `response-headers-add-corp`,
  `response-headers-add-permissions-policy`,
  `response-headers-add-cache-control` — injected values can break apps;
  operator must declare intent.
- `http-compliance-accept-header`, `http-compliance-user-agent-header` —
  detection-only protocol checks that fired on legitimate-but-unusual
  clients; opt in if relied on as a security signal.

To preserve pre-v0.4.0 behavior, add the relevant IDs to `global.enable:`
or to the route that needs them. `barbacana --catalog-leaf <id>` prints the
leaf's `WhyEnable` text describing when each is appropriate.

### CSP value flow

The `response-headers-add-csp` leaf is plain on/off. The actual policy
string lives in `response_headers.inject` keyed by the leaf ID:

```yaml
enable:
  - response-headers-add-csp
response_headers:
  inject:
    response-headers-add-csp: "default-src 'self'"
```

Same pattern for `response-headers-add-permissions-policy`,
`response-headers-add-cache-control`, etc. — the leaf gates the header,
the inject map carries the value.

## Content-type gating

`accept.content_types` controls which parsers run for a route:

- If empty (default), all parsers are active.
- If set to `[application/json]`, only the JSON parser runs. XML parsing, multipart parsing, and form-urlencoded parsing are all skipped. XML-related inspection knobs (`xml_depth`, `xml_entities`) have no effect.
- A POST with a Content-Type not in the accept list is rejected with `415 Unsupported Media Type`.
- The `multipart` section is only active if `content_types` includes `multipart/form-data`.

This is both a security control (rejecting unexpected content types) and a performance optimization (skipping unnecessary parsers).

## Route matching precedence

When a request arrives:

1. If a route has no `match` block, it matches everything.
2. Filter routes whose `match.hosts` matches the request `Host` header. Empty `hosts` matches any host.
3. Among survivors, select the route whose `match.paths` has the most specific match.
4. Specificity: literal path > longer prefix > shorter prefix. `/v1/users/profile` beats `/v1/users/*` beats `/v1/*` beats `/*`.
5. Ties are resolved by source order (earlier wins). The compiler warns when ties exist.
6. If no route matches, the request is rejected with `404 Not Found`. There is no default route — explicit routing is part of principle 3 (path-first).

Host matching:
- Exact: `api.example.com`
- Suffix wildcard: `*.example.com` matches `foo.example.com` but not `example.com`
- Case-insensitive

Path matching uses glob syntax: `*` matches a single segment, `**` matches any number of segments. Trailing slashes are normalized.

## Tracing

Distributed tracing is opt-in. With the block absent or `enabled: false`, no exporter is created and the OTel global TracerProvider stays as the no-op — Barbacana running without an OTel collector configured makes zero network calls for tracing.

```yaml
tracing:
  enabled: false           # default; flip to true to ship traces
  protocol: grpc           # grpc (default) or http (== http/protobuf)
  endpoint: ""             # falls back to OTEL_EXPORTER_OTLP_ENDPOINT
  insecure: true           # default; set false to require TLS to the collector
  headers:                 # optional, e.g. authentication
    authorization: "Api-Token <secret>"
  timeout: ""              # optional, e.g. 5s; >= 100ms when set

  service:
    name: ""               # falls back to OTEL_SERVICE_NAME, then "barbacana"
    namespace: ""
    version: ""            # falls back to the build's internal/version
```

| Field | Default | Validation |
|---|---|---|
| `tracing.enabled` | `false` | bool |
| `tracing.protocol` | `grpc` | one of `grpc`, `http`, `http/protobuf` |
| `tracing.endpoint` | `""` (use env) | non-empty wins over `OTEL_EXPORTER_OTLP_ENDPOINT`; empty defers to env |
| `tracing.insecure` | `true` | bool |
| `tracing.headers` | none | string→string |
| `tracing.timeout` | none | duration string parseable by `time.ParseDuration`; >= 100ms |
| `tracing.service.name` | from env or `"barbacana"` | string |
| `tracing.service.namespace` | none | string |
| `tracing.service.version` | from build | string |

Standard OTel env vars (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`, ...) are honored as fallback when the corresponding YAML field is empty. YAML wins when both are set. Sampling tuning happens via env (`OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG`); the YAML schema does not duplicate sampler config.

## Audit log

Stdout emission of audit events is **unconditional** — there is no off switch. The block below selects the wire schema only.

```yaml
audit_log:
  format: ocsf            # default; or "ecs"
```

| Field | Default | Valid values |
|---|---|---|
| `audit_log.format` | `ocsf` | `ocsf`, `ecs` |

Format choice is process-wide. Rotating between OCSF and ECS requires a config reload; one running process never mixes the two formats.

**Breaking change in this release**: the previous flat audit log shape (`matched_protections`, `matched_rules`, `cwe`) has been removed from the document root. Operators upgrading must set `audit_log.format` and translate dashboards/detection rules to either OCSF or ECS field names. The original field names are preserved verbatim under the vendor `barbacana.*` namespace on both formats (`barbacana.matched_protections`, `barbacana.matched_rules`, `barbacana.cwe`) for jq/grep workflows; there is no `legacy` format value. See `docs/design/architecture.md` audit-log section for full field examples.

## Phase 2: `routes.d/*.yaml` loading

The main config file contains `global` and optionally `routes`. Every file in `routes.d/` contributes a `routes:` list. Semantics:

- Files load in lexicographic order. Ordering matters only for tie-breaking, but teams should not rely on it.
- Each file is parsed independently. A parse error in one file fails the entire reload.
- Route IDs must be unique across the main file plus all `routes.d/` files.
- `routes.d/` files may **not** redefine `global`. Any `global:` key in those files is a validation error.
- A team owning `routes.d/payments.yaml` can change their file without touching anyone else's.

Directory resolution: if the main config is at `/etc/barbacana/waf.yaml`, the default routes directory is `/etc/barbacana/routes.d/`. Overridable via `routes_dir:` in the main file.

## Example 1: minimal (Mode 3, plain HTTP behind a load balancer)

```yaml
version: v1alpha1

routes:
  - upstream: http://app:8000
```

Everything else is defaulted. `port` defaults to `8080` because no `host` is set and no route uses `match.hosts`. `metrics_port` and `health_port` stay at `0` (disabled) — audit logs on stdout are the only observability. Every protection is active in blocking mode. Default security headers injected. All canonical strip headers removed. All content types accepted. All parsers active.

## Example 2: multi-route with per-team overrides (Mode 1, single host auto-TLS)

```yaml
version: v1alpha1
host: example.com                    # single host, auto-TLS on :443 and :80→:443 redirect
data_dir: /var/lib/barbacana         # persistent TLS/ACME state
metrics_port: 9090                   # opt-in: expose Prometheus /metrics
health_port: 8081                    # opt-in: expose /healthz and /readyz

global:
  mode: blocking                     # switch whole instance to blocking mode

routes:
  - id: public-api
    match:
      paths: ["/v1/*"]
    upstream: http://api-backend:8000
    accept:
      content_types: [application/json]
      methods: [GET, POST, PUT, DELETE]
    rewrite:
      strip_prefix: /v1
    openapi:
      spec: /etc/barbacana/specs/public-api.yaml

  - id: admin
    match:
      paths: ["/admin/*"]
    upstream: http://admin-backend:8000
    accept:
      content_types: [application/json]
    response_headers:
      inject:
        response-headers-add-csp: "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        response-headers-add-coep: "require-corp"
    cors:
      allow_origins: ["https://example.com"]
      allow_credentials: true

  - id: legacy-php
    match:
      paths: ["/legacy/*"]
    upstream: http://legacy:80
    rewrite:
      strip_prefix: /legacy
      add_prefix: /app
    disable:
      - php-injection                # legacy app trips on its own PHP-ish params
      - http-compliance-null-bytes   # legacy binary protocol uses \x00 markers
    mode: detect_only                # keep logging but don't break the legacy app
```

`host` also accepts a list to serve several hostnames from this same set
of routes, each getting its own certificate:

```yaml
host: [example.com, example.io]      # one cert each; every route below serves both
```

## Example 3: extensive overrides (Mode 2, multi-host auto-TLS)

```yaml
version: v1alpha1
data_dir: /var/lib/barbacana         # persistent TLS/ACME state
metrics_port: 9090                   # opt-in: expose Prometheus /metrics
health_port: 8081                    # opt-in: expose /healthz and /readyz

global:
  mode: blocking
  disable:
    - scanner-detection              # noisy across the whole fleet
  accept:
    methods: [GET, POST, PUT, DELETE]
    max_body_size: 50MB
  inspection:
    json_depth: 15
  enable:
    - response-headers-add-csp                           # opt into the off-by-default CSP leaf
  response_headers:
    inject:
      response-headers-add-csp: "default-src 'self' https://assets.example.com"
      response-headers-add-hsts: "max-age=31536000"
    strip_extra:
      - X-Custom-Backend-Id

routes:
  - id: uploads
    match:
      hosts: [uploads.example.com]
      paths: ["/upload/*"]
    upstream: http://uploads:8000
    accept:
      content_types: [multipart/form-data]
      max_body_size: 500MB
    multipart:
      file_limit: 50
      file_size: 100MB
      allowed_types:
        - image/png
        - image/jpeg
        - application/pdf
      double_extension: true
    inspection:
      max_inspect_size: 256KB        # larger payloads need more inspection buffer
    disable:
      - cross-site-scripting         # file bytes often look like HTML; validated server-side

  - id: graphql
    match:
      hosts: [api.example.com]
      paths: ["/graphql"]
    upstream: http://gql:4000
    accept:
      content_types: [application/json]
    inspection:
      json_depth: 40                 # GraphQL queries can be deep
      json_keys: 5000

  - id: webhooks
    match:
      hosts: [hooks.example.com]
    upstream: http://hook-router:8000
    accept:
      content_types: [application/json, application/x-www-form-urlencoded]
    disable:
      - response-headers-add-csp     # webhooks never render HTML
    response_headers:
      inject:
        response-headers-add-cache-control: "no-store"
```

## Validation behaviour

All validation runs during `barbacana --config <path> --validate` and on startup. Errors are emitted as a single `multierror` with file path, YAML line number, and a specific message. Example:

```
waf.yaml:17: unknown protection "sql-injetcion" in route "public-api" disable list (did you mean "sql-injection"?)
waf.yaml:19: protection "response-headers-add-csp" appears in both disable and enable on route "public-api"
waf.yaml:23: global.accept.max_body_size must be <= 1GB, got 2GB
waf.yaml:31: route "admin" cors.allow_credentials is true but allow_origins contains "*"
waf.yaml:45: route "uploads" accept.content_types includes "multipart/form-data" but multipart.file_limit is 0
```

The binary exits 1 with the error list. No config fragments are ever applied when validation fails.
