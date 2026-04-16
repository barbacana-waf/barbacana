# Config schema

> **When to read**: changing the YAML schema, adding a config key, writing the parser, or documenting defaults. **Not needed for**: implementing a protection that has no user-facing knobs.

Barbacana is configured with a single YAML file (phase 1) or a main file plus `routes.d/*.yaml` (phase 2). Users never write Caddy config. The YAML compiles to Caddy JSON inside `internal/config`.

## Top-level structure

```yaml
version: v1alpha1              # schema version, required
listen: ":8080"                # optional, default ":8080"
metrics_listen: ":9090"        # optional, default ":9090" (served separately from proxy)
health_listen: ":8081"         # optional, default ":8081" (served separately from proxy)

global:
  # defaults applied to every route unless the route overrides

routes:
  - # one block per route
```

Go types (`internal/config/types.go`):

```go
type Config struct {
    Version       string  `yaml:"version"`
    Listen        string  `yaml:"listen"`
    MetricsListen string  `yaml:"metrics_listen"`
    HealthListen  string  `yaml:"health_listen"`
    Global        Global  `yaml:"global"`
    Routes        []Route `yaml:"routes"`
}
```

### Required vs optional

| Field | Required | Default | Validation |
|---|---|---|---|
| `version` | yes | — | must equal `v1alpha1` |
| `listen` | no | `":8080"` | valid `host:port` |
| `metrics_listen` | no | `":9090"` | valid `host:port`, must differ from `listen` |
| `health_listen` | no | `":8081"` | valid `host:port`, must differ from `listen` and `metrics_listen` |
| `global` | no | see below | — |
| `routes` | yes | — | at least one route |

## Global section

```yaml
global:
  detect_only: false                 # default: false (blocking per principle 1)
  disable: []                        # canonical protection names disabled everywhere

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
  inspection:
    sensitivity: 1                   # 1-4; higher = more rules = more false positives
    anomaly_threshold: 5             # cumulative score to trigger block
    evaluation_timeout: 50ms         # context deadline for rule evaluation
    max_inspect_size: 128KB          # bytes of non-file body evaluated by rules
    max_memory_buffer: 128KB         # spool to disk above this
    decompression_ratio_limit: 100   # reject if uncompressed/compressed > ratio
    json_depth: 20                   # max nesting depth for JSON bodies
    json_keys: 1000                  # max key count in JSON objects
    xml_depth: 20                    # max nesting depth for XML bodies (only if XML accepted)
    xml_entities: 100                # max entity expansions (only if XML accepted)
    debug_log_rule_ids: false        # emit internal rule IDs in debug log

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
    parameter_pollution: reject      # reject | first | last

  # ── What the response carries ─────────────────────────────
  response_headers:
    preset: moderate                 # strict | moderate | api-only | custom; default: moderate
    inject: {}                       # overrides per header (see protections.md)
    strip_extra: []                  # additional response headers to strip

  # ── API contract ──────────────────────────────────────────
  openapi:
    shadow_api_logging: true         # log undeclared paths even when openapi-path is disabled
```

Go types:

```go
type Global struct {
    DetectOnly      bool              `yaml:"detect_only"`
    Disable         []string          `yaml:"disable"`
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
| `global.detect_only` | bool | `false` | — |
| `global.disable` | []string | `[]` | every entry must resolve to a registered canonical name (category or sub-protection) |
| `global.accept.methods` | []string | standard 7 | each must be a valid HTTP method |
| `global.accept.content_types` | []string | `[]` (all) | each must be valid MIME type syntax |
| `global.accept.max_body_size` | byte size | `10MB` | `> 0`, `<= 1GB` |
| `global.accept.max_url_length` | int | `8192` | `>= 512`, `<= 65536` |
| `global.accept.max_header_size` | byte size | `16KB` | `>= 4KB`, `<= 1MB` |
| `global.accept.max_header_count` | int | `100` | `>= 10`, `<= 1000` |
| `global.accept.require_host_header` | bool | `true` | — |
| `global.inspection.sensitivity` | int | `1` | `>= 1`, `<= 4` |
| `global.inspection.anomaly_threshold` | int | `5` | `>= 1` |
| `global.inspection.evaluation_timeout` | duration | `50ms` | `>= 10ms` |
| `global.inspection.max_inspect_size` | byte size | `128KB` | `> 0`, `<= 10MB` |
| `global.inspection.max_memory_buffer` | byte size | `128KB` | `> 0`, `<= 10MB` |
| `global.inspection.decompression_ratio_limit` | int | `100` | `>= 1` |
| `global.inspection.json_depth` | int | `20` | `>= 1`, `<= 1000` |
| `global.inspection.json_keys` | int | `1000` | `>= 1`, `<= 100000` |
| `global.inspection.xml_depth` | int | `20` | `>= 1`, `<= 1000` |
| `global.inspection.xml_entities` | int | `100` | `>= 0`, `<= 10000` |
| `global.inspection.debug_log_rule_ids` | bool | `false` | — |
| `global.multipart.file_limit` | int | `10` | `>= 1` |
| `global.multipart.file_size` | byte size | `10MB` | `> 0` |
| `global.multipart.allowed_types` | []string | `[]` (all) | MIME type syntax |
| `global.multipart.double_extension` | bool | `true` | — |
| `global.protocol.slow_request_header_timeout` | duration | `10s` | `>= 1s` |
| `global.protocol.slow_request_min_rate_bps` | int | `1024` | `>= 0` |
| `global.protocol.http2_max_concurrent_streams` | int | `100` | `>= 1` |
| `global.protocol.http2_max_continuation_frames` | int | `32` | `>= 1` |
| `global.protocol.http2_max_decoded_header_bytes` | int | `65536` | `>= 4096` |
| `global.protocol.parameter_pollution` | enum | `reject` | one of `reject`, `first`, `last` |
| `global.response_headers.preset` | enum | `moderate` | one of `strict`, `moderate`, `api-only`, `custom` |
| `global.response_headers.inject` | map[string]string | `{}` | keys must be canonical header-* names from `protections.md` |
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

    detect_only: false               # override global; optional

    disable: []                      # canonical protection names disabled for this route only

    accept:                          # any subset; unspecified fields inherit from global
      content_types: [application/json]
      methods: [GET, POST]
      max_body_size: 50MB

    inspection: {}                   # any subset; unspecified fields inherit from global
    multipart: {}                    # any subset; gated by accept.content_types
    protocol: {}                     # limited per-route overrides (parameter_pollution only)

    response_headers:
      preset: strict                 # override global preset
      inject:
        header-csp: "default-src 'self'; script-src 'self' https://cdn.example.com"
      strip_extra: []

    openapi:
      spec: /etc/barbacana/specs/public-api.yaml  # path relative to config or absolute
      strict: true                   # if true, enforce; if false, detect-only regardless of route
      disable: []                    # openapi-* sub-protections to skip

    cors:                            # CORS is opt-in per route
      allow_origins: ["https://app.example.com"]
      allow_methods: [GET, POST]
      allow_headers: [Authorization, Content-Type]
      expose_headers: []
      allow_credentials: false
      max_age: 600
```

Go types:

```go
type Route struct {
    ID              string             `yaml:"id"`
    Match           *Match             `yaml:"match"`             // pointer: nil means match all
    Upstream        string             `yaml:"upstream"`
    UpstreamTimeout time.Duration      `yaml:"upstream_timeout"`
    Rewrite         *RewriteCfg        `yaml:"rewrite"`           // pointer: nil means no rewrite
    DetectOnly      *bool              `yaml:"detect_only"`       // pointer: nil means inherit
    Disable         []string           `yaml:"disable"`
    Accept          *AcceptCfg         `yaml:"accept"`            // pointer: nil means inherit
    Inspection      *InspectionCfg     `yaml:"inspection"`        // pointer: nil means inherit
    Multipart       *MultipartCfg      `yaml:"multipart"`         // pointer: nil means inherit
    Protocol        *ProtocolCfg       `yaml:"protocol"`          // pointer: nil means inherit
    ResponseHeaders *ResponseHeaderCfg `yaml:"response_headers"`  // pointer: nil means inherit
    OpenAPI         *OpenAPICfg        `yaml:"openapi"`
    CORS            *CORSCfg           `yaml:"cors"`
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
| `routes[].detect_only` | bool pointer | inherit from global | — |
| `routes[].disable` | []string | `[]` | canonical names (category or sub-protection) |
| `routes[].accept.*` | | inherit from global | see global field reference |
| `routes[].inspection.*` | | inherit from global | see global field reference |
| `routes[].multipart.*` | | inherit from global | see global field reference |
| `routes[].response_headers.preset` | enum | inherit | `strict`, `moderate`, `api-only`, `custom` |
| `routes[].response_headers.inject` | map | inherit (merged key-wise) | keys are canonical `header-*` names |
| `routes[].openapi.spec` | filepath | none (feature off) | file must exist and parse as OpenAPI 3.x |
| `routes[].openapi.strict` | bool | `true` | — |
| `routes[].openapi.disable` | []string | `[]` | `openapi-*` sub-protection names |
| `routes[].cors.allow_origins` | []string | — (CORS off) | origins or `*` (never `*` with credentials) |
| `routes[].cors.allow_methods` | []string | `[GET]` | valid HTTP methods |
| `routes[].cors.allow_headers` | []string | `[]` | valid header names |
| `routes[].cors.expose_headers` | []string | `[]` | valid header names |
| `routes[].cors.allow_credentials` | bool | `false` | if `true`, `allow_origins` must not contain `*` |
| `routes[].cors.max_age` | int (seconds) | `600` | `>= 0`, `<= 86400` |

## The `disable` list

Accepted values are the canonical names defined in `protections.md` — both category names and sub-protection names. Examples:

- `sql-injection` — disables the entire category (and every `sql-injection-*` sub-protection)
- `sql-injection-auth` — disables only that technique
- `header-csp` — skips CSP header injection for the route
- `strip-server` — keeps the upstream's `Server` header
- `openapi-body` — skips body-schema validation but keeps path/method/param validation

Validation rejects any entry that does not resolve to a registered canonical name. The error message lists the misspelled entry and a suggestion if one is close (Levenshtein ≤ 2).

`route.disable` is **additive** to `global.disable`. A protection disabled globally cannot be re-enabled on a specific route.

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

## Phase 2: `routes.d/*.yaml` loading

The main config file contains `global` and optionally `routes`. Every file in `routes.d/` contributes a `routes:` list. Semantics:

- Files load in lexicographic order. Ordering matters only for tie-breaking, but teams should not rely on it.
- Each file is parsed independently. A parse error in one file fails the entire reload.
- Route IDs must be unique across the main file plus all `routes.d/` files.
- `routes.d/` files may **not** redefine `global`. Any `global:` key in those files is a validation error.
- A team owning `routes.d/payments.yaml` can change their file without touching anyone else's.

Directory resolution: if the main config is at `/etc/barbacana/waf.yaml`, the default routes directory is `/etc/barbacana/routes.d/`. Overridable via `routes_dir:` in the main file.

## Example 1: minimal

```yaml
version: v1alpha1

routes:
  - upstream: http://app:8000
```

Everything else is defaulted. Every protection is active in blocking mode. Security headers injected with the `moderate` preset. All canonical strip headers removed. All content types accepted. All parsers active.

## Example 2: multi-route with per-team overrides

```yaml
version: v1alpha1

global:
  detect_only: false                 # switch whole instance to blocking mode

routes:
  - id: public-api
    match:
      hosts: [api.example.com]
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
      hosts: [admin.example.com]
    upstream: http://admin-backend:8000
    accept:
      content_types: [application/json]
    response_headers:
      preset: strict
    cors:
      allow_origins: ["https://admin.example.com"]
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
      - null-byte-injection          # legacy binary protocol uses \x00 markers
    detect_only: true                # keep logging but don't break the legacy app
```

## Example 3: extensive overrides

```yaml
version: v1alpha1
listen: ":443"

global:
  detect_only: false
  disable:
    - scanner-detection              # noisy across the whole fleet
  accept:
    methods: [GET, POST, PUT, DELETE]
    max_body_size: 50MB
  inspection:
    sensitivity: 2
    anomaly_threshold: 7
    json_depth: 15
  response_headers:
    preset: custom
    inject:
      header-csp: "default-src 'self' https://assets.example.com"
      header-hsts: "max-age=31536000"
    strip_extra:
      - X-Custom-Backend-Id

routes:
  - id: uploads
    match:
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
      - xss-stored                   # file bytes often look like HTML; validated server-side

  - id: graphql
    match:
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
      - header-csp                   # webhooks never render HTML
    response_headers:
      preset: api-only
```

## Validation behaviour

All validation runs during `barbacana validate <config>` and on startup. Errors are emitted as a single `multierror` with file path, YAML line number, and a specific message. Example:

```
waf.yaml:17: unknown protection "sql-injetcion" in route "public-api" disable list (did you mean "sql-injection"?)
waf.yaml:23: global.accept.max_body_size must be <= 1GB, got 2GB
waf.yaml:31: route "admin" cors.allow_credentials is true but allow_origins contains "*"
waf.yaml:45: route "uploads" accept.content_types includes "multipart/form-data" but multipart.file_limit is 0
```

The binary exits 1 with the error list. No config fragments are ever applied when validation fails.
