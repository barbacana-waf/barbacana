# Config schema

> **When to read**: changing the YAML schema, adding a config key, writing the parser, or documenting defaults. **Not needed for**: implementing a protection that has no user-facing knobs.

Barbacana is configured with a single YAML file (phase 1) or a main file plus `routes.d/*.yaml` (phase 2). Users never write Caddy config. The YAML compiles to Caddy JSON inside `internal/config`.

## Top-level structure

```yaml
version: 1                 # schema version, required, only "1" is valid for now
listen: ":8080"            # optional, default ":8080"
metrics_listen: ":9090"    # optional, default ":9090" (served separately from proxy)
health_listen: ":8081"     # optional, default ":8081" (served separately from proxy)

global:
  # defaults applied to every route unless the route overrides

routes:
  - # one block per route
```

Go types (`internal/config/types.go`):

```go
type Config struct {
    Version       int     `yaml:"version"`
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
| `version` | yes | — | must equal `1` |
| `listen` | no | `":8080"` | valid `host:port` |
| `metrics_listen` | no | `":9090"` | valid `host:port`, must differ from `listen` |
| `health_listen` | no | `":8081"` | valid `host:port`, must differ from `listen` and `metrics_listen` |
| `global` | no | see below | — |
| `routes` | yes | — | at least one route |

## Global section

```yaml
global:
  detect_only: true                  # default: true (detect-only per principle 11)

  disable: []                        # canonical protection names disabled everywhere

  headers:
    preset: moderate                 # strict | moderate | api-only | custom; default: moderate
    inject: {}                       # overrides per header (see below)
    strip_extra: []                  # additional response headers to strip

  request_limits:
    max_body_size: 10MB
    max_url_length: 8192
    max_header_size: 16KB
    max_header_count: 100
    allowed_methods: [GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS]
    require_host_header: true
    require_content_type: true

  body_limits:
    json_depth: 20
    json_keys: 1000
    xml_depth: 20
    xml_entities: 100

  multipart:
    file_limit: 10
    file_size: 10MB
    allowed_types: []                # empty = all; values are MIME types
    double_extension: true

  protocol:
    slow_request_header_timeout: 10s
    slow_request_min_rate_bps: 1024
    http2_max_concurrent_streams: 100
    http2_max_continuation_frames: 32
    http2_max_decoded_header_bytes: 65536
    parameter_pollution: reject      # reject | first | last

  crs:
    paranoia_level: 1                # 1-4; default 1
    anomaly_threshold: 5             # score at or above which a request blocks in blocking mode
    debug_log_rule_ids: false        # if true, rule IDs appear in debug log

  openapi:
    shadow_api_logging: true         # log undeclared paths even when openapi-path is disabled
```

Go types:

```go
type Global struct {
    DetectOnly    bool           `yaml:"detect_only"`
    Disable       []string       `yaml:"disable"`
    Headers       HeaderConfig   `yaml:"headers"`
    RequestLimits RequestLimits  `yaml:"request_limits"`
    BodyLimits    BodyLimits     `yaml:"body_limits"`
    Multipart     MultipartCfg   `yaml:"multipart"`
    Protocol      ProtocolCfg    `yaml:"protocol"`
    CRS           CRSCfg         `yaml:"crs"`
    OpenAPI       OpenAPIGlobal  `yaml:"openapi"`
}
```

### Global field reference

| Path | Type | Default | Validation |
|---|---|---|---|
| `global.detect_only` | bool | `true` | — |
| `global.disable` | []string | `[]` | every entry must resolve to a registered canonical name (category or sub-protection) |
| `global.headers.preset` | enum | `moderate` | one of `strict`, `moderate`, `api-only`, `custom` |
| `global.headers.inject` | map[string]string | `{}` | keys must be canonical header-* names from `protections.md` |
| `global.headers.strip_extra` | []string | `[]` | valid HTTP header names |
| `global.request_limits.max_body_size` | byte size | `10MB` | `> 0`, `<= 1GB` |
| `global.request_limits.max_url_length` | int | `8192` | `>= 512`, `<= 65536` |
| `global.request_limits.max_header_size` | byte size | `16KB` | `>= 4KB`, `<= 1MB` |
| `global.request_limits.max_header_count` | int | `100` | `>= 10`, `<= 1000` |
| `global.request_limits.allowed_methods` | []string | standard 7 | each must be a valid HTTP method |
| `global.request_limits.require_host_header` | bool | `true` | — |
| `global.request_limits.require_content_type` | bool | `true` | — |
| `global.body_limits.json_depth` | int | `20` | `>= 1`, `<= 1000` |
| `global.body_limits.json_keys` | int | `1000` | `>= 1`, `<= 100000` |
| `global.body_limits.xml_depth` | int | `20` | `>= 1`, `<= 1000` |
| `global.body_limits.xml_entities` | int | `100` | `>= 0`, `<= 10000` |
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
| `global.crs.paranoia_level` | int | `1` | `>= 1`, `<= 4` |
| `global.crs.anomaly_threshold` | int | `5` | `>= 1` |
| `global.crs.debug_log_rule_ids` | bool | `false` | — |
| `global.openapi.shadow_api_logging` | bool | `true` | — |

**Byte sizes** accept suffixes: `B`, `KB`, `MB`, `GB` (powers of 1024). Bare integers are bytes.
**Durations** use Go's `time.ParseDuration` syntax: `500ms`, `10s`, `2m`, etc.

## Route section

```yaml
routes:
  - id: public-api                   # optional, used as metric label; default: generated from match
    match:
      hosts: [api.example.com]       # optional; default: match any host
      paths: ["/v1/*"]               # required; glob syntax, most-specific wins
    upstream: http://backend:8000    # required
    upstream_timeout: 30s            # optional, default: 30s

    detect_only: false               # override global; optional

    disable: []                      # canonical protection names disabled for this route only

    headers:
      preset: strict                 # override global preset
      inject:
        header-csp: "default-src 'self'; script-src 'self' https://cdn.example.com"
      strip_extra: []

    request_limits:                  # any subset; unspecified fields inherit from global
      max_body_size: 50MB

    body_limits: {}
    multipart: {}
    protocol: {}

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
    ID              string         `yaml:"id"`
    Match           Match          `yaml:"match"`
    Upstream        string         `yaml:"upstream"`
    UpstreamTimeout time.Duration  `yaml:"upstream_timeout"`
    DetectOnly      *bool          `yaml:"detect_only"`   // pointer: nil means inherit
    Disable         []string       `yaml:"disable"`
    Headers         *HeaderConfig  `yaml:"headers"`       // pointer: nil means inherit
    RequestLimits   *RequestLimits `yaml:"request_limits"`
    BodyLimits      *BodyLimits    `yaml:"body_limits"`
    Multipart       *MultipartCfg  `yaml:"multipart"`
    Protocol        *ProtocolCfg   `yaml:"protocol"`
    OpenAPI         *OpenAPIRoute  `yaml:"openapi"`
    CORS            *CORSCfg       `yaml:"cors"`
}

type Match struct {
    Hosts []string `yaml:"hosts"`
    Paths []string `yaml:"paths"`
}
```

### Route field reference

| Path | Type | Default | Validation |
|---|---|---|---|
| `routes[].id` | string | generated from first path | `^[a-z0-9][a-z0-9-]*$`, unique per config |
| `routes[].match.hosts` | []string | `[]` (any) | each a valid hostname or wildcard (`*.example.com`) |
| `routes[].match.paths` | []string | — (required) | non-empty, each starts with `/` |
| `routes[].upstream` | URL string | — (required) | valid `http://` or `https://` URL |
| `routes[].upstream_timeout` | duration | `30s` | `>= 1s`, `<= 600s` |
| `routes[].detect_only` | bool pointer | inherit from global | — |
| `routes[].disable` | []string | `[]` | canonical names (category or sub-protection) |
| `routes[].headers.preset` | enum | inherit | `strict`, `moderate`, `api-only`, `custom` |
| `routes[].headers.inject` | map | inherit (merged key-wise) | keys are canonical `header-*` names |
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

## Route matching precedence

When a request arrives:

1. Filter routes whose `match.hosts` matches the request `Host` header. Empty `hosts` matches any host.
2. Among survivors, select the route whose `match.paths` has the most specific match.
3. Specificity: literal path > longer prefix > shorter prefix. `/v1/users/profile` beats `/v1/users/*` beats `/v1/*` beats `/*`.
4. Ties are resolved by source order (earlier wins). The compiler warns when ties exist.
5. If no route matches, the request is rejected with `404 Not Found`. There is no default route — explicit routing is part of principle 3 (path-first).

Host matching:
- Exact: `api.example.com`
- Suffix wildcard: `*.example.com` matches `foo.example.com` but not `example.com`
- Case-insensitive

Path matching uses glob syntax: `*` matches a single segment, `**` matches any number of segments. Trailing slashes are normalized.

## Phase 2: `routes.d/*.yaml` loading

The main `waf.yaml` contains `global` and optionally `routes`. Every file in `routes.d/` contributes a `routes:` list. Semantics:

- Files load in lexicographic order. Ordering matters only for tie-breaking, but teams should not rely on it.
- Each file is parsed independently. A parse error in one file fails the entire reload.
- Route IDs must be unique across the main file plus all `routes.d/` files.
- `routes.d/` files may **not** redefine `global`. Any `global:` key in those files is a validation error.
- A team owning `routes.d/payments.yaml` can change their file without touching anyone else's.

Directory resolution: if the main config is at `/etc/barbacana/waf.yaml`, the default routes directory is `/etc/barbacana/routes.d/`. Overridable via `routes_dir:` in the main file.

## Example 1: minimal

```yaml
version: 1

routes:
  - match:
      paths: ["/*"]
    upstream: http://app:8000
```

Everything else is defaulted. Every protection is active in detect-only. Secure headers injected with the `moderate` preset. All canonical strip headers removed.

## Example 2: multi-route with per-team overrides

```yaml
version: 1

global:
  detect_only: false                 # switch whole instance to blocking mode

routes:
  - id: public-api
    match:
      hosts: [api.example.com]
      paths: ["/v1/*"]
    upstream: http://api-backend:8000
    openapi:
      spec: /etc/barbacana/specs/public-api.yaml

  - id: admin
    match:
      hosts: [admin.example.com]
      paths: ["/*"]
    upstream: http://admin-backend:8000
    headers:
      preset: strict
    cors:
      allow_origins: ["https://admin.example.com"]
      allow_credentials: true

  - id: legacy-php
    match:
      paths: ["/legacy/*"]
    upstream: http://legacy:80
    disable:
      - php-injection                # legacy app trips on its own PHP-ish params
      - null-byte-injection          # legacy binary protocol uses \x00 markers
    detect_only: true                # keep logging but don't break the legacy app
```

## Example 3: extensive overrides

```yaml
version: 1
listen: ":443"

global:
  detect_only: false
  disable:
    - scanner-detection              # noisy across the whole fleet
  headers:
    preset: custom
    inject:
      header-csp: "default-src 'self' https://assets.example.com"
      header-hsts: "max-age=31536000"
    strip_extra:
      - X-Custom-Backend-Id
  request_limits:
    max_body_size: 50MB
    allowed_methods: [GET, POST, PUT, DELETE]
  body_limits:
    json_depth: 15
  crs:
    paranoia_level: 2
    anomaly_threshold: 7

routes:
  - id: uploads
    match:
      paths: ["/upload/*"]
    upstream: http://uploads:8000
    request_limits:
      max_body_size: 500MB
    multipart:
      file_limit: 50
      file_size: 100MB
      allowed_types:
        - image/png
        - image/jpeg
        - application/pdf
      double_extension: true
    disable:
      - xss-stored                   # file bytes often look like HTML; validated server-side

  - id: graphql
    match:
      paths: ["/graphql"]
    upstream: http://gql:4000
    body_limits:
      json_depth: 40                 # GraphQL queries can be deep
      json_keys: 5000
    openapi:
      spec: ""                       # explicitly no OpenAPI; GraphQL has its own schema

  - id: webhooks
    match:
      hosts: [hooks.example.com]
      paths: ["/*"]
    upstream: http://hook-router:8000
    disable:
      - require-content-type         # some providers send empty body
      - header-csp                   # webhooks never render HTML
    headers:
      preset: api-only
```

## Validation behaviour

All validation runs during `barbacana validate <config>` and on startup. Errors are emitted as a single `multierror` with file path, YAML line number, and a specific message. Example:

```
waf.yaml:17: unknown protection "sql-injetcion" in route "public-api" disable list (did you mean "sql-injection"?)
waf.yaml:23: global.request_limits.max_body_size must be <= 1GB, got 2GB
waf.yaml:31: route "admin" cors.allow_credentials is true but allow_origins contains "*"
```

The binary exits 1 with the error list. No config fragments are ever applied when validation fails.
