# Testing

> **When to read**: writing tests, reviewing test changes, or deciding what to test for a new feature. **Not needed for**: implementing a protection itself (use `conventions.md`).

Barbacana has two test tiers:

1. **Unit tests** — table-driven, alongside the code, cover a single package in isolation.
2. **Integration tests** — end-to-end in `internal/pipeline/integration_test.go`, exercise the full request path through a running barbacana binary against a mock upstream.

There is no third tier. We do not write system tests, chaos tests, or load tests as part of the primary suite. Load testing is a separate operator concern.

## Unit tests

- Location: `_test.go` files next to the code under test.
- Framework: standard `testing` package only. No testify, no ginkgo, no custom harness.
- Pattern: table-driven with named subcases via `t.Run(tc.name, ...)`.
- Scope: one package per test file. Never reach across package boundaries in a unit test — if you need another package's behaviour, it belongs in integration.
- Parallelism: call `t.Parallel()` on subtests when they have no shared state.

Run:
```
go test ./...
```

### Unit test format

Template — follows the reference implementation in `conventions.md`:

```go
func TestXxx(t *testing.T) {
    cases := []struct {
        name      string
        input     <type>
        wantBlock bool
        wantName  string // canonical protection name, empty if allow
    }{
        {name: "clean request",   input: ...,                 wantBlock: false},
        {name: "attack payload",  input: ...,                 wantBlock: true,  wantName: "null-byte-injection"},
        {name: "edge case",       input: ...,                 wantBlock: false},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            t.Parallel()
            got := Subject{}.Evaluate(context.Background(), tc.input)
            if got.Block != tc.wantBlock {
                t.Errorf("Block = %v, want %v", got.Block, tc.wantBlock)
            }
            if tc.wantBlock && got.Protection != tc.wantName {
                t.Errorf("Protection = %q, want %q", got.Protection, tc.wantName)
            }
        })
    }
}
```

### What to cover in unit tests

Every protection unit test **must** include at minimum:
- One clean-traffic case that returns `Allow`.
- At least one attack case per distinct technique the protection targets.
- One boundary case (empty input, maximum allowed input, unusual encoding).
- One disabled-protection case (when `disable` contains the canonical name, the evaluator short-circuits).

Config parser unit tests must cover:
- Minimal valid config parses and defaults fill in correctly.
- Every invalid-input path produces a precise error message.
- Three end-to-end examples from `config-schema.md` parse successfully.

## Fixture layout

```
internal/
  protections/
    openapi/
      testdata/
        specs/
          petstore.yaml
          empty.yaml
      openapi_test.go
  config/
    testdata/
      golden/
        minimal.json           # expected compiled Caddy JSON
        multi-route.json
      configs/
        minimal.yaml
        multi-route.yaml
        invalid-unknown-protection.yaml
      config_test.go
  pipeline/
    testdata/
      cases/
        sqli-auth-bypass.yaml
        xss-script-tag.yaml
        clean-get.yaml
      integration_test.go
```

Golden files for config compilation:
- Write the expected Caddy JSON into `testdata/golden/<case>.json`.
- The test runs the compiler on `testdata/configs/<case>.yaml` and diffs against the golden file.
- Regenerate with `go test ./internal/config -update`.

## Integration tests

- Location: `internal/pipeline/integration_test.go` (and additional files for large scenarios).
- Build tag: `//go:build integration`. Normal `go test ./...` does not run them.
- Framework: standard `testing` + `httptest` for mock upstreams + a helper that boots a real barbacana process or a Caddy instance with the compiled config.
- Goal: prove the full pipeline behaves correctly, including middleware ordering, audit logs, and metrics.

Run:
```
go test -tags=integration ./internal/pipeline/...
```

### Integration test case format

Each test case is a YAML file in `testdata/cases/`. The integration harness loads each file, spins up barbacana with the embedded config, drives the request, and asserts the response + audit log + metrics.

```yaml
# testdata/cases/sqli-auth-bypass.yaml
name: sqli-auth-bypass
description: A classic OR 1=1 authentication bypass in a query parameter must be blocked.

config:
  version: 1
  global:
    mode: blocking
  routes:
    - id: api
      match:
        paths: ["/*"]
      upstream: "{{ upstream }}"     # templated — harness substitutes its mock server URL

request:
  method: GET
  path: "/login?user=admin&pass=' OR 1=1--"
  headers:
    Host: api.example.com

expect:
  response:
    status: 403
    body_contains: '"error":"blocked"'
  audit:
    action: blocked
    matched_protections:
      contains: ["sql-injection", "sql-injection-auth"]
    anomaly_score:
      gte: 5
  metrics:
    waf_requests_blocked_total:
      labels: { route: "api", protection: "sql-injection-auth" }
      delta: 1
  upstream:
    received_requests: 0              # the proxy must not forward a blocked request
```

Keys:
- `config`: the full barbacana YAML to start with. `{{ upstream }}` is substituted with the mock backend URL.
- `request`: a single HTTP request. `method`, `path`, `headers`, `body` (string or filepath).
- `expect.response`: status code, header assertions, `body_contains` or `body_equals`.
- `expect.audit`: structured assertions on the captured stdout JSON log.
- `expect.metrics`: named metric, labels, and a `delta` counter change or `value` for gauges.
- `expect.upstream`: whether and how the mock upstream was called.

### Required integration test coverage

The MVP integration suite must include cases for:

| Scenario | Case file |
|---|---|
| Clean GET passes through | `clean-get.yaml` |
| SQLi blocked by `sql-injection-auth` | `sqli-auth-bypass.yaml` |
| XSS blocked by `xss-script-tag` | `xss-script-tag.yaml` |
| RCE blocked by `rce-unix-command` | `rce-unix-cat.yaml` |
| Disabled sub-protection lets request through | `disable-sub-sqli-union.yaml` |
| Disabled category disables all sub-protections | `disable-category-sqli.yaml` |
| OpenAPI: undeclared path returns 404 | `openapi-unknown-path.yaml` |
| OpenAPI: invalid body returns 422 | `openapi-invalid-body.yaml` |
| Security header injected in response | `headers-csp-injected.yaml` |
| Server header stripped from upstream | `headers-strip-server.yaml` |
| Request smuggling (CL+TE) rejected | `smuggling-cl-te.yaml` |
| CRLF in header rejected | `crlf-header.yaml` |
| Null byte in URL rejected | `null-byte-url.yaml` |
| JSON body depth exceeded returns 413 | `json-depth-exceeded.yaml` |
| XML billion-laughs rejected | `xml-bomb.yaml` |
| Multipart double-extension (`shell.php.jpg`) rejected | `multipart-double-ext.yaml` |
| Multipart file count limit | `multipart-file-limit.yaml` |
| Detect mode: attack is logged but proxied | `detect-mode-sqli.yaml` |
| CORS: preflight from allowed origin returns 204 with correct headers | `cors-preflight-allowed.yaml` |
| CORS: request from unlisted origin blocked | `cors-origin-blocked.yaml` |
| Metrics: blocked request increments `waf_requests_blocked_total` with sub-protection label | `metrics-block-label.yaml` |
| Audit log: blocked request emits JSON with both category + sub-protection names | `audit-aggregation.yaml` |
| Decompression bomb rejected (ratio > 100:1) | `decompression-bomb.yaml` |
| Body exceeding max_inspect_size: CRS evaluates only first 128KB | `max-inspect-size.yaml` |
| Body exceeding max_memory_buffer spools to disk, request succeeds | `body-spool-to-disk.yaml` |
| CRS evaluation exceeding evaluation_timeout is killed | `evaluation-timeout.yaml` |
| Content-type not in accept list returns 415 | `content-type-rejected.yaml` |
| JSON-only route skips XML parsing (XML payload not parsed) | `content-type-gating-json.yaml` |
| Path rewrite: strip_prefix removes prefix before upstream | `rewrite-strip-prefix.yaml` |
| Path rewrite: OpenAPI validates against rewritten path | `rewrite-openapi.yaml` |
| Config reload: SIGHUP applies new route | `reload-sighup.yaml` |

## CRS rule coverage

For each CRS-backed sub-protection, the unit test in `internal/protections/crs/` must include at least one payload known to trigger that sub-protection. Source these from the OWASP CRS test suite (also embedded or referenced by fixture), not from hand-written payloads — hand-written payloads tend to over-fit the test.

The CRS test suite is a structured YAML format; the barbacana test loader maps CRS test cases to sub-protection names via `protections-crs-mapping.md`. Regression: if the CRS version is bumped and a sub-protection loses coverage (no triggering payload maps to it), CI fails.

## OpenAPI validation tests

- Sample specs live in `internal/protections/openapi/testdata/specs/`.
- `petstore.yaml` — the standard OpenAPI 3.0 example; covers typical validation cases.
- `empty.yaml` — a spec with zero paths, used to test that every request is rejected as undeclared.
- Cases must cover: undeclared path, undeclared method for declared path, declared path with invalid body, declared path with invalid query param type, declared path with unlisted content type, valid request passes.

## What NOT to test

- **Caddy internals.** We don't reimplement tests for reverse proxying, TLS, HTTP/2 framing, etc. If Caddy regresses, that is an upstream bug.
- **Coraza internals.** We don't test that Coraza correctly executes SecLang. We test that *our mapping* from canonical names to Coraza rule ranges is correct by driving attack payloads end-to-end.
- **Third-party OpenAPI library internals.** We test our adapter and our assertions, not the library's schema validator.
- **Go standard library** (`net/http`, `encoding/json`, `log/slog`).
- **Prometheus client internals.** We verify that our metric names and labels are emitted, not that the Prometheus text format is correct.

If a bug shows up in one of these "do not test" boundaries, the fix is an upstream issue, a dependency pin adjustment, or an adapter test — never a reimplementation of the upstream's test suite.

## Running locally

```
# Unit tests (fast, always run)
go test ./...

# With verbose output and race detector
go test -race -v ./...

# Integration tests (requires the binary to build cleanly)
go test -tags=integration ./internal/pipeline/...

# Regenerate golden config JSON files after an intentional schema change
go test ./internal/config -update

# Single protection
go test ./internal/protections/protocol -run TestNullByte
```

CI runs all three blocks in the pipeline defined in `build.md`.
