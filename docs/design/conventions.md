# Conventions

> **When to read**: writing or reviewing Go code in this repo, adding a protection, adding a metric, adding a config key. **Not needed for**: high-level scope decisions (use `principles.md`/`features.md`).

This document is the source of truth for *how* code is written. Anything not specified here defers to `gofmt`, `go vet`, and idiomatic Go.

## Go code conventions

### Errors

- Wrap with `fmt.Errorf("context: %w", err)`. The context describes *what was being attempted*, not the error itself.
- No sentinel errors. Use typed errors only when callers need to switch on them; check with `errors.As`.
- Never panic in the request path. Panics in `main` startup are acceptable for unrecoverable misconfiguration.
- Errors returned to a request flow through the audit log; do not also `slog.Error` them at the call site.

### Logging

- `log/slog` only. No `log`, no `logrus`, no `zap`, no `fmt.Println`.
- JSON handler always: `slog.NewJSONHandler(os.Stdout, ...)`.
- Levels: `Debug` for rule-ID-level detail, `Info` for lifecycle (startup, reload), `Warn` for recovered config issues, `Error` for unrecoverable issues. Audit log entries are `Info`.
- Always pass `context.Context` to logging helpers that read trace/request fields.
- Field naming: lowercase snake_case keys (`request_id`, not `RequestID` or `requestId`).

### Context

- Every exported function that performs I/O, blocks, or could be cancelled takes `ctx context.Context` as its **first** argument.
- Never store `context.Context` in a struct.
- Never pass `nil` context. Use `context.Background()` at the top of `main` and propagate.

### Naming

- Package names: short, lowercase, no underscores (`protocol`, not `protocol_hardening`).
- Exported types and functions: `PascalCase`. Acronyms keep case (`HTTPClient`, `URLParser`, `ID`).
- Files: `snake_case.go`. Test files: `<name>_test.go`. Integration tests: `<name>_integration_test.go` with `//go:build integration`.
- Canonical protection names in code: lowercase, hyphens (`"null-byte-injection"`). Define each as a `const` in the protection's package.

### Concurrency

- No global mutable state. Anything shared is constructed in `main` and passed in.
- Configuration is immutable after `caddy.Load`. Reloads produce a new config object, never mutate the running one.
- Per-request state lives on the request context.

### Imports

- Standard library, blank line, third-party, blank line, internal (`github.com/barbacana-waf/barbacana/...`). `goimports` enforces this.
- No dot imports. No package-level aliases unless resolving a name conflict.

## How to add a new protection

1. **Pick a canonical name**. Check `docs/design/protections.md`. If it is a CRS-backed sub-protection, the name and CRS rule range come from `docs/design/protections-crs-mapping.md`.
2. **Pick a package**. CRS-backed → `internal/protections/crs/`. Native protocol/normalization → `internal/protections/protocol/`. Header injection/strip → `internal/protections/headers/`. Request shape → `internal/protections/request/`. OpenAPI → `internal/protections/openapi/`.
3. **Write the protection**. Implement the `Protection` interface (see reference below). Define the canonical name as a `const`.
4. **Register it**. Add an explicit registration call in `main.go`. No `init()`.
5. **Add the metric label**. The protection name automatically becomes a label value for `waf_requests_blocked_total`. No new metric needed for a normal protection.
6. **Add tests**. Table-driven, request in / decision out. Cover: clean traffic passes, attack payload blocks, disabled protection short-circuits.
7. **Add a config defaults entry** if the protection has tunable knobs (e.g. limits). See "How to add a new config key".
8. **Update docs**. Add the canonical name + description + CWE row to the relevant table in `protections.md`. If CRS-backed, update `protections-crs-mapping.md`.
9. **Run** `go vet ./...` and `go test ./...`. Both must pass.

## How to add a new metric

1. Decide if it belongs at the **route** level, **protection** level, or **process** level. This determines labels.
2. Add the registration in `internal/metrics/metrics.go`. Use `promauto.New<Counter|Gauge|Histogram>Vec` with the global registry.
3. Document it in `docs/design/architecture.md` under the metrics table.
4. The metric name is part of the public API — adding is a minor version bump, renaming/removing is major.
5. Avoid high-cardinality labels. `route` is bounded by config; `protection` is bounded by the registry. Never label by IP, user, or request ID.

## How to add a new config key

1. Add the field to the appropriate struct in `internal/config/types.go` with a `yaml:"..."` tag.
2. Add the default value in `internal/config/defaults.go`. Even "unset means false" gets an explicit entry — it documents intent.
3. Add validation in `internal/config/validate.go` if the value has constraints.
4. Update `docs/design/config-schema.md` with the field, type, default, and constraints.
5. Add a unit test in `internal/config/config_test.go` covering: default applied when unset, value preserved when set, invalid value rejected.
6. Renaming or removing a config key is a major version bump. Adding a key is minor.

## Reference implementation: `null-byte-injection`

This is a complete, idiomatic protection. Use it as the template for any native protection.

```go
// Package protocol implements native protocol hardening protections.
package protocol

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/barbacana-waf/barbacana/internal/audit"
	"github.com/barbacana-waf/barbacana/internal/protections"
)

const NullByteInjection = "null-byte-injection"

// NullByte rejects requests containing %00 / NUL bytes in the URL,
// query string, or any header value. Null bytes are virtually never
// legitimate in HTTP and are a classic path-truncation evasion.
type NullByte struct{}

func (NullByte) Name() string { return NullByteInjection }

func (NullByte) Category() string { return "" } // top-level, no parent

func (NullByte) CWE() string { return "CWE-158" }

func (NullByte) Evaluate(ctx context.Context, r *http.Request) protections.Decision {
	if strings.ContainsRune(r.URL.RawPath, '\x00') ||
		strings.ContainsRune(r.URL.RawQuery, '\x00') {
		return protections.Block(NullByteInjection, "null byte in URL")
	}
	for name, values := range r.Header {
		for _, v := range values {
			if strings.ContainsRune(v, '\x00') {
				return protections.Block(
					NullByteInjection,
					fmt.Sprintf("null byte in header %q", name),
				)
			}
		}
	}
	return protections.Allow()
}

// Register adds NullByte to the registry. Called explicitly from main.
func Register(reg *protections.Registry) {
	reg.Add(NullByte{})
}
```

The corresponding test:

```go
package protocol

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestNullByte(t *testing.T) {
	cases := []struct {
		name      string
		path      string
		query     string
		header    [2]string
		wantBlock bool
	}{
		{name: "clean request", path: "/api/users", wantBlock: false},
		{name: "null in path", path: "/api/users\x00.txt", wantBlock: true},
		{name: "null in query", path: "/api/users", query: "id=1\x00", wantBlock: true},
		{name: "null in header", path: "/api/users", header: [2]string{"X-Foo", "bar\x00"}, wantBlock: true},
		{name: "encoded null is decoded by net/http", path: "/api/users%00", wantBlock: true},
	}

	p := NullByte{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := tc.path
			if tc.query != "" {
				url += "?" + tc.query
			}
			r := httptest.NewRequest("GET", url, nil)
			if tc.header[0] != "" {
				r.Header.Set(tc.header[0], tc.header[1])
			}
			d := p.Evaluate(context.Background(), r)
			if d.Block != tc.wantBlock {
				t.Errorf("Block = %v, want %v (reason=%q)", d.Block, tc.wantBlock, d.Reason)
			}
		})
	}
}
```

Audit emission is the pipeline's job. The protection only returns a `Decision`. This keeps protections free of cross-cutting concerns.

## The Protection interface

Defined in `internal/protections/protection.go`:

```go
type Protection interface {
	Name() string             // canonical name, e.g. "null-byte-injection"
	Category() string         // parent category, "" if top-level
	CWE() string              // e.g. "CWE-89", "" if not applicable
	Evaluate(ctx context.Context, r *http.Request) Decision
}

type Decision struct {
	Block      bool
	Protection string // canonical name that triggered
	Reason     string // human-readable, ends up in debug log only
}

func Allow() Decision                          { return Decision{} }
func Block(name, reason string) Decision       { return Decision{Block: true, Protection: name, Reason: reason} }
```

CRS-backed protections do not implement this directly; they delegate to Coraza and translate Coraza's outcome into one or more `Decision` values via the mapping in `protections-crs-mapping.md`.

## Test patterns

- **Table-driven**, with named cases. Use `t.Run(tc.name, ...)` so failures point to the case.
- **Request in, decision out** for protection unit tests. Use `httptest.NewRequest` to construct inputs.
- **No mocks for the standard library**. Use `httptest.Server` for integration tests that need a real backend.
- **No mocks for Coraza or Caddy**. Either use the real thing in integration tests or do not test that boundary in a unit test.
- **Fixtures in `testdata/`** alongside the package. OpenAPI specs in `testdata/specs/`. Integration test cases in `internal/pipeline/testdata/`.
- **Golden files** are acceptable for config compilation tests (`Config → Caddy JSON`). Use `-update` flag to regenerate.
- Integration tests use the build tag `integration` and live in `internal/pipeline/integration_test.go`.

## Hierarchy in code

- A category protection (e.g. `sql-injection`) is registered with `Category() == ""` and a list of sub-protection names it owns.
- Sub-protections (e.g. `sql-injection-union`) are registered with `Category() == "sql-injection"`.
- The registry exposes `ExpandDisable(disable []string) map[string]bool`. Given a disable list that may include category names, it returns the full set of disabled sub-protection names.
- Pipeline calls `ExpandDisable` once per route at compile time. Per-request hot path is a single map lookup.

## Do NOT

- Do not use `init()` functions. Registration is explicit in `main.go`.
- Do not use package-level mutable variables. Configuration and registries are constructed in `main` and passed in.
- Do not use `fmt.Println`, `fmt.Printf`, `log.Printf`, or any non-`slog` logger.
- Do not import `log` (the standard `log` package). Import `log/slog`.
- Do not panic in the request path. Return a `Decision` or an error.
- Do not bypass the `Protection` interface. Every per-request security check goes through it.
- Do not expose Caddyfile syntax, Caddy JSON keys, or CRS rule IDs in user-facing config, CLI output, error messages, or audit logs. Debug logs only.
- Do not add `time.Sleep` in production code. If you need backoff, use `time/rate` or a context deadline.
- Do not write code that depends on goroutine scheduling order.
- Do not introduce a third-party logging, metrics, or HTTP framework. Use `log/slog`, `prometheus/client_golang`, and Caddy's `net/http` integration.
