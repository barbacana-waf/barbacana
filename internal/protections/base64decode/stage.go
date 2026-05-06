package base64decode

import (
	"context"
	"net/http"

	"github.com/barbacana-waf/barbacana/internal/protections"
)

// Canonical leaf names. These must match the catalog entries exactly —
// see internal/protections/catalog_data_base64.go.
const (
	LeafPath  = "base64-decoding-path"
	LeafQuery = "base64-decoding-parameters"
	LeafBody  = "base64-decoding-body"
	LeafFlood = "base64-decoding-flood"
)

// maxDecodedValues is the per-request cap on successful printable
// decodes across all surfaces. Hardcoded for v0.5 — see the plan
// §2.7 for why this is not user-configurable.
const maxDecodedValues = 50

// Stage is the per-route base64-decoding stage. It populates the
// pipeline's InspectionArgs with synthetic ARGS for any base64-encoded
// values found in the path, query, or body, and emits a blocking
// decision when a request crosses the flood threshold.
//
// The stage never modifies the request — all output flows through the
// context-scoped InspectionArgs.
type Stage struct {
	disabled map[string]bool
}

// New returns a Stage configured against the route's resolved disable
// set. The disable map is read at request time to gate per-surface
// scanning, so all four leaves can be tuned independently.
func New(disabled map[string]bool) *Stage {
	return &Stage{disabled: disabled}
}

// Evaluate scans the request and writes any decoded values to the
// InspectionArgs attached to ctx. Returns a blocking decision if the
// flood threshold is exceeded; otherwise Allow().
func (s *Stage) Evaluate(ctx context.Context, r *http.Request, body []byte) protections.Decision {
	ia := protections.DecodedArgsFromContext(ctx)
	if ia == nil {
		// No pipeline wiring (unit-test harness without the surrounding
		// handler). Nothing to populate.
		return protections.Allow()
	}

	floodEnabled := !protections.IsDisabled(LeafFlood, s.disabled)
	b := newBudget(maxDecodedValues, floodEnabled)

	if !protections.IsDisabled(LeafPath, s.disabled) {
		path := pathToScan(ctx, r)
		scanPath(path, ia, b)
	}
	if !protections.IsDisabled(LeafQuery, s.disabled) {
		scanQuery(rawQueryToScan(ctx, r), ia, b)
	}
	if !protections.IsDisabled(LeafBody, s.disabled) {
		scanBody(body, ia, b)
	}

	if b.tripped() {
		return protections.Block(LeafFlood, "request contains too many base64-decodable values")
	}
	return protections.Allow()
}

// pathToScan returns the normalized inspection path when the pipeline
// wired one in, falling back to r.URL.Path for unit-test callers.
func pathToScan(ctx context.Context, r *http.Request) string {
	if ip, ok := protections.InspectionPathFromContext(ctx); ok {
		return ip.Path
	}
	return r.URL.Path
}

// rawQueryToScan returns the normalized inspection raw query when the
// pipeline wired one in, falling back to r.URL.RawQuery.
func rawQueryToScan(ctx context.Context, r *http.Request) string {
	if ip, ok := protections.InspectionPathFromContext(ctx); ok {
		return ip.RawQuery
	}
	return r.URL.RawQuery
}

// budget tracks successful-decode count against maxDecodedValues. When
// flood enforcement is enabled and the count exceeds the cap, the
// budget trips and consume() returns false so per-surface scanners
// stop walking.
type budget struct {
	max     int
	count   int
	enabled bool
	trip    bool
}

func newBudget(max int, enabled bool) *budget {
	return &budget{max: max, enabled: enabled}
}

// consume records one successful decode and returns true if the caller
// may emit it. When the budget is exhausted (flood enabled and count
// would exceed max), consume returns false and trips the budget.
func (b *budget) consume() bool {
	if b.enabled && b.count >= b.max {
		b.trip = true
		return false
	}
	b.count++
	return true
}

// exceeded reports whether the budget has tripped. Per-surface scanners
// check this between iterations so a tripped budget halts the walk
// without further work.
func (b *budget) exceeded() bool { return b.trip }

// tripped reports whether the budget tripped during this evaluation —
// the signal the stage uses to emit the flood decision.
func (b *budget) tripped() bool { return b.trip }
