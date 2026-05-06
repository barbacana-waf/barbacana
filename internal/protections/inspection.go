package protections

import (
	"context"
	"net/http"
	"net/url"
)

// InspectionPath holds the normalized view of the request URL used for
// security evaluation (CRS). Normalization stages mutate this struct
// instead of r.URL so the reverse proxy can forward the original path
// bytes the client sent — see docs/design/conventions.md
// §"Normalization is for detection, not for proxying".
type InspectionPath struct {
	Path     string
	RawPath  string
	RawQuery string
}

type inspectionCtxKey struct{}

// NewInspectionPath captures the request's current path and query into
// a fresh InspectionPath. Call this once at the pipeline entry before
// any normalization stage runs.
func NewInspectionPath(r *http.Request) *InspectionPath {
	return &InspectionPath{
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
	}
}

// WithInspectionPath attaches ip to ctx so later stages can read and
// update it. The value is a pointer: normalization stages mutate in
// place, downstream stages see the accumulated result.
func WithInspectionPath(ctx context.Context, ip *InspectionPath) context.Context {
	return context.WithValue(ctx, inspectionCtxKey{}, ip)
}

// InspectionPathFromContext returns the inspection path attached by the
// pipeline. The second return value is false when the caller is running
// outside the pipeline (e.g. a unit test that builds a handler in
// isolation) — callers should fall back to r.URL in that case.
func InspectionPathFromContext(ctx context.Context) (*InspectionPath, bool) {
	ip, ok := ctx.Value(inspectionCtxKey{}).(*InspectionPath)
	return ip, ok
}

// BuildInspectionURL renders the inspection path as a URL string
// suitable for Coraza's ProcessURI. It falls back to r.URL.String()
// when no inspection path has been attached to the context.
func BuildInspectionURL(ctx context.Context, r *http.Request) string {
	ip, ok := InspectionPathFromContext(ctx)
	if !ok {
		return r.URL.String()
	}
	u := url.URL{
		Path:     ip.Path,
		RawPath:  ip.RawPath,
		RawQuery: ip.RawQuery,
	}
	return u.RequestURI()
}

// ArgPair is one synthetic ARG fed to CRS — a name/value pair produced by
// a producer stage (e.g. base64 decoding) for inspection only. The name
// is the synthetic key shown in audit logs (e.g. "q.b64decoded"); the
// value is the decoded payload that CRS rules evaluate.
type ArgPair struct {
	Name  string
	Value string
}

// InspectionArgs holds synthetic ARGS produced by producer stages
// (currently just base64 decoding) for the CRS engine to evaluate
// alongside the request. Mirrors InspectionPath: producer stages append
// to the slices, the consumer (crs.Engine.Evaluate) reads them. The
// upstream request body and URL are never mutated — see
// docs/design/conventions.md §"Normalization is for detection, not for
// proxying".
type InspectionArgs struct {
	GET  []ArgPair
	POST []ArgPair
	PATH []ArgPair
}

type inspectionArgsCtxKey struct{}

// NewInspectionArgs returns a fresh empty InspectionArgs. Call once at
// the pipeline entry, before any producer stage runs.
func NewInspectionArgs() *InspectionArgs {
	return &InspectionArgs{}
}

// WithInspectionArgs attaches ia to ctx so producer stages can append to
// it and the CRS consumer can read it. The value is a pointer:
// producers mutate in place.
func WithInspectionArgs(ctx context.Context, ia *InspectionArgs) context.Context {
	return context.WithValue(ctx, inspectionArgsCtxKey{}, ia)
}

// DecodedArgsFromContext returns the synthetic ARGS attached by the
// pipeline, or nil when the caller is running outside the pipeline
// (e.g. a unit test that drives Engine.Evaluate directly). Returning
// nil rather than (value, false) lets the consumer write the
// idiomatic `if decoded := DecodedArgsFromContext(ctx); decoded != nil`
// guard.
func DecodedArgsFromContext(ctx context.Context) *InspectionArgs {
	ia, _ := ctx.Value(inspectionArgsCtxKey{}).(*InspectionArgs)
	return ia
}
