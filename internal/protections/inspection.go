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
