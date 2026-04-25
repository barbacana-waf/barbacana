package protocol

import (
	"context"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/barbacana-waf/barbacana/internal/protections"
	"golang.org/x/text/unicode/norm"
)

const (
	DoubleEncoding       = "double-encoding"
	UnicodeNormalization = "unicode-normalization"
	PathNormalization    = "path-normalization"
)

// ── double-encoding ─────────────────────────────────────────────────

// DoubleEncode rejects requests that contain double-encoded characters.
// Decode once, check if the result still contains encoded sequences.
type DoubleEncode struct{}

func (DoubleEncode) Name() string     { return DoubleEncoding }
func (DoubleEncode) Category() string { return "" }
func (DoubleEncode) CWE() string      { return "CWE-174" }

func (DoubleEncode) Evaluate(_ context.Context, r *http.Request) protections.Decision {
	// Check URL path.
	raw := r.URL.RawPath
	if raw == "" {
		raw = r.URL.Path
	}
	if hasDoubleEncoding(raw) {
		return protections.Block(DoubleEncoding, "double-encoded path")
	}
	// Check query string.
	if hasDoubleEncoding(r.URL.RawQuery) {
		return protections.Block(DoubleEncoding, "double-encoded query")
	}
	return protections.Allow()
}

func hasDoubleEncoding(s string) bool {
	if s == "" {
		return false
	}
	// Decode once.
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return false
	}
	// If the decoded result still contains percent-encoded sequences, it was double-encoded.
	return containsPercentEncoding(decoded)
}

func containsPercentEncoding(s string) bool {
	for i := 0; i < len(s)-2; i++ {
		if s[i] == '%' && isHex(s[i+1]) && isHex(s[i+2]) {
			return true
		}
	}
	return false
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// ── unicode-normalization ───────────────────────────────────────────

// UnicodeNorm NFC-normalizes the request URI and query before downstream
// evaluation. This is a transformation, not a blocking protection.
type UnicodeNorm struct{}

func (UnicodeNorm) Name() string     { return UnicodeNormalization }
func (UnicodeNorm) Category() string { return "" }
func (UnicodeNorm) CWE() string      { return "CWE-176" }

func (UnicodeNorm) Evaluate(ctx context.Context, r *http.Request) protections.Decision {
	// NFC normalization is for CRS inspection only. The upstream still
	// receives the exact bytes the client sent, so we write into the
	// pipeline's InspectionPath rather than mutating r.URL.
	ip, ok := protections.InspectionPathFromContext(ctx)
	if !ok {
		// Unit tests may call Evaluate without the pipeline wiring.
		// Fall through to a local struct so the normalization logic
		// is still exercised; the caller just does not observe it.
		ip = protections.NewInspectionPath(r)
	}
	if !norm.NFC.IsNormalString(ip.Path) {
		ip.Path = norm.NFC.String(ip.Path)
	}
	if ip.RawPath != "" && !norm.NFC.IsNormalString(ip.RawPath) {
		ip.RawPath = norm.NFC.String(ip.RawPath)
	}
	if !norm.NFC.IsNormalString(ip.RawQuery) {
		ip.RawQuery = norm.NFC.String(ip.RawQuery)
	}
	return protections.Allow()
}

// ── path-normalization ──────────────────────────────────────────────

// PathNorm resolves `../`, `./`, `//`, backslash, and encoded variants
// in request paths. This is a transformation protection.
type PathNorm struct{}

func (PathNorm) Name() string     { return PathNormalization }
func (PathNorm) Category() string { return "" }
func (PathNorm) CWE() string      { return "CWE-22" }

func (PathNorm) Evaluate(ctx context.Context, r *http.Request) protections.Decision {
	// Path canonicalization is for CRS inspection only — a trailing
	// slash, `/foo/../bar`, or `\` in the client's URL must still reach
	// the upstream exactly as sent. Write the canonical form into the
	// pipeline's InspectionPath instead of mutating r.URL.
	ip, ok := protections.InspectionPathFromContext(ctx)
	if !ok {
		// No pipeline wiring (unit test harness). Exercise the logic
		// against a local struct so the normalization code path is
		// still covered, even though nothing downstream reads it.
		ip = protections.NewInspectionPath(r)
	}
	p := ip.Path
	p = strings.ReplaceAll(p, "\\", "/")
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	p = path.Clean(p)
	if p == "" || p == "." {
		p = "/"
	}
	ip.Path = p
	ip.RawPath = ""
	return protections.Allow()
}

