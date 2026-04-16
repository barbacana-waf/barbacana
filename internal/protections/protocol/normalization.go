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

func (UnicodeNorm) Evaluate(_ context.Context, r *http.Request) protections.Decision {
	// NFC normalize path and query.
	if !norm.NFC.IsNormalString(r.URL.Path) {
		r.URL.Path = norm.NFC.String(r.URL.Path)
	}
	if r.URL.RawPath != "" && !norm.NFC.IsNormalString(r.URL.RawPath) {
		r.URL.RawPath = norm.NFC.String(r.URL.RawPath)
	}
	if !norm.NFC.IsNormalString(r.URL.RawQuery) {
		r.URL.RawQuery = norm.NFC.String(r.URL.RawQuery)
	}
	return protections.Allow()
}

// ── path-normalization ──────────────────────────────────────────────

// PathNorm resolves `../`, `./`, `//`, backslash, and encoded variants
// in request paths. This is a transformation protection.
type PathNorm struct{}

func (PathNorm) Name() string     { return PathNormalization }
func (PathNorm) Category() string { return "" }

func (PathNorm) Evaluate(_ context.Context, r *http.Request) protections.Decision {
	p := r.URL.Path
	// Replace backslashes with forward slashes.
	p = strings.ReplaceAll(p, "\\", "/")
	// Collapse double slashes.
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	// Resolve . and .. using path.Clean.
	p = path.Clean(p)
	if p == "" || p == "." {
		p = "/"
	}
	r.URL.Path = p
	r.URL.RawPath = ""
	return protections.Allow()
}

// RegisterNormalization adds input normalization protections to the registry.
func RegisterNormalization(reg *protections.Registry) {
	reg.Add(DoubleEncode{})
	reg.Add(UnicodeNorm{})
	reg.Add(PathNorm{})
}
