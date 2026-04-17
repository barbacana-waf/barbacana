// Package protocol implements native protocol hardening protections.
// These run independently of CRS and before CRS evaluation in the pipeline.
package protocol

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/barbacana-waf/barbacana/internal/protections"
)

// Canonical names.
const (
	RequestSmuggling   = "request-smuggling"
	CRLFInjection      = "crlf-injection"
	NullByteInjection  = "null-byte-injection"
	MethodOverride     = "method-override"
)

// ── request-smuggling ───────────────────────────────────────────────

// Smuggling rejects requests with both Content-Length and Transfer-Encoding.
type Smuggling struct{}

func (Smuggling) Name() string     { return RequestSmuggling }
func (Smuggling) Category() string { return "" }
func (Smuggling) CWE() string      { return "CWE-444" }

func (Smuggling) Evaluate(_ context.Context, r *http.Request) protections.Decision {
	hasCL := r.Header.Get("Content-Length") != ""
	hasTE := r.Header.Get("Transfer-Encoding") != ""
	if hasCL && hasTE {
		return protections.Block(RequestSmuggling,
			"both Content-Length and Transfer-Encoding present")
	}
	return protections.Allow()
}

// ── crlf-injection ──────────────────────────────────────────────────

// CRLF rejects requests containing %0d%0a (CR/LF) in headers, URL, or query.
type CRLF struct{}

func (CRLF) Name() string     { return CRLFInjection }
func (CRLF) Category() string { return "" }
func (CRLF) CWE() string      { return "CWE-93" }

func (CRLF) Evaluate(_ context.Context, r *http.Request) protections.Decision {
	// Check raw URL for encoded CRLF.
	rawURL := r.URL.RawPath + "?" + r.URL.RawQuery
	if containsCRLF(rawURL) {
		return protections.Block(CRLFInjection, "CRLF in URL")
	}
	// Check decoded URL and query.
	if containsCRLF(r.URL.Path) || containsCRLF(r.URL.RawQuery) {
		return protections.Block(CRLFInjection, "CRLF in URL")
	}
	// Check header values.
	for name, values := range r.Header {
		for _, v := range values {
			if containsCRLF(v) {
				return protections.Block(CRLFInjection,
					fmt.Sprintf("CRLF in header %q", name))
			}
		}
	}
	return protections.Allow()
}

func containsCRLF(s string) bool {
	return strings.Contains(s, "\r\n") ||
		strings.Contains(s, "\r") ||
		strings.Contains(s, "\n") ||
		strings.Contains(strings.ToLower(s), "%0d%0a") ||
		strings.Contains(strings.ToLower(s), "%0d") ||
		strings.Contains(strings.ToLower(s), "%0a")
}

// ── null-byte-injection ─────────────────────────────────────────────

// NullByte rejects requests containing %00 / NUL bytes in URL, query, or headers.
type NullByte struct{}

func (NullByte) Name() string     { return NullByteInjection }
func (NullByte) Category() string { return "" }
func (NullByte) CWE() string      { return "CWE-158" }

func (NullByte) Evaluate(_ context.Context, r *http.Request) protections.Decision {
	if strings.ContainsRune(r.URL.Path, '\x00') ||
		strings.ContainsRune(r.URL.RawPath, '\x00') ||
		strings.ContainsRune(r.URL.RawQuery, '\x00') {
		return protections.Block(NullByteInjection, "null byte in URL")
	}
	// Check encoded form.
	if strings.Contains(strings.ToLower(r.URL.RawQuery), "%00") ||
		strings.Contains(strings.ToLower(r.URL.RawPath), "%00") {
		return protections.Block(NullByteInjection, "encoded null byte in URL")
	}
	for name, values := range r.Header {
		for _, v := range values {
			if strings.ContainsRune(v, '\x00') {
				return protections.Block(NullByteInjection,
					fmt.Sprintf("null byte in header %q", name))
			}
		}
	}
	return protections.Allow()
}

// ── method-override ─────────────────────────────────────────────────

// MethodOverrideStrip strips X-HTTP-Method-Override, X-Method-Override,
// and X-HTTP-Method headers. This is a stripping protection, not a
// blocking one — it modifies the request rather than rejecting it.
type MethodOverrideStrip struct{}

func (MethodOverrideStrip) Name() string     { return MethodOverride }
func (MethodOverrideStrip) Category() string { return "" }
func (MethodOverrideStrip) CWE() string      { return "" }

func (MethodOverrideStrip) Evaluate(_ context.Context, r *http.Request) protections.Decision {
	r.Header.Del("X-HTTP-Method-Override")
	r.Header.Del("X-Method-Override")
	r.Header.Del("X-HTTP-Method")
	return protections.Allow()
}

// Register adds all protocol hardening protections to the registry.
func Register(reg *protections.Registry) {
	reg.Add(Smuggling{})
	reg.Add(CRLF{})
	reg.Add(NullByte{})
	reg.Add(MethodOverrideStrip{})
	RegisterSlowRequest(reg)
	RegisterNormalization(reg)
}
