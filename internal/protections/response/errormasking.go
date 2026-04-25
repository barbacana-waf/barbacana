// Package response implements stateless response-modification protections
// that operate on the bytes the upstream returned. Today it ships the
// error-page masker (response-error-masking); the existing tier-2
// response inspection protections (response-open-redirect, response-openapi)
// are catalogued but not yet wired.
package response

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/barbacana-waf/barbacana/internal/protections"
)

// ResponseErrorMasking is the canonical protection name. It is exported so
// the pipeline can include it in disable-list checks and audit metadata
// without re-typing the literal.
const ResponseErrorMasking = "response-error-masking"

// MaxInspectBytes caps how much of the upstream body the masker examines.
// Real framework error pages put the trace at the top; if the first 8KB
// look clean the response is treated as a normal application error and
// passed through unmodified.
const MaxInspectBytes = 8 * 1024

// stackFrameRE matches " at <file>.<ext>:<line>" stack frames common to
// Java, Python, Node, and Go traces. The leading whitespace and the file
// extension keep it from matching incidental words like " at https://host:443/".
var stackFrameRE = regexp.MustCompile(`\sat\s+[^\s:]+\.[A-Za-z]+:\d+`)

// substringMarkers are literal substrings that strongly indicate a
// framework or interpreter error page rather than an application-shaped
// error response. Matched case-sensitively because every entry on this
// list is a fixed framework token.
var substringMarkers = []string{
	"Traceback (most recent call last)", // Python
	"Exception in thread",               // Java
	"panic:",                            // Go
	"goroutine ",                        // Go
	"Fatal error:",                      // PHP
	"Stack trace:",                      // PHP
	"SQLSTATE[",                         // PDO
	"ORA-",                              // Oracle
	"<title>500 Internal Server Error",  // generic HTML 5xx page
	"<title>500 -",                      // IIS-style
	"<title>404 Not Found",              // generic HTML 4xx page
	"Microsoft OLE DB",                  // IIS
	"ODBC ",                             // IIS
	"at Object.<anonymous>",             // Node
}

// ShouldMask reports whether body looks like a framework error page. Only
// the first MaxInspectBytes are examined. The check is heuristic — it is
// designed to catch the broad classes called out in the security-control
// spec without trying to catalogue every framework on earth.
func ShouldMask(body []byte) bool {
	if len(body) > MaxInspectBytes {
		body = body[:MaxInspectBytes]
	}
	s := string(body)
	for _, sub := range substringMarkers {
		if strings.Contains(s, sub) {
			return true
		}
	}
	if strings.Contains(s, "MySQL") && strings.Contains(s, "error") {
		return true
	}
	return stackFrameRE.MatchString(s)
}

// IsTextContentType reports whether ct is a content type whose body could
// reasonably contain an error-page string and is therefore worth scanning.
// Binary types (images, fonts, video, application/octet-stream) are skipped
// to avoid pointless work and to preserve byte-for-byte fidelity.
func IsTextContentType(ct string) bool {
	if ct == "" {
		// No upstream content type — be conservative and inspect; a body
		// with no content-type is unusual and often indicates a stack
		// trace dumped raw to the writer.
		return true
	}
	base := ct
	if i := strings.IndexByte(base, ';'); i >= 0 {
		base = base[:i]
	}
	base = strings.ToLower(strings.TrimSpace(base))
	if strings.HasPrefix(base, "text/") {
		return true
	}
	switch base {
	case "application/json",
		"application/xml",
		"application/javascript",
		"application/x-javascript",
		"application/xhtml+xml",
		"application/problem+json",
		"application/problem+xml":
		return true
	}
	return false
}

// IsErrorStatus reports whether the status code is a 4xx or 5xx. The masker
// only inspects error responses — 2xx/3xx are streamed straight through so
// normal traffic incurs no buffering cost.
func IsErrorStatus(code int) bool {
	return code >= 400 && code <= 599
}

// MaskedBody returns the JSON envelope written in place of an upstream
// error page. The request_id correlates the masked client response with
// the unredacted body recorded in the audit log.
func MaskedBody(requestID string) []byte {
	return []byte(`{"error":"An unexpected error occurred","request_id":"` + escapeJSONString(requestID) + `"}`)
}

// escapeJSONString produces a JSON-string-safe rendering of s — quotes,
// backslashes, and control characters are escaped. Used instead of
// encoding/json so we can return raw bytes and keep the response body
// fully deterministic for tests.
func escapeJSONString(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Disabled reports whether response-error-masking is disabled for the
// request's resolved route.
func Disabled(disabled map[string]bool) bool {
	return protections.IsDisabled(ResponseErrorMasking, disabled)
}

// Register exposes ResponseErrorMasking on the registry so disable-list
// validation accepts the canonical name.
func Register(reg *protections.Registry) {
	reg.Add(named{name: ResponseErrorMasking})
}

type named struct{ name string }

func (n named) Name() string     { return n.name }
func (n named) Category() string { return "" }
func (n named) CWE() string      { return protections.CWEForProtection(n.name) }
func (n named) Evaluate(_ context.Context, _ *http.Request) protections.Decision {
	return protections.Allow()
}
