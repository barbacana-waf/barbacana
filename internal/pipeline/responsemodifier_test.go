package pipeline

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/protections/headers"
	"github.com/barbacana-waf/barbacana/internal/protections/response"
)

// newTestModifier builds a responseModifier backed by an httptest recorder
// with the minimum Handler surface the modifier touches: a resolved
// config for the disable map and ID, plus the three header protections.
// CORS is left nil — the tests here are about the masker's state machine,
// not CORS negotiation.
func newTestModifier(t *testing.T, disable []string) (*responseModifier, *httptest.ResponseRecorder) {
	t.Helper()
	disMap := map[string]bool{}
	for _, d := range disable {
		disMap[d] = true
	}
	res := &config.Resolved{
		ID:      "test",
		Disable: disMap,
		ResponseHeaders: config.ResolvedHeaders{
			Preset: "moderate",
			Inject: map[string]string{},
		},
	}
	h := &Handler{
		resolved:       res,
		headerStripper: headers.NewStripper(*res),
		headerInjector: headers.NewInjector(*res),
		cookieHardener: headers.NewCookieHardener(*res),
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com/x", nil)
	return &responseModifier{
		ResponseWriter: rec,
		handler:        h,
		request:        req,
		requestID:      "req-test",
	}, rec
}

// TestResponseModifier_SmallBodyMask covers the Finalize-time decision
// for bodies that fit inside the inspection window. The mask verdict is
// reached from maskStateInspecting, not from a window-fill transition.
func TestResponseModifier_SmallBodyMask(t *testing.T) {
	rm, rec := newTestModifier(t, nil)
	rm.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rm.WriteHeader(http.StatusInternalServerError)
	rm.Write([]byte("panic: boom\ngoroutine 1 [running]"))
	rm.Finalize()

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"error":"An unexpected error occurred"`) {
		t.Errorf("body not masked: %q", body)
	}
	if strings.Contains(body, "panic:") {
		t.Errorf("original stack trace leaked: %q", body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json; charset=utf-8", ct)
	}
}

// TestResponseModifier_SmallBodyPass covers the complementary path:
// small body, inspection yields no marker, original body flushed intact.
func TestResponseModifier_SmallBodyPass(t *testing.T) {
	rm, rec := newTestModifier(t, nil)
	rm.Header().Set("Content-Type", "application/json")
	rm.WriteHeader(http.StatusInternalServerError)
	clean := `{"error":"validation failed","code":"E_BAD_INPUT"}`
	rm.Write([]byte(clean))
	rm.Finalize()

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if got := rec.Body.String(); got != clean {
		t.Errorf("body mutated:\n got:  %q\n want: %q", got, clean)
	}
}

// TestResponseModifier_WindowFillMask forces the decision through the
// Write fast-path: a marker sits at the front of the body but the body
// is much larger than the inspection window. The machine must mask and
// must NOT leak any of the trailing bytes.
func TestResponseModifier_WindowFillMask(t *testing.T) {
	rm, rec := newTestModifier(t, nil)
	rm.Header().Set("Content-Type", "text/plain")
	rm.WriteHeader(http.StatusInternalServerError)

	// Marker at byte 0, then filler to well past MaxInspectBytes. Written
	// in a single Write so the transition happens inside one call.
	body := "panic: oh no\n" + strings.Repeat("A", 3*response.MaxInspectBytes)
	rm.Write([]byte(body))
	// A second Write after the window filled should be silently dropped.
	rm.Write([]byte("SECRET LEAK"))
	rm.Finalize()

	got := rec.Body.String()
	if !strings.Contains(got, `"error":"An unexpected error occurred"`) {
		t.Errorf("response not masked: %q", got[:min(len(got), 200)])
	}
	if strings.Contains(got, "AAAA") {
		t.Error("padding bytes leaked past the inspection window")
	}
	if strings.Contains(got, "SECRET LEAK") {
		t.Error("post-decision writes were not dropped")
	}
}

// TestResponseModifier_WindowFillPass covers the "no match, flush and
// stream" transition: body has no markers, exceeds the window, so the
// modifier must flush the buffer and stream the rest unmodified.
func TestResponseModifier_WindowFillPass(t *testing.T) {
	rm, rec := newTestModifier(t, nil)
	rm.Header().Set("Content-Type", "text/html")
	rm.WriteHeader(http.StatusNotFound)

	// 12KB of benign HTML, no framework markers.
	body := strings.Repeat("<p>not found</p>\n", 12*1024/len("<p>not found</p>\n"))
	rm.Write([]byte(body))
	rm.Write([]byte("<!-- tail -->"))
	rm.Finalize()

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	got := rec.Body.String()
	if !strings.HasPrefix(got, "<p>not found</p>") {
		t.Errorf("buffered prefix missing: %q", got[:min(len(got), 64)])
	}
	if !strings.HasSuffix(got, "<!-- tail -->") {
		t.Errorf("streamed tail missing: got suffix %q", got[max(0, len(got)-32):])
	}
	if len(got) < len(body)+len("<!-- tail -->") {
		t.Errorf("truncated: got %d bytes, want >= %d", len(got), len(body)+len("<!-- tail -->"))
	}
}

// TestResponseModifier_2xxPassthrough verifies that a 200 response
// carrying bytes that would otherwise trigger the masker is streamed
// unchanged — the masker only inspects error statuses.
func TestResponseModifier_2xxPassthrough(t *testing.T) {
	rm, rec := newTestModifier(t, nil)
	rm.Header().Set("Content-Type", "text/plain")
	rm.WriteHeader(http.StatusOK)
	doc := "Documentation mentions panic: and goroutine leaks."
	rm.Write([]byte(doc))
	rm.Finalize()

	if got := rec.Body.String(); got != doc {
		t.Errorf("2xx body mutated: %q", got)
	}
}

// TestResponseModifier_BinaryPassthrough verifies that a 5xx response
// with a binary content type skips inspection entirely.
func TestResponseModifier_BinaryPassthrough(t *testing.T) {
	rm, rec := newTestModifier(t, nil)
	rm.Header().Set("Content-Type", "application/octet-stream")
	rm.WriteHeader(http.StatusInternalServerError)
	// A stack-trace-looking byte sequence that happens to appear in a
	// binary payload must not be treated as an error page.
	payload := []byte("panic: \x00\x01\x02 binary")
	rm.Write(payload)
	rm.Finalize()

	if got := rec.Body.Bytes(); string(got) != string(payload) {
		t.Errorf("binary body mutated: %q", got)
	}
}

// TestResponseModifier_Disabled verifies that the disable list opts a
// route out of masking even when every other gate would match.
func TestResponseModifier_Disabled(t *testing.T) {
	rm, rec := newTestModifier(t, []string{response.ResponseErrorMasking})
	rm.Header().Set("Content-Type", "text/plain")
	rm.WriteHeader(http.StatusInternalServerError)
	trace := "panic: boom\ngoroutine 1 [running]"
	rm.Write([]byte(trace))
	rm.Finalize()

	if got := rec.Body.String(); got != trace {
		t.Errorf("body masked despite disable: %q", got)
	}
}

// TestResponseModifier_Discard simulates the panic path: WriteHeader +
// Write have put the modifier in a buffering state, then Discard runs
// in place of Finalize. The underlying writer must still be untouched
// so Caddy's recover middleware can emit a fresh response.
func TestResponseModifier_Discard(t *testing.T) {
	rm, rec := newTestModifier(t, nil)
	rm.Header().Set("Content-Type", "text/plain")
	rm.WriteHeader(http.StatusInternalServerError)
	rm.Write([]byte("panic: mid-write"))

	rm.Discard()
	// Finalize after Discard must be a no-op — the finalized flag guards it.
	rm.Finalize()

	if rec.Code != http.StatusOK {
		// httptest.ResponseRecorder.Code defaults to 200 when WriteHeader
		// never fires on the underlying writer. Any other value means the
		// buffer leaked out.
		t.Errorf("underlying WriteHeader fired after Discard: code = %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("underlying Write fired after Discard: body = %q", rec.Body.String())
	}
}

// TestResponseModifier_WriteWithoutWriteHeader covers the defaulting
// path: an upstream that writes body bytes without an explicit
// WriteHeader must be treated as a 200 and stream through.
func TestResponseModifier_WriteWithoutWriteHeader(t *testing.T) {
	rm, rec := newTestModifier(t, nil)
	rm.Write([]byte("hello"))
	rm.Finalize()

	if rec.Code != http.StatusOK {
		t.Errorf("default status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "hello" {
		t.Errorf("body = %q, want %q", got, "hello")
	}
}

// TestResponseModifier_MaskRewritesContentLength confirms that when the
// masker replaces the body, Content-Length is rewritten to match the
// replacement and Content-Encoding is dropped — otherwise the client
// would try to decompress a plain UTF-8 JSON envelope.
func TestResponseModifier_MaskRewritesContentLength(t *testing.T) {
	rm, rec := newTestModifier(t, nil)
	rm.Header().Set("Content-Type", "text/plain")
	rm.Header().Set("Content-Encoding", "gzip")
	rm.Header().Set("Content-Length", "9999")
	rm.WriteHeader(http.StatusInternalServerError)
	rm.Write([]byte("panic: x"))
	rm.Finalize()

	if ce := rec.Header().Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding not dropped: %q", ce)
	}
	wantLen := len(rec.Body.Bytes())
	if cl := rec.Header().Get("Content-Length"); cl == "" || cl == "9999" {
		t.Errorf("Content-Length not rewritten: %q (body is %d bytes)", cl, wantLen)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
