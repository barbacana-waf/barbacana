package pipeline

import (
	"bytes"
	"net/http/httptest"
	"testing"
)

// TestFlushBufferedNoStatusCaptured pins the fix for a panic where
// runResponsePhase always allocates rw.buf up front and calls
// flushBuffered on any upstream/proxy error (see stages.go
// runResponsePhase). If the proxy errored before ever calling
// WriteHeader — e.g. dial refused — bufStatus is still its zero value
// and flushBuffered must not forward that to the underlying
// ResponseWriter: WriteHeader(0) is not a valid HTTP status and
// net/http (and httptest.ResponseRecorder) panic on it. flushBuffered
// must recognize "nothing was ever captured" and become a no-op so the
// caller's error can propagate and Caddy can emit its own error
// response.
func TestFlushBufferedNoStatusCaptured(t *testing.T) {
	rec := httptest.NewRecorder()
	rm := &responseModifier{
		ResponseWriter: rec,
		buf:            &bytes.Buffer{},
		// bufStatus intentionally left at its zero value: WriteHeader
		// was never called because the upstream dial failed.
	}

	rm.flushBuffered() // must not panic

	if rec.Code != 200 {
		t.Errorf("recorder Code = %d, want unchanged default 200 (no WriteHeader call)", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("recorder Body = %q, want empty (nothing to flush)", rec.Body.String())
	}
	if rm.buf != nil {
		t.Errorf("rm.buf = %v, want nil after flushBuffered", rm.buf)
	}
}

// TestFlushBufferedWithCapturedStatus is the companion case: once a
// real status was captured, flushBuffered must still emit it and the
// buffered body as before the fix.
func TestFlushBufferedWithCapturedStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	buf := &bytes.Buffer{}
	buf.WriteString("hello")
	rm := &responseModifier{
		ResponseWriter: rec,
		buf:            buf,
		bufStatus:      201,
	}

	rm.flushBuffered()

	if rec.Code != 201 {
		t.Errorf("recorder Code = %d, want 201", rec.Code)
	}
	if got := rec.Body.String(); got != "hello" {
		t.Errorf("recorder Body = %q, want %q", got, "hello")
	}
	if rm.buf != nil {
		t.Errorf("rm.buf = %v, want nil after flushBuffered", rm.buf)
	}
}
