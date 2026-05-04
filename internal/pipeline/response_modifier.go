package pipeline

import (
	"bytes"
	"net/http"
)

// responseModifier intercepts the upstream response so the pipeline can
//   - inject and strip security response headers (always),
//   - buffer status/headers/body up to the route's MaxInspectSize so the
//     WAF response phase can run on the result before any bytes leave
//     the box (only when the route has a response-phase concern).
//
// Buffering is bounded: once the body exceeds MaxInspectSize the
// modifier flushes everything captured so far and switches to direct
// passthrough. That preserves streaming semantics for large or
// long-lived responses (SSE, file downloads) at the cost of skipping
// response-phase WAF inspection for those paths — the same boundary
// the request-phase already uses for body inspection.
type responseModifier struct {
	http.ResponseWriter
	handler     *Handler
	request     *http.Request
	wroteHeader bool

	// Buffering state — present only when the route has at least one
	// active response-phase protection. nil-buf means passthrough.
	buf            *bytes.Buffer
	bufStatus      int
	bufHeader      http.Header
	bufLimit       int
	overflowFlushed bool
}

func (rm *responseModifier) WriteHeader(code int) {
	if rm.wroteHeader {
		return
	}
	rm.wroteHeader = true

	// Strip headers from upstream.
	rm.handler.headerStripper.StripHeaders(rm.ResponseWriter, rm.handler.resolved.Disable)
	// Inject security headers.
	rm.handler.headerInjector.InjectHeaders(rm.ResponseWriter, rm.handler.resolved.Disable)
	// CORS headers for non-preflight requests.
	if rm.handler.corsHandler != nil {
		rm.handler.corsHandler.SetCORSHeaders(rm.ResponseWriter, rm.request)
	}

	if rm.buf != nil {
		// Snapshot the resulting header map at the moment of WriteHeader
		// so the response-phase pass sees exactly what the client would
		// receive. The clone protects against later mutations to
		// rm.ResponseWriter.Header() between Write calls.
		rm.bufStatus = code
		rm.bufHeader = rm.ResponseWriter.Header().Clone()
		return
	}
	rm.ResponseWriter.WriteHeader(code)
}

func (rm *responseModifier) Write(b []byte) (int, error) {
	if !rm.wroteHeader {
		rm.WriteHeader(http.StatusOK)
	}
	if rm.buf == nil || rm.overflowFlushed {
		return rm.ResponseWriter.Write(b)
	}
	if rm.buf.Len()+len(b) > rm.bufLimit {
		// Body too large to inspect; flush captured prefix and stream
		// the rest. Response-phase WAF for this request is skipped.
		rm.flushBuffered()
		rm.overflowFlushed = true
		return rm.ResponseWriter.Write(b)
	}
	return rm.buf.Write(b)
}

func (rm *responseModifier) Unwrap() http.ResponseWriter {
	return rm.ResponseWriter
}

// flushBuffered emits the buffered status, headers (already written to
// rm.ResponseWriter.Header() at WriteHeader time), and body to the
// underlying writer. Used both on overflow and on response-phase pass.
func (rm *responseModifier) flushBuffered() {
	if rm.buf == nil {
		return
	}
	rm.ResponseWriter.WriteHeader(rm.bufStatus)
	if rm.buf.Len() > 0 {
		_, _ = rm.ResponseWriter.Write(rm.buf.Bytes())
	}
	rm.buf = nil
}

// bufferedResponse returns the buffered status, headers, and body for
// response-phase inspection. Returns nil/empty values if buffering is
// disabled or the modifier overflowed.
func (rm *responseModifier) bufferedResponse() (status int, headers http.Header, body []byte, ok bool) {
	if rm.buf == nil || rm.overflowFlushed {
		return 0, nil, nil, false
	}
	return rm.bufStatus, rm.bufHeader, rm.buf.Bytes(), true
}
