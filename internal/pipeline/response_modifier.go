package pipeline

import "net/http"

// responseModifier intercepts WriteHeader to strip and inject response headers.
// Write passes upstream bytes through unmodified — that's the reverse-proxy
// contract; mutating the body would corrupt non-HTML content. See
// .github/codeql/codeql-config.yml for the go/reflected-xss exclusion rationale.
type responseModifier struct {
	http.ResponseWriter
	handler     *Handler
	request     *http.Request
	wroteHeader bool
}

func (rm *responseModifier) WriteHeader(code int) {
	if rm.wroteHeader {
		rm.ResponseWriter.WriteHeader(code)
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

	rm.ResponseWriter.WriteHeader(code)
}

func (rm *responseModifier) Write(b []byte) (int, error) {
	if !rm.wroteHeader {
		rm.WriteHeader(http.StatusOK)
	}
	return rm.ResponseWriter.Write(b)
}

func (rm *responseModifier) Unwrap() http.ResponseWriter {
	return rm.ResponseWriter
}
