package pipeline

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/barbacana-waf/barbacana/internal/audit"
	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/metrics"
	"github.com/barbacana-waf/barbacana/internal/protections"
	"github.com/barbacana-waf/barbacana/internal/protections/crs"
	"github.com/barbacana-waf/barbacana/internal/protections/headers"
	"github.com/barbacana-waf/barbacana/internal/protections/openapi"
	"github.com/barbacana-waf/barbacana/internal/protections/protocol"
	"github.com/barbacana-waf/barbacana/internal/protections/request"
	"github.com/barbacana-waf/barbacana/internal/protections/response"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is the Caddy middleware that evaluates all barbacana protections.
type Handler struct {
	RouteID string `json:"route_id,omitempty"`

	resolved        *config.Resolved
	reqValidator    *request.Validator
	originValidator *request.OriginValidator
	multipartVal    *request.MultipartValidator
	resourceVal     *request.ResourceValidator
	crsEngine       *crs.Engine
	openAPIVal      *openapi.Validator
	corsHandler     *headers.CORSHandler
	headerInjector  *headers.Injector
	headerStripper  *headers.Stripper
	cookieHardener  *headers.CookieHardener
	protocolChecks  []protections.Protection
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.barbacana",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (h *Handler) Provision(_ caddy.Context) error {
	res := GetConfig(h.RouteID)
	if res == nil {
		return fmt.Errorf("no resolved config for route %q", h.RouteID)
	}
	h.resolved = res

	h.reqValidator = request.NewValidator(*res)
	h.originValidator = request.NewOriginValidator(*res)
	h.multipartVal = request.NewMultipartValidator(*res)
	h.resourceVal = request.NewResourceValidator(*res)
	h.corsHandler = headers.NewCORSHandler(res.CORS)
	h.headerInjector = headers.NewInjector(*res)
	h.headerStripper = headers.NewStripper(*res)
	h.cookieHardener = headers.NewCookieHardener(*res)

	h.protocolChecks = []protections.Protection{
		// Normalization runs first: DoubleEncode uses RawPath before PathNorm clears it.
		protocol.DoubleEncode{},
		protocol.PathNorm{},
		protocol.UnicodeNorm{},
		protocol.Smuggling{},
		protocol.CRLF{},
		protocol.NullByte{},
		protocol.MethodOverrideStrip{},
	}

	engine, err := crs.NewEngine(*res)
	if err != nil {
		return fmt.Errorf("create CRS engine for route %q: %w", h.RouteID, err)
	}
	h.crsEngine = engine

	if res.OpenAPI != nil && res.OpenAPI.Spec != "" {
		val, err := openapi.NewValidator(res.OpenAPI.Spec, *res)
		if err != nil {
			return fmt.Errorf("create OpenAPI validator for route %q: %w", h.RouteID, err)
		}
		h.openAPIVal = val
	}

	return nil
}

func (h *Handler) Validate() error { return nil }

// auditCollector accumulates matched protections, rule IDs, and CWEs
// across pipeline stages for a single request.
type auditCollector struct {
	protections  []string
	rules        []int
	cwes         map[string]bool
	seenProt     map[string]bool
	anomalyScore int
}

func newAuditCollector() *auditCollector {
	return &auditCollector{
		cwes:     map[string]bool{},
		seenProt: map[string]bool{},
	}
}

func (ac *auditCollector) addDecision(d protections.Decision) {
	if !ac.seenProt[d.Protection] {
		ac.seenProt[d.Protection] = true
		ac.protections = append(ac.protections, d.Protection)
		// Look up CWE for this protection.
		if cwe := protections.CWEForProtection(d.Protection); cwe != "" {
			ac.cwes[cwe] = true
		}
	}
	ac.rules = append(ac.rules, d.MatchedRules...)
}

func (ac *auditCollector) addNativeDecision(d protections.Decision, p protections.Protection) {
	if !ac.seenProt[d.Protection] {
		ac.seenProt[d.Protection] = true
		ac.protections = append(ac.protections, d.Protection)
		if cwe := p.CWE(); cwe != "" {
			ac.cwes[cwe] = true
		}
	}
}

func (ac *auditCollector) cweList() []string {
	if len(ac.cwes) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(ac.cwes))
	for c := range ac.cwes {
		out = append(out, c)
	}
	return out
}

func (ac *auditCollector) hasMatches() bool {
	return len(ac.protections) > 0
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Attach a mutable InspectionPath to the request context. Normalization
	// stages (path-normalization, unicode-normalization) write to it;
	// CRS evaluation reads from it. r.URL is never mutated, so Caddy's
	// reverse proxy forwards the client's original path bytes unchanged.
	// See docs/design/conventions.md §"Normalization is for detection".
	ctx := protections.WithInspectionPath(r.Context(), protections.NewInspectionPath(r))
	r = r.WithContext(ctx)

	reqID := getRequestID(r)
	ac := newAuditCollector()
	startTime := time.Now()
	defer func() {
		metrics.RequestDurationOverhead.WithLabelValues(h.resolved.ID).Observe(time.Since(startTime).Seconds())
	}()

	// ── Stage 1: request validation (size, methods, content-type gating) ──
	if d := h.reqValidator.ValidateRequest(ctx, r); d.Block {
		ac.addDecision(d)
		if h.resolved.Mode != config.ModeDetect {
			metrics.RequestsTotal.WithLabelValues(h.resolved.ID, "blocked").Inc()
			metrics.RequestsBlockedTotal.WithLabelValues(h.resolved.ID, d.Protection).Inc()
			h.emitAudit(ctx, r, reqID, ac, "blocked", http.StatusForbidden)
			h.writeDecision(w, reqID, d)
			return nil
		}
		slog.DebugContext(ctx, "detect-only: request validation", "protection", d.Protection, "reason", d.Reason)
	}

	// ── Stage 1b: csrf-origin-check on state-changing methods ──
	// Runs alongside request validation: it inspects only Origin/Referer
	// and the resolved allow-set, so it has no body or normalisation
	// dependency and is cheap enough to run before protocol hardening.
	if d := h.originValidator.Validate(ctx, r); d.Block {
		ac.addDecision(d)
		if h.resolved.Mode != config.ModeDetect {
			metrics.RequestsTotal.WithLabelValues(h.resolved.ID, "blocked").Inc()
			metrics.RequestsBlockedTotal.WithLabelValues(h.resolved.ID, d.Protection).Inc()
			h.emitAudit(ctx, r, reqID, ac, "blocked", http.StatusForbidden)
			h.writeBlock(w, reqID, http.StatusForbidden)
			return nil
		}
		slog.DebugContext(ctx, "detect-only: origin check", "protection", d.Protection, "reason", d.Reason)
	}

	// ── Stage 2: protocol hardening ──
	for _, p := range h.protocolChecks {
		if protections.IsDisabled(p.Name(), h.resolved.Disable) {
			continue
		}
		if d := p.Evaluate(ctx, r); d.Block {
			ac.addNativeDecision(d, p)
			if h.resolved.Mode != config.ModeDetect {
				metrics.RequestsTotal.WithLabelValues(h.resolved.ID, "blocked").Inc()
				metrics.RequestsBlockedTotal.WithLabelValues(h.resolved.ID, d.Protection).Inc()
				h.emitAudit(ctx, r, reqID, ac, "blocked", http.StatusForbidden)
				h.writeBlock(w, reqID, http.StatusForbidden)
				return nil
			}
			slog.DebugContext(ctx, "detect-only: protocol hardening", "protection", d.Protection, "reason", d.Reason)
		}
	}

	// ── Stage 3-5: body analysis ──
	// Buffer the body once for body parsing, resource checks, and CRS.
	var bodyBytes []byte
	if r.Body != nil && r.ContentLength != 0 {
		var err error
		bodyBytes, err = io.ReadAll(r.Body)
		if err == nil {
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	// Decompression ratio check.
	enc := strings.ToLower(r.Header.Get("Content-Encoding"))
	if (enc == "gzip" || enc == "deflate") && len(bodyBytes) > 0 {
		// Restore body for resource check.
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		_, rd := h.resourceVal.CheckDecompression(ctx, r)
		if rd.Block {
			ac.addDecision(rd)
			metrics.DecompressionRejectedTotal.WithLabelValues(h.resolved.ID).Inc()
			if h.resolved.Mode != config.ModeDetect {
				metrics.RequestsTotal.WithLabelValues(h.resolved.ID, "blocked").Inc()
				metrics.RequestsBlockedTotal.WithLabelValues(h.resolved.ID, rd.Protection).Inc()
				h.emitAudit(ctx, r, reqID, ac, "blocked", http.StatusForbidden)
				h.writeBlock(w, reqID, http.StatusForbidden)
				return nil
			}
			slog.DebugContext(ctx, "detect-only: decompression limit", "reason", rd.Reason)
		}
		// Restore body for subsequent stages.
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// JSON depth / XML entity checks on the raw body.
	if len(bodyBytes) > 0 {
		ct := r.Header.Get("Content-Type")
		if strings.Contains(ct, "json") {
			if d := h.reqValidator.ValidateJSONBody(ctx, bodyBytes); d.Block {
				ac.addDecision(d)
				if h.resolved.Mode != config.ModeDetect {
					metrics.RequestsTotal.WithLabelValues(h.resolved.ID, "blocked").Inc()
					metrics.RequestsBlockedTotal.WithLabelValues(h.resolved.ID, d.Protection).Inc()
					h.emitAudit(ctx, r, reqID, ac, "blocked", http.StatusForbidden)
					h.writeBlock(w, reqID, http.StatusForbidden)
					return nil
				}
				slog.DebugContext(ctx, "detect-only: JSON body", "protection", d.Protection, "reason", d.Reason)
			}
		}
		if strings.Contains(ct, "xml") {
			if d := h.reqValidator.ValidateXMLBody(ctx, bodyBytes); d.Block {
				ac.addDecision(d)
				if h.resolved.Mode != config.ModeDetect {
					metrics.RequestsTotal.WithLabelValues(h.resolved.ID, "blocked").Inc()
					metrics.RequestsBlockedTotal.WithLabelValues(h.resolved.ID, d.Protection).Inc()
					h.emitAudit(ctx, r, reqID, ac, "blocked", http.StatusForbidden)
					h.writeBlock(w, reqID, http.StatusForbidden)
					return nil
				}
				slog.DebugContext(ctx, "detect-only: XML body", "protection", d.Protection, "reason", d.Reason)
			}
		}
	}

	// ── Stage 6: multipart file upload checks ──
	if h.resolved.RunMultipartParser && len(bodyBytes) > 0 {
		ct := r.Header.Get("Content-Type")
		if strings.Contains(ct, "multipart/form-data") {
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			if d := h.multipartVal.Validate(ctx, r); d.Block {
				ac.addDecision(d)
				if h.resolved.Mode != config.ModeDetect {
					metrics.RequestsTotal.WithLabelValues(h.resolved.ID, "blocked").Inc()
					metrics.RequestsBlockedTotal.WithLabelValues(h.resolved.ID, d.Protection).Inc()
					h.emitAudit(ctx, r, reqID, ac, "blocked", http.StatusForbidden)
					h.writeBlock(w, reqID, http.StatusForbidden)
					return nil
				}
				slog.DebugContext(ctx, "detect-only: multipart", "protection", d.Protection, "reason", d.Reason)
			}
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	// ── Stage 7: CORS preflight ──
	if h.corsHandler != nil && h.corsHandler.HandlePreflight(w, r) {
		return nil
	}

	// ── Stage 8: OpenAPI validation ──
	if h.openAPIVal != nil {
		if d := h.openAPIVal.Validate(ctx, r); d.Block {
			ac.addDecision(d)
			metrics.OpenAPIValidationTotal.WithLabelValues(h.resolved.ID, "fail").Inc()
			if h.resolved.Mode != config.ModeDetect {
				metrics.RequestsTotal.WithLabelValues(h.resolved.ID, "blocked").Inc()
				metrics.RequestsBlockedTotal.WithLabelValues(h.resolved.ID, d.Protection).Inc()
				code := openAPIStatusCode(d.Protection)
				h.emitAudit(ctx, r, reqID, ac, "blocked", code)
				h.writeBlock(w, reqID, code)
				return nil
			}
			slog.DebugContext(ctx, "detect-only: openapi", "protection", d.Protection, "reason", d.Reason)
		} else {
			metrics.OpenAPIValidationTotal.WithLabelValues(h.resolved.ID, "pass").Inc()
		}
	}

	// ── Stage 9: CRS evaluation ──
	// Restore body for CRS.
	if len(bodyBytes) > 0 {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	crsResult := h.crsEngine.Evaluate(ctx, r)
	ac.anomalyScore = crsResult.AnomalyScore
	metrics.AnomalyScoreHistogram.WithLabelValues(h.resolved.ID).Observe(float64(crsResult.AnomalyScore))
	for _, d := range crsResult.Decisions {
		if d.Block {
			ac.addDecision(d)
			slog.DebugContext(ctx, "block: CRS", "protection", d.Protection, "reason", d.Reason)
			if h.resolved.Mode != config.ModeDetect {
				metrics.RequestsTotal.WithLabelValues(h.resolved.ID, "blocked").Inc()
				metrics.RequestsBlockedTotal.WithLabelValues(h.resolved.ID, d.Protection).Inc()
				h.emitAudit(ctx, r, reqID, ac, "blocked", http.StatusForbidden)
				h.writeBlock(w, reqID, http.StatusForbidden)
				return nil
			}
		} else if d.Protection != "" {
			// In detect-only mode, CRS returns non-blocking decisions for
			// matched rules. Collect them for the audit log.
			ac.addDecision(d)
		}
	}

	// Emit detect-only audit entry if any protections matched.
	if ac.hasMatches() {
		metrics.RequestsTotal.WithLabelValues(h.resolved.ID, "detected").Inc()
		for _, p := range ac.protections {
			metrics.RequestsBlockedTotal.WithLabelValues(h.resolved.ID, p).Inc()
		}
		h.emitAudit(ctx, r, reqID, ac, "detected", http.StatusOK)
	} else {
		metrics.RequestsTotal.WithLabelValues(h.resolved.ID, "allowed").Inc()
	}

	// Restore body for the reverse proxy.
	if len(bodyBytes) > 0 {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// ── Stage 10-11: proxy + response modification ──
	// Wrap the response writer to strip/inject headers, harden cookies,
	// inject CORS-safe Vary values, and (for 4xx/5xx text responses)
	// mask framework error pages.
	rw := &responseModifier{
		ResponseWriter: w,
		handler:        h,
		request:        r,
		requestID:      reqID,
	}

	// Finalize drains any buffered body and writes the masked replacement
	// or flushes the original bytes. It must run on every exit path,
	// including panics — otherwise a mid-write panic would leave the
	// client with an incomplete response and no status. On panic we
	// Discard first so Caddy's recover middleware runs against a clean
	// slate (the underlying ResponseWriter has not yet been touched
	// while the masker is still inspecting, so dropping partial state
	// lets recover emit a real 500 instead of a truncated error body).
	defer func() {
		if p := recover(); p != nil {
			rw.Discard()
			panic(p)
		}
		rw.Finalize()
	}()
	return next.ServeHTTP(rw, r)
}

// emitAudit writes a structured audit log entry for the request.
func (h *Handler) emitAudit(ctx context.Context, r *http.Request, reqID string, ac *auditCollector, action string, responseCode int) {
	sourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if sourceIP == "" {
		sourceIP = r.RemoteAddr
	}

	matchedRules := ac.rules
	if matchedRules == nil {
		matchedRules = []int{}
	}
	matchedProtections := ac.protections
	if matchedProtections == nil {
		matchedProtections = []string{}
	}

	audit.Emit(ctx, audit.Entry{
		Timestamp:          time.Now(),
		RequestID:          reqID,
		SourceIP:           sourceIP,
		Method:             r.Method,
		Host:               r.Host,
		Path:               r.URL.Path,
		RouteID:            h.resolved.ID,
		MatchedProtections: matchedProtections,
		MatchedRules:       matchedRules,
		CWE:                ac.cweList(),
		AnomalyScore:       ac.anomalyScore,
		Action:             action,
		ResponseCode:       responseCode,
	})
}

// responseModifier intercepts WriteHeader to strip and inject response
// headers, harden Set-Cookie attributes, inject CORS-related Vary values,
// and — for 4xx/5xx text responses — mask upstream framework error pages.
//
// The reverse-proxy contract is to forward upstream body bytes unchanged.
// The masker is a deliberate exception: when a stack trace or framework
// error page is detected the body is replaced with a generic JSON envelope
// before the bytes leave the process. 2xx/3xx responses, binary content,
// and bodies whose first response.MaxInspectBytes contain no error
// markers are passed through verbatim. See
// .github/codeql/codeql-config.yml for the go/reflected-xss exclusion
// rationale.
//
// Buffering is bounded at response.MaxInspectBytes (8KB). As soon as the
// inspection window fills, the mask/pass decision is made and further
// bytes either stream directly (pass) or are dropped (mask replacement
// body is written in Finalize). This bounds memory and closes an
// otherwise exploitable gap where a large upstream error body could
// skip inspection by padding past the buffer cap.
type responseModifier struct {
	http.ResponseWriter
	handler     *Handler
	request     *http.Request
	requestID   string
	wroteHeader bool
	statusCode  int

	maskState maskState
	maskBuf   bytes.Buffer
	finalized bool
}

// maskState is the state machine that governs how Write handles bytes
// from the upstream. It is set once in WriteHeader (based on status and
// content-type) and transitions at most once more — either when the
// inspection window fills during Write or when Finalize runs on a body
// smaller than the window.
type maskState int

const (
	// maskStateInactive means the response is not a candidate for
	// masking — 2xx/3xx, binary content, or response-error-masking
	// disabled for the route. Writes stream straight through.
	maskStateInactive maskState = iota

	// maskStateInspecting means the response is a candidate and Write
	// is accumulating bytes into maskBuf until it reaches
	// response.MaxInspectBytes. The underlying ResponseWriter has not
	// yet seen WriteHeader — we hold it back so the masker can still
	// rewrite Content-Type, drop Content-Encoding, etc.
	maskStateInspecting

	// maskStateWillMask means the inspection window matched a framework
	// marker. Subsequent Write calls discard their bytes; Finalize
	// writes the replacement body.
	maskStateWillMask

	// maskStatePassThrough means inspection found no marker and the
	// buffered bytes have been flushed to the underlying ResponseWriter.
	// Subsequent Write calls stream directly.
	maskStatePassThrough
)

func (rm *responseModifier) WriteHeader(code int) {
	if rm.wroteHeader {
		rm.ResponseWriter.WriteHeader(code)
		return
	}
	rm.wroteHeader = true
	rm.statusCode = code

	// Decide whether to buffer the body for error-page masking. The
	// status code and content type are both fixed by the time the
	// upstream calls WriteHeader, so this is the natural decision point.
	if !response.Disabled(rm.handler.resolved.Disable) &&
		response.IsErrorStatus(code) &&
		response.IsTextContentType(rm.Header().Get("Content-Type")) {
		rm.maskState = maskStateInspecting
		// Defer the underlying WriteHeader until Finalize or the first
		// Write that fills the inspection window — we may need to
		// rewrite Content-Type, drop Content-Length, and replace the
		// body. The status code is preserved either way.
		return
	}

	rm.applyResponseHeaders()
	rm.ResponseWriter.WriteHeader(code)
}

func (rm *responseModifier) Write(b []byte) (int, error) {
	if !rm.wroteHeader {
		rm.WriteHeader(http.StatusOK)
	}
	switch rm.maskState {
	case maskStateWillMask:
		// Decision already made: drop the bytes. Report success so the
		// upstream proceeds as if the write had happened.
		return len(b), nil
	case maskStateInspecting:
		// Fast path: inspection window still has room for b.
		if rm.maskBuf.Len()+len(b) < response.MaxInspectBytes {
			return rm.maskBuf.Write(b)
		}
		// b fills or overflows the inspection window — decide now.
		// First, absorb exactly the bytes that complete the window so
		// ShouldMask sees the full MaxInspectBytes of context.
		want := response.MaxInspectBytes - rm.maskBuf.Len()
		if want > len(b) {
			want = len(b)
		}
		if want > 0 {
			rm.maskBuf.Write(b[:want])
		}
		if response.ShouldMask(rm.maskBuf.Bytes()) {
			rm.maskState = maskStateWillMask
			// Keep maskBuf for the audit preview; do not grow it further.
			return len(b), nil
		}
		// No match — flush buffered bytes and stream the remainder of b
		// directly. This also transitions to pass-through for future writes.
		rm.flushInspectionBuffer()
		if rest := b[want:]; len(rest) > 0 {
			n, err := rm.ResponseWriter.Write(rest)
			return want + n, err
		}
		return want, nil
	default: // inactive, pass-through
		return rm.ResponseWriter.Write(b)
	}
}

func (rm *responseModifier) Unwrap() http.ResponseWriter {
	return rm.ResponseWriter
}

// Finalize is called by the pipeline after next.ServeHTTP returns. It
// drains the mask buffer (if any) and decides whether to mask. No-op
// when the response was streamed straight through.
func (rm *responseModifier) Finalize() {
	if rm.finalized {
		return
	}
	rm.finalized = true
	switch rm.maskState {
	case maskStateInspecting:
		// Body finished before filling the inspection window — decide now.
		if response.ShouldMask(rm.maskBuf.Bytes()) {
			rm.writeMaskedReplacement()
			return
		}
		rm.flushInspectionBuffer()
	case maskStateWillMask:
		rm.writeMaskedReplacement()
	}
}

// Discard abandons any buffered state without touching the underlying
// ResponseWriter. Called from the pipeline's panic handler so Caddy's
// recover middleware runs against a clean slate: while the masker is
// inspecting or has decided to mask, the real WriteHeader has not yet
// fired, so the framework can still emit a 500. Flushing a partial
// buffer in that state would produce a truncated body with a
// corresponding status — strictly worse than an empty failure because
// it looks like a complete response to the client.
func (rm *responseModifier) Discard() {
	rm.finalized = true
	rm.maskState = maskStateInactive
	rm.maskBuf.Reset()
}

// applyResponseHeaders runs the response-modifying protections that touch
// only headers: strip, inject, cookie-harden, CORS, vary. Called once per
// response, just before the underlying WriteHeader.
func (rm *responseModifier) applyResponseHeaders() {
	rm.handler.headerStripper.StripHeaders(rm.ResponseWriter, rm.handler.resolved.Disable)
	rm.handler.headerInjector.InjectHeaders(rm.ResponseWriter, rm.handler.resolved.Disable)
	rm.handler.cookieHardener.HardenCookies(rm.Header(), rm.handler.resolved.Disable)
	if rm.handler.corsHandler != nil {
		rm.handler.corsHandler.SetCORSHeaders(rm.ResponseWriter, rm.request)
		rm.handler.corsHandler.InjectVary(rm.Header(), rm.handler.resolved.Disable)
	}
}

// flushInspectionBuffer sends the buffered status, headers, and body
// unchanged, then transitions to pass-through so subsequent writes
// stream directly. Used when the inspection window yielded no match.
func (rm *responseModifier) flushInspectionBuffer() {
	rm.maskState = maskStatePassThrough
	rm.applyResponseHeaders()
	rm.ResponseWriter.WriteHeader(rm.statusCode)
	if rm.maskBuf.Len() > 0 {
		_, _ = rm.ResponseWriter.Write(rm.maskBuf.Bytes())
		rm.maskBuf.Reset()
	}
}

// writeMaskedReplacement sends the generic JSON error body in place of the
// upstream's framework error page. Content-Length is rewritten because the
// payload size changed; Content-Encoding is dropped because the
// replacement is plain UTF-8 and the upstream's encoding (gzip/br/...)
// no longer applies.
func (rm *responseModifier) writeMaskedReplacement() {
	body := response.MaskedBody(rm.requestID)

	hdr := rm.Header()
	hdr.Set("Content-Type", "application/json; charset=utf-8")
	hdr.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	hdr.Del("Content-Encoding")
	hdr.Del("Transfer-Encoding")

	rm.applyResponseHeaders()
	rm.ResponseWriter.WriteHeader(rm.statusCode)
	_, _ = rm.ResponseWriter.Write(body)

	metrics.RequestsBlockedTotal.WithLabelValues(rm.handler.resolved.ID, response.ResponseErrorMasking).Inc()
	rm.emitMaskAudit()
}

// emitMaskAudit records that an upstream error body was masked. The
// original body (truncated) goes into the audit entry so the operator can
// debug what the upstream really returned without seeing it leak to the
// client.
func (rm *responseModifier) emitMaskAudit() {
	r := rm.request
	sourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if sourceIP == "" {
		sourceIP = r.RemoteAddr
	}
	const previewMax = 1024
	preview := rm.maskBuf.Bytes()
	if len(preview) > previewMax {
		preview = preview[:previewMax]
	}
	cwe := protections.CWEForProtection(response.ResponseErrorMasking)
	cweList := []string{}
	if cwe != "" {
		cweList = []string{cwe}
	}
	audit.Emit(r.Context(), audit.Entry{
		Timestamp:          time.Now(),
		RequestID:          rm.requestID,
		SourceIP:           sourceIP,
		Method:             r.Method,
		Host:               r.Host,
		Path:               r.URL.Path,
		RouteID:            rm.handler.resolved.ID,
		MatchedProtections: []string{response.ResponseErrorMasking},
		MatchedRules:       []int{},
		CWE:                cweList,
		Action:             "masked",
		ResponseCode:       rm.statusCode,
	})
	slog.DebugContext(r.Context(), "response-error-masking",
		"request_id", rm.requestID,
		"status", rm.statusCode,
		"original_body_preview", string(preview),
	)
}

// writeDecision writes an error response based on the protection that triggered.
func (h *Handler) writeDecision(w http.ResponseWriter, reqID string, d protections.Decision) {
	code := http.StatusForbidden
	msg := "blocked"
	switch d.Protection {
	case request.AllowedMethods:
		code = http.StatusMethodNotAllowed
		msg = "method not allowed"
	case request.RequireHostHeader:
		code = http.StatusBadRequest
		msg = "bad request"
	case request.MaxBodySize:
		code = http.StatusRequestEntityTooLarge
		msg = "payload too large"
	case request.MaxURLLength:
		code = http.StatusRequestURITooLong
		msg = "URI too long"
	case request.MaxHeaderSize, request.MaxHeaderCount:
		code = 431
		msg = "header too large"
	case request.RequireContentType:
		code = http.StatusUnsupportedMediaType
		msg = "unsupported media type"
	}
	if h.resolved.ErrorTemplate != nil {
		protections.WriteCustomBlockResponse(w, reqID, code, h.resolved.ErrorTemplate)
		return
	}
	protections.WriteErrorResponse(w, reqID, code, msg)
}

func openAPIStatusCode(protection string) int {
	switch protection {
	case openapi.OpenAPIPath:
		return http.StatusNotFound
	case openapi.OpenAPIMethod:
		return http.StatusMethodNotAllowed
	case openapi.OpenAPIBody, openapi.OpenAPIParams:
		return http.StatusUnprocessableEntity
	case openapi.OpenAPIContentType:
		return http.StatusUnsupportedMediaType
	default:
		return http.StatusForbidden
	}
}

func getRequestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-Id"); id != "" {
		return id
	}
	// Generate a simple unique ID from the Caddy request UUID if available.
	if v, ok := r.Context().Value(caddyhttp.VarsCtxKey).(map[string]any); ok {
		if uuid, exists := v["uuid"]; exists {
			return fmt.Sprint(uuid)
		}
	}
	return fmt.Sprintf("%p", r)
}

// writeBlock writes a block response, using the custom error template if configured.
func (h *Handler) writeBlock(w http.ResponseWriter, reqID string, statusCode int) {
	if h.resolved.ErrorTemplate != nil {
		protections.WriteCustomBlockResponse(w, reqID, statusCode, h.resolved.ErrorTemplate)
		return
	}
	protections.WriteBlockResponse(w, reqID, statusCode)
}

var _ caddyhttp.MiddlewareHandler = (*Handler)(nil)
