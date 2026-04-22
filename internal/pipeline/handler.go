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
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is the Caddy middleware that evaluates all barbacana protections.
type Handler struct {
	RouteID string `json:"route_id,omitempty"`

	resolved       *config.Resolved
	reqValidator   *request.Validator
	multipartVal   *request.MultipartValidator
	resourceVal    *request.ResourceValidator
	crsEngine      *crs.Engine
	openAPIVal     *openapi.Validator
	corsHandler    *headers.CORSHandler
	headerInjector *headers.Injector
	headerStripper *headers.Stripper
	protocolChecks []protections.Protection
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
	h.multipartVal = request.NewMultipartValidator(*res)
	h.resourceVal = request.NewResourceValidator(*res)
	h.corsHandler = headers.NewCORSHandler(res.CORS)
	h.headerInjector = headers.NewInjector(*res)
	h.headerStripper = headers.NewStripper(*res)

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
	ctx := r.Context()
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
	// Wrap the response writer to strip/inject headers and add CORS headers.
	rw := &responseModifier{
		ResponseWriter: w,
		handler:        h,
		request:        r,
		wroteHeader:    false,
	}

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
