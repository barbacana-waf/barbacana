package pipeline

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
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

// ServeHTTP runs the request through the pipeline as a top-down stage table.
// Each stage owns its own evaluation, audit accumulation, and stage-specific
// metrics; the runner handles the common block path (metrics, audit emit,
// response write) so the body of this function reads as the pipeline.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Attach a mutable InspectionPath to the request context. Normalization
	// stages (path-normalization, unicode-normalization) write to it; CRS
	// reads from it. r.URL is never mutated, so Caddy's reverse proxy
	// forwards the client's original path bytes unchanged.
	ctx := protections.WithInspectionPath(r.Context(), protections.NewInspectionPath(r))
	r = r.WithContext(ctx)

	reqID := getRequestID(r)
	ac := newAuditCollector()
	startTime := time.Now()
	defer func() {
		metrics.RequestDurationOverhead.WithLabelValues(h.resolved.ID).Observe(time.Since(startTime).Seconds())
	}()

	stages := []stage{
		{name: "request-validation", run: h.runRequestValidation},
		{name: "protocol-hardening", run: h.runProtocolChecks},
		{name: "body-decompression", run: h.runDecompression, needsBody: true},
		{name: "body-json-xml", run: h.runJSONXMLBody, needsBody: true},
		{name: "multipart", run: h.runMultipart, needsBody: true},
		{name: "cors-preflight", run: h.runCORSPreflight},
		{name: "openapi", run: h.runOpenAPI},
		{name: "crs", run: h.runCRS, needsBody: true},
	}
	var body []byte
	bodyBuffered := false
	for _, s := range stages {
		if s.needsBody && !bodyBuffered {
			body = readBody(r)
			bodyBuffered = true
		}
		if h.runStage(ctx, w, r, reqID, ac, body, s) {
			return nil
		}
	}

	// Detect-only summary: emit one audit entry if any stage matched.
	// Detect-mode matches do not bump RequestsBlockedTotal (nothing was
	// blocked); each matched protection bumps DetectedThreatsTotal — the
	// same counter the runner bumps in blocking mode — so per-protection
	// threat counts are mode-independent.
	if ac.hasMatches() {
		metrics.RequestsTotal.WithLabelValues(h.resolved.ID, "detected").Inc()
		for _, p := range ac.protections {
			metrics.DetectedThreatsTotal.WithLabelValues(h.resolved.ID, p).Inc()
		}
		h.emitAudit(ctx, r, reqID, ac, "detected", http.StatusOK)
	} else {
		metrics.RequestsTotal.WithLabelValues(h.resolved.ID, "allowed").Inc()
	}

	// Restore body for the reverse proxy.
	if len(body) > 0 {
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	rw := &responseModifier{
		ResponseWriter: w,
		handler:        h,
		request:        r,
		wroteHeader:    false,
	}
	return next.ServeHTTP(rw, r)
}

// auditCollector accumulates matched protections, rule IDs, and CWEs across
// pipeline stages for a single request.
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

// addDecision records a decision whose CWE is sourced from the canonical
// catalog (CRS-mapped or request-side protections).
func (ac *auditCollector) addDecision(d protections.Decision) {
	if !ac.seenProt[d.Protection] {
		ac.seenProt[d.Protection] = true
		ac.protections = append(ac.protections, d.Protection)
		if cwe := protections.CWEForProtection(d.Protection); cwe != "" {
			ac.cwes[cwe] = true
		}
	}
	ac.rules = append(ac.rules, d.MatchedRules...)
}

// addNativeDecision records a decision whose CWE is sourced from the
// Protection itself (native protocol checks).
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

func (ac *auditCollector) hasMatches() bool { return len(ac.protections) > 0 }

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

// writeBlock writes a generic block response, honouring a route's custom
// error template if configured.
func (h *Handler) writeBlock(w http.ResponseWriter, reqID string, statusCode int) {
	if h.resolved.ErrorTemplate != nil {
		protections.WriteCustomBlockResponse(w, reqID, statusCode, h.resolved.ErrorTemplate)
		return
	}
	protections.WriteBlockResponse(w, reqID, statusCode)
}

func getRequestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-Id"); id != "" {
		return id
	}
	if v, ok := r.Context().Value(caddyhttp.VarsCtxKey).(map[string]any); ok {
		if uuid, exists := v["uuid"]; exists {
			return fmt.Sprint(uuid)
		}
	}
	return fmt.Sprintf("%p", r)
}

var _ caddyhttp.MiddlewareHandler = (*Handler)(nil)
