package pipeline

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/barbacana-waf/barbacana/internal/config"
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

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ctx := r.Context()
	reqID := getRequestID(r)

	// ── Stage 1: request validation (size, methods, content-type gating) ──
	if d := h.reqValidator.ValidateRequest(ctx, r); d.Block {
		if !h.resolved.DetectOnly {
			writeDecision(w, reqID, d)
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
			if !h.resolved.DetectOnly {
				protections.WriteBlockResponse(w, reqID, http.StatusForbidden)
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
			if !h.resolved.DetectOnly {
				protections.WriteBlockResponse(w, reqID, http.StatusForbidden)
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
				if !h.resolved.DetectOnly {
					protections.WriteBlockResponse(w, reqID, http.StatusForbidden)
					return nil
				}
				slog.DebugContext(ctx, "detect-only: JSON body", "protection", d.Protection, "reason", d.Reason)
			}
		}
		if strings.Contains(ct, "xml") {
			if d := h.reqValidator.ValidateXMLBody(ctx, bodyBytes); d.Block {
				if !h.resolved.DetectOnly {
					protections.WriteBlockResponse(w, reqID, http.StatusForbidden)
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
				if !h.resolved.DetectOnly {
					protections.WriteBlockResponse(w, reqID, http.StatusForbidden)
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
			code := openAPIStatusCode(d.Protection)
			protections.WriteBlockResponse(w, reqID, code)
			return nil
		}
	}

	// ── Stage 9: CRS evaluation ──
	// Restore body for CRS.
	if len(bodyBytes) > 0 {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	decisions := h.crsEngine.Evaluate(ctx, r)
	for _, d := range decisions {
		if d.Block {
			slog.DebugContext(ctx, "block: CRS", "protection", d.Protection, "reason", d.Reason)
			if !h.resolved.DetectOnly {
				protections.WriteBlockResponse(w, reqID, http.StatusForbidden)
				return nil
			}
		}
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

// responseModifier intercepts WriteHeader to strip and inject response headers.
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
func writeDecision(w http.ResponseWriter, reqID string, d protections.Decision) {
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

var _ caddyhttp.MiddlewareHandler = (*Handler)(nil)
