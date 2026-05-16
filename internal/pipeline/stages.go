package pipeline

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/metrics"
	"github.com/barbacana-waf/barbacana/internal/protections"
)

func readBody(r *http.Request) []byte {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body
}

func (h *Handler) blockingMode() bool { return h.resolved.Mode != config.ModeDetect }

// runRateLimit enforces the per-route (or global-default) sliding-window rate
// limit. It is a no-op when no rate_limit block is configured for the route.
// Rate limiting is a config-driven feature, not a catalog-managed protection:
// activation is controlled by the presence of a rate_limit: block, not by the
// enable/disable lists, so h.resolved.Disable is intentionally not consulted.
func (h *Handler) runRateLimit(ctx context.Context, _ http.ResponseWriter, r *http.Request, _ []byte, ac *auditCollector) stageOutcome {
	if h.rateLimiter == nil {
		return stageOutcome{}
	}
	// Extract and Allow are interface methods that may error in future
	// backends (e.g. Redis); current memory backend and extractors never do.
	key, _ := h.rateExtractor.Extract(r)
	allowed, _ := h.rateLimiter.Allow(ctx, key)
	if allowed {
		return stageOutcome{}
	}
	d := protections.Decision{
		Block:      true,
		Protection: "rate-limit",
		Reason:     "rate limit exceeded",
		Status:     http.StatusTooManyRequests,
		CWE:        []string{"CWE-400", "CWE-770"},
	}
	ac.addDecision(d)
	if h.blockingMode() {
		return stageOutcome{block: d}
	}
	slog.DebugContext(ctx, "detect-only: rate limit exceeded", "protection", d.Protection, "reason", d.Reason)
	return stageOutcome{}
}

// runRequestValidation enforces method allow-list, host header, URL/header
// size limits, and content-type gating against the route's `accept` config.
func (h *Handler) runRequestValidation(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, ac *auditCollector) stageOutcome {
	d := h.reqValidator.ValidateRequest(ctx, r)
	if !d.Block {
		return stageOutcome{}
	}
	ac.addDecision(d)
	if h.blockingMode() {
		return stageOutcome{block: d}
	}
	slog.DebugContext(ctx, "detect-only: request validation", "protection", d.Protection, "reason", d.Reason)
	return stageOutcome{}
}

// runProtocolChecks runs the native protocol-hardening checks (path
// normalization, smuggling, CRLF, null-byte, method-override) in order.
// Native decisions go through addNativeDecision so the CWE is sourced from
// the Protection itself rather than the canonical-name catalog.
func (h *Handler) runProtocolChecks(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, ac *auditCollector) stageOutcome {
	for _, p := range h.protocolChecks {
		if protections.IsDisabled(p.Name(), h.resolved.Disable) {
			continue
		}
		d := p.Evaluate(ctx, r)
		if !d.Block {
			continue
		}
		ac.addNativeDecision(d, p)
		if h.blockingMode() {
			return stageOutcome{block: d}
		}
		slog.DebugContext(ctx, "detect-only: protocol hardening", "protection", d.Protection, "reason", d.Reason)
	}
	return stageOutcome{}
}

// runDecompression enforces the gzip/deflate decompression-ratio limit on
// compressed request bodies. No-op for other encodings or empty bodies.
func (h *Handler) runDecompression(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, ac *auditCollector) stageOutcome {
	enc := strings.ToLower(r.Header.Get("Content-Encoding"))
	if (enc != "gzip" && enc != "deflate") || len(body) == 0 {
		return stageOutcome{}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	_, rd := h.resourceVal.CheckDecompression(ctx, r)
	r.Body = io.NopCloser(bytes.NewReader(body))
	if !rd.Block {
		return stageOutcome{}
	}
	ac.addDecision(rd)
	// DecompressionRejectedTotal fires on any block, regardless of mode.
	metrics.DecompressionRejectedTotal.WithLabelValues(h.resolved.ID).Inc()
	if h.blockingMode() {
		return stageOutcome{block: rd}
	}
	slog.DebugContext(ctx, "detect-only: decompression limit", "reason", rd.Reason)
	return stageOutcome{}
}

// runJSONXMLBody enforces JSON depth/key and XML depth/entity limits on the
// buffered raw body, gated on Content-Type.
func (h *Handler) runJSONXMLBody(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, ac *auditCollector) stageOutcome {
	if len(body) == 0 {
		return stageOutcome{}
	}
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "json") {
		if d := h.reqValidator.ValidateJSONBody(ctx, body); d.Block {
			ac.addDecision(d)
			if h.blockingMode() {
				return stageOutcome{block: d}
			}
			slog.DebugContext(ctx, "detect-only: JSON body", "protection", d.Protection, "reason", d.Reason)
		}
	}
	if strings.Contains(ct, "xml") {
		if d := h.reqValidator.ValidateXMLBody(ctx, body); d.Block {
			ac.addDecision(d)
			if h.blockingMode() {
				return stageOutcome{block: d}
			}
			slog.DebugContext(ctx, "detect-only: XML body", "protection", d.Protection, "reason", d.Reason)
		}
	}
	return stageOutcome{}
}

// runMultipart enforces multipart upload limits (file count, per-file size,
// double-extension detection). Active only when the route is configured to
// parse multipart and the request actually carries multipart/form-data.
func (h *Handler) runMultipart(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, ac *auditCollector) stageOutcome {
	if !h.resolved.RunMultipartParser || len(body) == 0 {
		return stageOutcome{}
	}
	if !strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
		return stageOutcome{}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	d := h.multipartVal.Validate(ctx, r)
	r.Body = io.NopCloser(bytes.NewReader(body))
	if !d.Block {
		return stageOutcome{}
	}
	ac.addDecision(d)
	if h.blockingMode() {
		return stageOutcome{block: d}
	}
	slog.DebugContext(ctx, "detect-only: multipart", "protection", d.Protection, "reason", d.Reason)
	return stageOutcome{}
}

// runCORSPreflight handles OPTIONS preflight requests, writing the 204 +
// Access-Control-Allow-* response itself and short-circuiting the pipeline.
// Not a block — no audit, no metric. Must run between the body stages and
// OpenAPI so preflights skip OpenAPI validation (which would otherwise
// reject them).
func (h *Handler) runCORSPreflight(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, ac *auditCollector) stageOutcome {
	if h.corsHandler == nil {
		return stageOutcome{}
	}
	if h.corsHandler.HandlePreflight(w, r) {
		return stageOutcome{shortCircuited: true}
	}
	return stageOutcome{}
}

// runOpenAPI validates the request against the route's loaded OpenAPI spec
// (path, method, params, body, content-type). Bumps the pass/fail counter
// every request, regardless of mode.
func (h *Handler) runOpenAPI(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, ac *auditCollector) stageOutcome {
	if h.openAPIVal == nil {
		return stageOutcome{}
	}
	d := h.openAPIVal.Validate(ctx, r)
	if !d.Block {
		metrics.OpenAPIValidationTotal.WithLabelValues(h.resolved.ID, "pass").Inc()
		return stageOutcome{}
	}
	ac.addDecision(d)
	metrics.OpenAPIValidationTotal.WithLabelValues(h.resolved.ID, "fail").Inc()
	if h.blockingMode() {
		return stageOutcome{block: d}
	}
	slog.DebugContext(ctx, "detect-only: openapi", "protection", d.Protection, "reason", d.Reason)
	return stageOutcome{}
}

// runBase64Decoding scans the request for base64-encoded payloads and
// writes any successful decodes to the InspectionArgs attached to ctx.
// CRS will read those synthetic ARGS in the next stage. The stage only
// emits a blocking decision when the per-request decode budget trips
// (base64-decoding-flood); otherwise it accumulates state and falls
// through.
func (h *Handler) runBase64Decoding(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, ac *auditCollector) stageOutcome {
	if h.base64Stage == nil {
		return stageOutcome{}
	}
	d := h.base64Stage.Evaluate(ctx, r, body)
	if !d.Block {
		return stageOutcome{}
	}
	ac.addDecision(d)
	if h.blockingMode() {
		return stageOutcome{block: d}
	}
	slog.DebugContext(ctx, "detect-only: base64 decoding", "protection", d.Protection, "reason", d.Reason)
	return stageOutcome{}
}

// runCRS evaluates the Coraza WAF (CRS rules) against the request. Produces
// zero or more decisions in one Evaluate call: blocking mode halts on the
// first blocking decision; detect-only accumulates every blocking and every
// non-blocking-but-named match. The anomaly histogram and ac.anomalyScore
// are recorded every request, even when nothing matched.
//
// A child span "coraza.evaluate" wraps the call so traces show the WAF
// step distinctly from the parent request span. Each matched rule fires
// as a span event rather than a span-per-rule (CRS rules can fire 5-50
// times per request, so spans-per-rule explodes trace cardinality).
func (h *Handler) runCRS(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, ac *auditCollector) stageOutcome {
	if len(body) > 0 {
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	ctx, span := startCorazaSpan(ctx)
	defer span.End()

	res := h.crsEngine.Evaluate(ctx, r)
	ac.anomalyScore = res.AnomalyScore
	metrics.AnomalyScoreHistogram.WithLabelValues(h.resolved.ID).Observe(float64(res.AnomalyScore))

	// IsRecording is the standard guard for skipping span work on a
	// no-op span; tracingEnabled.Load was already checked inside
	// startCorazaSpan, so this gates only the (unreachable when
	// disabled) attribute construction path.
	if span.IsRecording() {
		span.SetAttributes(attribute.Int("waf.score", res.AnomalyScore))
		recordRuleMatchEvents(span, res.Decisions)
	}

	for _, d := range res.Decisions {
		if d.Block {
			ac.addDecision(d)
			slog.DebugContext(ctx, "block: CRS", "protection", d.Protection, "reason", d.Reason)
			if h.blockingMode() {
				if span.IsRecording() {
					span.SetAttributes(attribute.String("waf.action", "block"))
				}
				return stageOutcome{block: d}
			}
			continue
		}
		if d.Protection != "" {
			ac.addDecision(d)
		}
	}
	return stageOutcome{}
}

// recordRuleMatchEvents emits one span event per (decision, rule_id)
// pair. Each event carries the protection name as the rule category
// and the integer rule ID — sufficient to correlate a span back to a
// CRS rule in dashboards. Severity is intentionally not emitted: it
// is not on the Decision and would require a per-rule lookup the
// catalog does not expose.
func recordRuleMatchEvents(span trace.Span, decisions []protections.Decision) {
	for _, d := range decisions {
		if d.Protection == "" {
			continue
		}
		for _, rid := range d.MatchedRules {
			span.AddEvent("waf.rule.match",
				trace.WithAttributes(
					attribute.Int("waf.rule.id", rid),
					attribute.String("waf.rule.category", d.Protection),
				),
			)
		}
	}
}

// upstreamSpanAttrs builds the HTTP-semconv attribute set the upstream
// span starts with: method, full URL, server.address/port. Parsing the
// configured upstream string per request is a few microseconds — small
// next to a CRS pass and not worth caching on Handler.
func upstreamSpanAttrs(r *http.Request, upstream string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("http.request.method", r.Method),
	}
	u, err := url.Parse(upstream)
	if err != nil {
		// Malformed upstream is a config bug, not a runtime concern;
		// emit the raw string so the operator sees what was attempted.
		attrs = append(attrs, attribute.String("url.full", upstream+r.URL.RequestURI()))
		return attrs
	}
	attrs = append(attrs,
		attribute.String("url.full", u.Scheme+"://"+u.Host+r.URL.RequestURI()),
		attribute.String("server.address", u.Hostname()),
	)
	if port := u.Port(); port != "" {
		attrs = append(attrs, attribute.String("server.port", port))
	}
	return attrs
}

// classifyUpstreamError buckets a proxy-side error into one of the
// labels used by waf_upstream_errors_total. The dashboard relies on
// these labels to answer "WAF blocked vs upstream broken" without
// reading log lines, so the classification rules are deliberately
// conservative — known signals first, "other" as the catch-all.
func classifyUpstreamError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	// Connection refused commonly arrives wrapped in *net.OpError →
	// *os.SyscallError → syscall.Errno. Falling back to a substring
	// match catches the cases where the proxy library has rewrapped
	// the error and Errno comparison no longer works.
	s := err.Error()
	if strings.Contains(s, "connection refused") {
		return "connection_refused"
	}
	if strings.Contains(s, "deadline exceeded") || strings.Contains(s, "timeout") {
		return "timeout"
	}
	return "other"
}

// runResponsePhase wraps the upstream response, runs response-phase WAF
// against the buffered status/headers/body, and either flushes the
// captured response or replaces it with a block.
//
// It is the post-pipeline counterpart to the request stages above:
// it owns the response-phase audit, metrics, and block emission so
// ServeHTTP reads as the pipeline table plus this single tail step.
func (h *Handler) runResponsePhase(ctx context.Context, w http.ResponseWriter, r *http.Request, reqID string, ac *auditCollector, next caddyhttp.Handler, upstreamElapsed *time.Duration) error {
	rw := &responseModifier{
		ResponseWriter: w,
		handler:        h,
		request:        r,
		wroteHeader:    false,
		buf:            &bytes.Buffer{},
		bufLimit:       int(h.resolved.Inspection.MaxInspectSize),
	}
	upstreamStart := time.Now()
	upstreamCtx, upstreamSpan := startUpstreamSpan(r.Context(), upstreamSpanAttrs(r, h.resolved.Upstream)...)
	err := next.ServeHTTP(rw, r.WithContext(upstreamCtx))
	*upstreamElapsed = time.Since(upstreamStart)
	if err != nil {
		// Upstream/proxy error before flush: pass-through what was
		// captured so the client sees the proxy's error response.
		metrics.UpstreamErrorsTotal.WithLabelValues(h.resolved.ID, classifyUpstreamError(err)).Inc()
		upstreamSpan.SetStatus(codes.Error, err.Error())
		upstreamSpan.End()
		rw.flushBuffered()
		return err
	}
	// Successful proxy call — but the upstream may have returned 5xx.
	// Count those separately so the dashboard can attribute "broken
	// app" vs "broken WAF" without inspecting log lines.
	if rw.wroteHeader && rw.lastStatus >= 500 && rw.lastStatus < 600 {
		metrics.UpstreamErrorsTotal.WithLabelValues(h.resolved.ID, "5xx").Inc()
	}
	if rw.wroteHeader {
		upstreamSpan.SetAttributes(attribute.Int("http.response.status_code", rw.lastStatus))
	}
	upstreamSpan.End()

	// If the writer never produced anything (Caddy short-circuited with
	// no Write/WriteHeader), there is nothing to inspect.
	if !rw.wroteHeader {
		return nil
	}

	status, headers, respBody, ok := rw.bufferedResponse()
	if !ok {
		// Response overflowed the inspection cap and was streamed
		// directly. Skip response-phase WAF.
		return nil
	}

	res := h.crsEngine.EvaluateResponse(ctx, r, status, headers, respBody)
	for _, d := range res.Decisions {
		if !d.Block {
			if d.Protection != "" {
				ac.addDecision(d)
			}
			continue
		}
		ac.addDecision(d)
		if !h.blockingMode() {
			slog.DebugContext(ctx, "detect-only: response phase", "protection", d.Protection, "reason", d.Reason)
			continue
		}
		// Blocking: replace the buffered response with the WAF block.
		code := protections.StatusFor(d.Protection)
		metrics.RequestsTotal.WithLabelValues(h.resolved.ID, "blocked").Inc()
		metrics.RequestsBlockedTotal.WithLabelValues(h.resolved.ID, d.Protection).Inc()
		for _, p := range ac.protections {
			metrics.DetectedThreatsTotal.WithLabelValues(h.resolved.ID, p).Inc()
		}
		h.emitAudit(ctx, r, reqID, ac, "blocked", code)
		// Discard the buffered upstream response and reset the
		// outbound header map. Without the reset the upstream's
		// Content-Length / Content-Type carry over and corrupt the
		// WAF block payload (length mismatch, wrong type) — the
		// writer's underlying connection has not been written to yet,
		// so a clean reset here is safe.
		rw.buf = nil
		hdrs := w.Header()
		for k := range hdrs {
			delete(hdrs, k)
		}
		h.writeBlock(w, reqID, code)
		return nil
	}

	rw.flushBuffered()
	return nil
}
