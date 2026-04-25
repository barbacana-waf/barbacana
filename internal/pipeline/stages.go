package pipeline

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"

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

// runCRS evaluates the Coraza WAF (CRS rules) against the request. Produces
// zero or more decisions in one Evaluate call: blocking mode halts on the
// first blocking decision; detect-only accumulates every blocking and every
// non-blocking-but-named match. The anomaly histogram and ac.anomalyScore
// are recorded every request, even when nothing matched.
func (h *Handler) runCRS(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, ac *auditCollector) stageOutcome {
	if len(body) > 0 {
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	res := h.crsEngine.Evaluate(ctx, r)
	ac.anomalyScore = res.AnomalyScore
	metrics.AnomalyScoreHistogram.WithLabelValues(h.resolved.ID).Observe(float64(res.AnomalyScore))

	for _, d := range res.Decisions {
		if d.Block {
			ac.addDecision(d)
			slog.DebugContext(ctx, "block: CRS", "protection", d.Protection, "reason", d.Reason)
			if h.blockingMode() {
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
