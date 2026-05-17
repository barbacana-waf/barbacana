package pipeline

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/barbacana-waf/barbacana/internal/metrics"
	"github.com/barbacana-waf/barbacana/internal/protections"
	"github.com/barbacana-waf/barbacana/internal/ratelimit"
)

// stageFunc evaluates one pipeline step. The stage owns its own skip guards,
// body restoration, audit accumulation (including the native-vs-catalog CWE
// distinction), stage-specific metrics, and detect-mode debug logging.
//
// outcome.block carries Block=true iff the runner must enforce a block
// response and halt the pipeline. In detect-only mode the stage returns the
// zero Decision regardless of how many matches it accumulated.
//
// outcome.shortCircuited means the stage already wrote the response (CORS
// preflight); the runner returns immediately, no audit, no block metrics.
type stageFunc func(ctx context.Context, w http.ResponseWriter, r *http.Request, body []byte, ac *auditCollector) stageOutcome

type stageOutcome struct {
	block          protections.Decision
	shortCircuited bool
}

// stage is one step in the pipeline table. The runner reads stages in order
// and halts at the first short-circuit or blocked decision. The HTTP status
// code on a block is resolved from out.block.Status when set (used by
// config-driven features outside the catalog), otherwise from the protection
// name via protections.StatusFor.
type stage struct {
	name string
	run  stageFunc
	// needsBody marks the stage as a body reader. The runner buffers the
	// request body lazily on the first such stage, so header-only stages
	// (e.g. request-validation rejecting via ContentLength) can short-circuit
	// before any io.ReadAll runs — preserving their oversize-body DoS guard.
	needsBody bool
}

// runStage executes one stage and returns whether the pipeline should halt.
// When halted the response has already been written (or short-circuited).
func (h *Handler) runStage(ctx context.Context, w http.ResponseWriter, r *http.Request, reqID string, ac *auditCollector, body []byte, s stage) bool {
	stageCtx, stageSpan := startStageSpan(ctx, s.name)
	defer stageSpan.End()
	out := s.run(stageCtx, w, r, body, ac)
	if out.shortCircuited {
		return true
	}
	if !out.block.Block {
		return false
	}
	code := out.block.Status
	if code == 0 {
		code = protections.StatusFor(out.block.Protection)
	}
	// RFC 6585 §4: 429 responses SHOULD include Retry-After. Sourced from
	// the route's configured rate-limit window (ceil to seconds, minimum 1).
	// Any future protection returning 429 with different retry semantics
	// will need a per-protection retry hint (e.g. on Decision).
	if code == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(h.resolved.RateLimit)))
	}
	metrics.RequestsTotal.WithLabelValues(h.resolved.ID, "blocked").Inc()
	metrics.RequestsBlockedTotal.WithLabelValues(h.resolved.ID, out.block.Protection).Inc()
	// DetectedThreatsTotal counts threats regardless of mode. ac may carry
	// non-blocking matches that fired before the halting decision (e.g. CRS
	// finds several rules in one Evaluate call); credit each one once.
	for _, p := range ac.protections {
		metrics.DetectedThreatsTotal.WithLabelValues(h.resolved.ID, p).Inc()
	}
	// Tag both the stage span (where the block actually fired) and
	// the request-level parent (so a Jaeger search by service shows
	// the error status without drilling into the stage tree).
	recordBlockOnSpan(stageSpan, out.block, code)
	recordBlockOnSpan(trace.SpanFromContext(ctx), out.block, code)
	h.emitAudit(ctx, r, reqID, ac, "blocked", code)
	h.writeBlock(w, reqID, code)
	return true
}

// retryAfterSeconds returns the Retry-After value (in whole seconds) for a
// 429 emitted by the rate-limit stage. It rounds up partial seconds and
// clamps to a minimum of 1, matching the RFC 6585 §4 integer form.
// Defaults to 1 when the route has no configured rate_limit (a non-rate-
// limit 429 source, defensive only — no such source exists today).
func retryAfterSeconds(rl *ratelimit.Config) int {
	if rl == nil {
		return 1
	}
	secs := int(rl.Window / time.Second)
	if rl.Window%time.Second != 0 {
		secs++
	}
	if secs < 1 {
		secs = 1
	}
	return secs
}
