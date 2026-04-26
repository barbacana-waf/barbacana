package pipeline

import (
	"context"
	"net/http"

	"github.com/barbacana-waf/barbacana/internal/metrics"
	"github.com/barbacana-waf/barbacana/internal/protections"
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
// code on a block is resolved uniformly from the protection name via
// protections.StatusFor — there is no per-stage override.
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
	out := s.run(ctx, w, r, body, ac)
	if out.shortCircuited {
		return true
	}
	if !out.block.Block {
		return false
	}
	code := protections.StatusFor(out.block.Protection)
	metrics.RequestsTotal.WithLabelValues(h.resolved.ID, "blocked").Inc()
	metrics.RequestsBlockedTotal.WithLabelValues(h.resolved.ID, out.block.Protection).Inc()
	// DetectedThreatsTotal counts threats regardless of mode. ac may carry
	// non-blocking matches that fired before the halting decision (e.g. CRS
	// finds several rules in one Evaluate call); credit each one once.
	for _, p := range ac.protections {
		metrics.DetectedThreatsTotal.WithLabelValues(h.resolved.ID, p).Inc()
	}
	h.emitAudit(ctx, r, reqID, ac, "blocked", code)
	h.writeBlock(w, reqID, code)
	return true
}
