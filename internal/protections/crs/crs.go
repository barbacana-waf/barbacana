// Package crs integrates the Coraza WAF with embedded OWASP CRS v4 rules.
// It translates between Coraza's rule-ID-oriented model and barbacana's
// canonical-name-oriented model. No CRS rule IDs are exposed to users.
package crs

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"io/fs"

	coraza "github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/metrics"
	"github.com/barbacana-waf/barbacana/internal/protections"
)

// Engine holds a per-route Coraza WAF instance. Created at config compile
// time, used at request time. Immutable after creation.
type Engine struct {
	waf        coraza.WAF
	disabled   map[string]bool
	routeID    string
	detectOnly bool
	timeout    time.Duration
}

// NewEngine creates a Coraza WAF for a resolved route. It loads the embedded
// CRS rules and removes rules corresponding to disabled sub-protections.
func NewEngine(route config.Resolved) (*Engine, error) {
	setupConf, err := buildSetupDirectives(route)
	if err != nil {
		return nil, fmt.Errorf("build CRS setup: %w", err)
	}

	// Use a sub-filesystem rooted at rules/ so @pmFromFile references resolve.
	rulesFS, err := fs.Sub(FS, "rules")
	if err != nil {
		return nil, fmt.Errorf("create rules sub-fs: %w", err)
	}

	cfg := coraza.NewWAFConfig().
		WithRootFS(rulesFS).
		WithDirectives(setupConf).
		WithRequestBodyAccess().
		WithRequestBodyLimit(int(route.Inspection.MaxInspectSize)).
		WithRequestBodyInMemoryLimit(int(route.Inspection.MaxMemoryBuffer))

	// Load crs-setup.conf from embedded FS as a string directive.
	setupData, err := FS.ReadFile("crs-setup.conf")
	if err != nil {
		return nil, fmt.Errorf("read crs-setup.conf: %w", err)
	}
	cfg = cfg.WithDirectives(string(setupData))

	// Load all CRS rule .conf files in order from embedded FS.
	ruleFiles, err := listRuleFiles()
	if err != nil {
		return nil, fmt.Errorf("list rule files: %w", err)
	}
	for _, f := range ruleFiles {
		if !strings.HasSuffix(f, ".conf") {
			continue
		}
		data, err := FS.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read rule file %s: %w", f, err)
		}
		cfg = cfg.WithDirectives(string(data))
	}

	// Remove rules for disabled sub-protections.
	disabledIDs := DisabledRuleIDs(route.Disable)
	if len(disabledIDs) > 0 {
		sort.Ints(disabledIDs)
		var parts []string
		for _, id := range disabledIDs {
			parts = append(parts, strconv.Itoa(id))
		}
		cfg = cfg.WithDirectives("SecRuleRemoveById " + strings.Join(parts, " "))
	}

	// Set engine mode.
	detectOnly := route.Mode == config.ModeDetect
	if detectOnly {
		cfg = cfg.WithDirectives("SecRuleEngine DetectionOnly")
	} else {
		cfg = cfg.WithDirectives("SecRuleEngine On")
	}

	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		return nil, fmt.Errorf("create WAF for route %q: %w", route.ID, err)
	}

	// Count loaded rules for observability.
	metrics.CRSRulesLoadedTotal.Set(float64(len(ruleFiles)))

	return &Engine{
		waf:        waf,
		disabled:   route.Disable,
		routeID:    route.ID,
		detectOnly: detectOnly,
		timeout:    route.Inspection.EvaluationTimeout,
	}, nil
}

// EvaluationResult holds the decisions and anomaly score from a CRS evaluation.
type EvaluationResult struct {
	Decisions    []protections.Decision
	AnomalyScore int
}

// Evaluate processes a request through the Coraza WAF and returns the
// matched sub-protections as Decisions along with the anomaly score.
// The caller (pipeline) decides whether to block based on detect-only mode.
func (e *Engine) Evaluate(ctx context.Context, r *http.Request) EvaluationResult {
	// Apply evaluation timeout.
	if e.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.timeout)
		defer cancel()
	}

	tx := e.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		if err := tx.Close(); err != nil {
			slog.WarnContext(ctx, "coraza tx close error", "err", err.Error())
		}
	}()

	// Process URI
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)

	// Process request headers
	for k, vals := range r.Header {
		for _, v := range vals {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
	}

	// Check for interruption after headers
	if it := tx.ProcessRequestHeaders(); it != nil {
		return e.buildResult(it, tx)
	}

	// Check context deadline
	if ctx.Err() != nil {
		metrics.EvaluationTimeoutTotal.WithLabelValues(e.routeID).Inc()
		return EvaluationResult{
			Decisions: []protections.Decision{{
				Block:      true,
				Protection: "waf-evaluation-timeout",
				Reason:     "CRS evaluation timeout exceeded",
			}},
		}
	}

	// Write request body if present.
	if r.Body != nil && r.ContentLength != 0 {
		body, err := io.ReadAll(io.LimitReader(r.Body, r.ContentLength))
		if err == nil && len(body) > 0 {
			if _, _, writeErr := tx.WriteRequestBody(body); writeErr != nil {
				slog.DebugContext(ctx, "coraza write body error", "err", writeErr.Error())
			}
		}
	}

	// Always process request body phase — CRS evaluates query params,
	// headers, and URI in phase 2, not just the body content.
	if it, err := tx.ProcessRequestBody(); err == nil && it != nil {
		return e.buildResult(it, tx)
	}

	// Collect all matched rules even without interruption (for detect-only).
	// block=false because CRS did not actually interrupt the request.
	decisions := e.matchedRulesToDecisions(tx, false)
	return EvaluationResult{
		Decisions:    decisions,
		AnomalyScore: e.computeAnomalyScore(tx),
	}
}

// buildResult creates an EvaluationResult from an interruption.
func (e *Engine) buildResult(it *types.Interruption, tx types.Transaction) EvaluationResult {
	decisions := e.matchedRulesToDecisions(tx, true)
	if len(decisions) == 0 {
		sub := RuleIDToSubProtection(it.RuleID)
		if sub == "" {
			sub = "crs-unknown"
		}
		decisions = append(decisions, protections.Decision{
			Block:      true,
			Protection: sub,
			Reason:     fmt.Sprintf("CRS rule %d triggered", it.RuleID),
		})
	}
	return EvaluationResult{
		Decisions:    decisions,
		AnomalyScore: e.computeAnomalyScore(tx),
	}
}

// computeAnomalyScore sums the CRS anomaly points from matched rules.
// CRS severity → score: critical(2)=5, error(3)=4, warning(4)=3, notice(5)=2.
func (e *Engine) computeAnomalyScore(tx types.Transaction) int {
	score := 0
	for _, mr := range tx.MatchedRules() {
		switch mr.Rule().Severity() {
		case types.RuleSeverityCritical:
			score += 5
		case types.RuleSeverityError:
			score += 4
		case types.RuleSeverityWarning:
			score += 3
		case types.RuleSeverityNotice:
			score += 2
		}
	}
	return score
}

// matchedRulesToDecisions converts Coraza matched rules to Decisions.
// block controls whether matched rules should produce blocking decisions.
// When CRS caused an actual interruption, block=true; when called for
// detect-only reporting (no interruption), block=false.
//
// Note: Coraza's mr.Disruptive() returns true even for "pass" action rules
// (pass, allow, redirect are all considered disruptive by the Coraza API),
// so it cannot be used to determine whether a rule caused an actual block.
func (e *Engine) matchedRulesToDecisions(tx types.Transaction, block bool) []protections.Decision {
	matched := tx.MatchedRules()
	if len(matched) == 0 {
		return nil
	}

	// Group matched rule IDs by sub-protection.
	type subMatch struct {
		ruleIDs []int
		message string
	}
	grouped := map[string]*subMatch{}
	var order []string
	for _, mr := range matched {
		ruleID := mr.Rule().ID()
		sub := RuleIDToSubProtection(ruleID)
		if sub == "" {
			continue // orchestration rule, skip
		}

		slog.Debug("CRS rule matched",
			"rule_id", ruleID,
			"sub_protection", sub,
			"message", mr.Message(),
		)

		if g, ok := grouped[sub]; ok {
			g.ruleIDs = append(g.ruleIDs, ruleID)
		} else {
			grouped[sub] = &subMatch{
				ruleIDs: []int{ruleID},
				message: mr.Message(),
			}
			order = append(order, sub)
		}
	}

	var decisions []protections.Decision
	for _, sub := range order {
		g := grouped[sub]
		decisions = append(decisions, protections.Decision{
			Block:        block,
			Protection:   sub,
			Reason:       g.message,
			MatchedRules: g.ruleIDs,
		})
	}
	return decisions
}

func buildSetupDirectives(route config.Resolved) (string, error) {
	var sb strings.Builder
	// Set paranoia level from sensitivity.
	fmt.Fprintf(&sb, "SecAction \"id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=%d\"\n",
		route.Inspection.Sensitivity)
	fmt.Fprintf(&sb, "SecAction \"id:900001,phase:1,pass,nolog,setvar:tx.detection_paranoia_level=%d\"\n",
		route.Inspection.Sensitivity)
	// Set anomaly threshold.
	fmt.Fprintf(&sb, "SecAction \"id:900100,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=%d\"\n",
		route.Inspection.AnomalyThreshold)
	fmt.Fprintf(&sb, "SecAction \"id:900101,phase:1,pass,nolog,setvar:tx.outbound_anomaly_score_threshold=%d\"\n",
		route.Inspection.AnomalyThreshold)

	// When method-override is disabled, pre-set restricted_headers_basic without
	// the X-HTTP-Method-Override / X-HTTP-Method / X-Method-Override entries.
	// Rule 901165 in REQUEST-901-INITIALIZATION.conf only writes this variable when
	// it is empty, so our pre-set prevents those header names from being blocked.
	if route.Disable["method-override"] {
		fmt.Fprintf(&sb, "SecAction \"id:900050,phase:1,pass,nolog,t:none,"+
			"setvar:'tx.restricted_headers_basic=/content-encoding/ /proxy/ /lock-token/ /content-range/ /if/ /x-middleware-subrequest/ /expect/'\"\n")
	}

	return sb.String(), nil
}

func listRuleFiles() ([]string, error) {
	entries, err := FS.ReadDir("rules")
	if err != nil {
		return nil, fmt.Errorf("read rules dir: %w", err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		files = append(files, "rules/"+e.Name())
	}
	sort.Strings(files)
	return files, nil
}
