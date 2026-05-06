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
	"github.com/barbacana-waf/barbacana/internal/protections/crs/curated"
)

// CRS paranoia level and anomaly threshold are hardcoded. User-facing
// config does not expose them. On top of the PL1 baseline Barbacana
// force-enables a curated set of PL2/PL3 rules — see the curated
// subpackage and docs/design/security-evaluation.md.
const (
	paranoiaLevel    = 1
	anomalyThreshold = 5
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
		WithRequestBodyInMemoryLimit(int(route.Inspection.MaxMemoryBuffer)).
		WithResponseBodyAccess().
		WithResponseBodyLimit(int(route.Inspection.MaxInspectSize)).
		WithResponseBodyMimeTypes([]string{
			"text/plain", "text/html", "text/css", "text/javascript",
			"application/json", "application/xml", "application/javascript",
		})

	// Load crs-setup.conf from embedded FS as a string directive.
	setupData, err := FS.ReadFile("crs-setup.conf")
	if err != nil {
		return nil, fmt.Errorf("read crs-setup.conf: %w", err)
	}
	cfg = cfg.WithDirectives(string(setupData))

	// Load all CRS rule .conf files from embedded FS.
	//
	// Curated rules split by phase: curated-rules-request.conf must load
	// before REQUEST-949-BLOCKING-EVALUATION (so phase-2 matches feed the
	// inbound score before aggregation) and curated-rules-response.conf
	// must load before RESPONSE-959-BLOCKING-EVALUATION (same logic on
	// the outbound side). Each is preceded by SecRuleRemoveById of the
	// rules curated for that phase, so the originals — which by load
	// order have already been parsed by the time we hit the marker — are
	// stripped before the curated copies parse, avoiding duplicate-ID
	// errors. Score accumulators in the curated bodies have been
	// rewritten to PL1 + critical severity (see cmd/tools/rules).
	ruleFiles, err := listRuleFiles()
	if err != nil {
		return nil, fmt.Errorf("list rule files: %w", err)
	}
	const (
		curatedRequestFile  = "rules/curated-rules-request.conf"
		curatedResponseFile = "rules/curated-rules-response.conf"
		requestBlockingPfx  = "rules/REQUEST-949"
		responseBlockingPfx = "rules/RESPONSE-959"
	)

	curatedFiles := map[string]bool{
		curatedRequestFile:  false,
		curatedResponseFile: false,
	}
	for _, f := range ruleFiles {
		if _, ok := curatedFiles[f]; ok {
			curatedFiles[f] = true
		}
	}

	requestCuratedIDs, responseCuratedIDs := curated.PhaseSplit()

	emitCurated := func(file string, ids []int) error {
		if len(ids) == 0 || !curatedFiles[file] {
			return nil
		}
		sort.Ints(ids)
		parts := make([]string, len(ids))
		for i, id := range ids {
			parts[i] = strconv.Itoa(id)
		}
		cfg = cfg.WithDirectives("SecRuleRemoveById " + strings.Join(parts, " "))
		data, err := FS.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read rule file %s: %w", file, err)
		}
		cfg = cfg.WithDirectives(string(data))
		return nil
	}

	requestEmitted := false
	responseEmitted := false
	for _, f := range ruleFiles {
		if _, isCurated := curatedFiles[f]; isCurated || !strings.HasSuffix(f, ".conf") {
			continue
		}
		if !requestEmitted && strings.HasPrefix(f, requestBlockingPfx) {
			if err := emitCurated(curatedRequestFile, requestCuratedIDs); err != nil {
				return nil, err
			}
			// Inject Barbacana custom XSS rules (210xxx range) here, in
			// the same window the curated-request bundle uses: after
			// the CRS attack rules but before REQUEST-949 aggregates
			// and blocks. Loaded after 949 they would still match but
			// never contribute to the blocking decision because the
			// blocking evaluator has already run for this phase.
			cfg = cfg.WithDirectives(barbacanaXSSRules)
			requestEmitted = true
		}
		if !responseEmitted && strings.HasPrefix(f, responseBlockingPfx) {
			if err := emitCurated(curatedResponseFile, responseCuratedIDs); err != nil {
				return nil, err
			}
			responseEmitted = true
		}
		data, err := FS.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read rule file %s: %w", f, err)
		}
		cfg = cfg.WithDirectives(string(data))
	}
	if len(requestCuratedIDs) > 0 && !requestEmitted {
		return nil, fmt.Errorf("curated-rules-request.conf present but %s* not found; cannot place curated rules before request blocking evaluation", requestBlockingPfx)
	}
	if len(responseCuratedIDs) > 0 && !responseEmitted {
		return nil, fmt.Errorf("curated-rules-response.conf present but %s* not found; cannot place curated rules before response blocking evaluation", responseBlockingPfx)
	}

	// Content-type enforcement is owned by Barbacana's accept.content_types
	// per route, not by CRS. Rule 920420 enforces a global allowlist via
	// tx.allowed_request_content_type and cannot express per-route policy,
	// so leaving it active contradicts Barbacana's check whenever a route
	// omits content_types (everything passes at the accept stage but CRS
	// rejects it). See docs/design/conventions.md §"When protections
	// overlap: one layer owns each concern".
	cfg = cfg.WithDirectives("SecRuleRemoveById 920420")

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

	// Process URI. The pipeline attaches an InspectionPath carrying the
	// canonical (normalized) form — CRS must see that, not the verbatim
	// URL headed for the upstream. If the pipeline wiring is absent
	// (unit tests), BuildInspectionURL falls back to r.URL.String().
	tx.ProcessURI(protections.BuildInspectionURL(ctx, r), r.Method, r.Proto)

	// Feed any synthetic ARGS produced by upstream stages (e.g. the
	// base64-decoding stage). Each pair is added to the universal
	// ARGS / ARGS_NAMES collections plus its surface-specific
	// counterpart, so CRS attack rules evaluate decoded payloads
	// alongside the raw request without the original body or URL
	// being mutated.
	if decoded := protections.DecodedArgsFromContext(ctx); decoded != nil {
		for _, p := range decoded.GET {
			tx.AddGetRequestArgument(p.Name, p.Value)
		}
		for _, p := range decoded.POST {
			tx.AddPostRequestArgument(p.Name, p.Value)
		}
		for _, p := range decoded.PATH {
			tx.AddPathRequestArgument(p.Name, p.Value)
		}
	}

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
				Protection: "resource-limits-evaluation-timeout",
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

// EvaluateResponse runs response-phase CRS rules (phase 3 — response
// headers, phase 4 — response body) against a buffered upstream
// response. It uses a fresh transaction; the Coraza state from the
// matching request-phase Evaluate call is not carried over because the
// pipeline does not retain transactions across phases. Response-side
// curated rules in the catalog (server-data-leakage-5xx-bodies,
// ruby-data-leakage-source-code, all sql-data-leakage-*, web-shell-
// detection) inspect the response in isolation, so the cross-phase
// context loss is not load-bearing.
//
// The caller is responsible for buffering the response — by the time
// this runs the headers and body have not been written to the client
// yet, so an interruption can replace the response wholesale.
func (e *Engine) EvaluateResponse(ctx context.Context, r *http.Request, statusCode int, respHeaders http.Header, body []byte) EvaluationResult {
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

	// Replay minimal request context so phase 1/2 rules that gate
	// phase 3/4 setvars (paranoia init, allowlists) run before the
	// response is examined. Without this replay, response-side
	// data-leakage rules silently no-op because tx.variables.tx.paranoia_level
	// (and the per-request allowlist setvars) are never initialised.
	tx.ProcessURI(protections.BuildInspectionURL(ctx, r), r.Method, r.Proto)
	for k, vals := range r.Header {
		for _, v := range vals {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		// A request-phase rule fired here would already have been
		// surfaced by Evaluate; re-firing it on the response side is a
		// no-op for the caller. Log so an unexpected interruption
		// (e.g. a rule that only triggers on the replay path) leaves
		// a breadcrumb instead of vanishing.
		slog.DebugContext(ctx, "coraza response-eval request-headers interruption (ignored)", "rule_id", it.RuleID, "action", it.Action)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		slog.DebugContext(ctx, "coraza response-eval request-body error", "err", err.Error())
	}

	for k, vals := range respHeaders {
		for _, v := range vals {
			tx.AddResponseHeader(k, v)
		}
	}
	if it := tx.ProcessResponseHeaders(statusCode, r.Proto); it != nil {
		return e.buildResult(it, tx)
	}

	if len(body) > 0 {
		if _, _, err := tx.WriteResponseBody(body); err != nil {
			slog.DebugContext(ctx, "coraza write response body error", "err", err.Error())
		}
	}
	if it, err := tx.ProcessResponseBody(); err == nil && it != nil {
		return e.buildResult(it, tx)
	}

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
	// Paranoia level and anomaly threshold are not user-configurable. The
	// PL1 baseline is complemented by a curated set of PL2/PL3 rules loaded
	// from curated-rules.conf (produced by cmd/tools/rules). See
	// docs/design/security-evaluation.md.
	fmt.Fprintf(&sb, "SecAction \"id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=%d\"\n",
		paranoiaLevel)
	fmt.Fprintf(&sb, "SecAction \"id:900001,phase:1,pass,nolog,setvar:tx.detection_paranoia_level=%d\"\n",
		paranoiaLevel)
	fmt.Fprintf(&sb, "SecAction \"id:900100,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=%d\"\n",
		anomalyThreshold)
	fmt.Fprintf(&sb, "SecAction \"id:900101,phase:1,pass,nolog,setvar:tx.outbound_anomaly_score_threshold=%d\"\n",
		anomalyThreshold)

	// Wire accept.methods → CRS tx.allowed_methods. Otherwise
	// REQUEST-901-INITIALIZATION.conf falls back to CRS's own default of
	// "GET HEAD POST OPTIONS", and rule 911100 blocks every PUT/PATCH/
	// DELETE at PL1 with a critical-severity anomaly score. Barbacana's
	// accept.methods already validates the client's method at the
	// request layer; the CRS variable has to mirror it so method
	// enforcement there is consistent with the route's public contract.
	if methods := strings.Join(route.Accept.Methods, " "); methods != "" {
		fmt.Fprintf(&sb, "SecAction \"id:900200,phase:1,pass,nolog,setvar:'tx.allowed_methods=%s'\"\n",
			strings.ToUpper(methods))
	}

	// When method-override is disabled, pre-set restricted_headers_basic without
	// the X-HTTP-Method-Override / X-HTTP-Method / X-Method-Override entries.
	// Rule 901165 in REQUEST-901-INITIALIZATION.conf only writes this variable when
	// it is empty, so our pre-set prevents those header names from being blocked.
	if route.Disable["http-compliance-method-override-param"] {
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
