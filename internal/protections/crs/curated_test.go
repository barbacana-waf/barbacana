package crs

import (
	"context"
	"fmt"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/protections/crs/curated"
)

// TestCuratedRuleIDsMapToSubProtections asserts that every force-enabled
// rule resolves to a sub-protection name — either via the curated
// subpackage itself (authoritative) or via the base ruleMapping. A
// curated match that has no sub-protection name would silently drop out
// of matched_rules in the audit log.
func TestCuratedRuleIDsMapToSubProtections(t *testing.T) {
	for _, r := range curated.Rules {
		got := RuleIDToSubProtection(r.ID)
		if got == "" {
			t.Errorf("curated rule %d has no sub-protection", r.ID)
			continue
		}
		if got != r.Protection {
			t.Errorf("curated rule %d: RuleIDToSubProtection returned %q, curated.Rules says %q",
				r.ID, got, r.Protection)
		}
	}
}

// TestCuratedRulesFilePresent verifies curated-rules.conf was produced by
// cmd/tools/rules and contains exactly the same IDs as curated.Rules.
// Fails the build if the generator output drifted from the Go source.
func TestCuratedRulesFilePresent(t *testing.T) {
	data, err := FS.ReadFile("rules/curated-rules.conf")
	if err != nil {
		t.Fatalf("curated-rules.conf missing from embedded FS: %v (run 'make rules')", err)
	}
	idRe := regexp.MustCompile(`(?m)id:(\d+)`)
	matches := idRe.FindAllSubmatch(data, -1)
	gotIDs := make([]int, 0, len(matches))
	for _, m := range matches {
		id, _ := strconv.Atoi(string(m[1]))
		gotIDs = append(gotIDs, id)
	}
	sort.Ints(gotIDs)

	wantIDs := curated.IDs()
	sort.Ints(wantIDs)

	if fmt.Sprint(gotIDs) != fmt.Sprint(wantIDs) {
		t.Errorf("curated-rules.conf IDs drift from curated.Rules:\n got:  %v\n want: %v", gotIDs, wantIDs)
	}
}

// TestCuratedRulesFileHasNoParanoiaAccumulators asserts that the extraction
// tool rewrote every pl2/pl3 score setvar to pl1. Without this rewrite the
// curated rules match but never contribute to tx.blocking_inbound_anomaly_score
// at PL1, so requests are not blocked. See docs/design/security-evaluation.md.
func TestCuratedRulesFileHasNoParanoiaAccumulators(t *testing.T) {
	data, err := FS.ReadFile("rules/curated-rules.conf")
	if err != nil {
		t.Fatalf("curated-rules.conf missing: %v", err)
	}
	if bad := regexp.MustCompile(`inbound_anomaly_score_pl[23456789]`).FindAllString(string(data), -1); len(bad) > 0 {
		t.Errorf("curated-rules.conf contains non-pl1 score accumulators (extraction did not rewrite): %v", bad)
	}
}

// TestNewEngineWithCuratedRules ensures the engine builds cleanly when
// curated-rules.conf is present. Guards against Coraza rejecting the
// re-declaration of a rule ID that SecRuleRemoveById was supposed to
// strip first (a future Coraza bump could change parse-time semantics).
func TestNewEngineWithCuratedRules(t *testing.T) {
	route := testRoute()
	eng, err := NewEngine(route)
	if err != nil {
		t.Fatalf("NewEngine with curated rules: %v", err)
	}
	if eng == nil {
		t.Fatal("engine is nil")
	}
}

// TestCuratedRuleFiresSMTPInjection is the load-bearing test for the whole
// curated-rules mechanism: at PL1, rule 932300 (PL2, SMTP command injection)
// lives behind a skipAfter gate in REQUEST-932-*.conf and cannot fire. The
// engine is expected to strip the dormant CRS original with SecRuleRemoveById
// and re-load the rule from curated-rules.conf, placing it past all skip
// gates so Coraza evaluates it.
//
// Payload "\r\nRCPT TO:<a@b.c>" in a query arg hits 932300's regex after
// t:escapeSeqDecode converts the literal \r\n to a real CRLF.
func TestCuratedRuleFiresSMTPInjection(t *testing.T) {
	route := testRoute()
	eng, err := NewEngine(route)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// %5C%72%5Cn = "\r\n" literal (4 chars), %3C = <, %3E = >
	r := httptest.NewRequest("GET",
		"http://example.com/test?to=%5Cr%5CnRCPT%20TO%3A%3Ca%40b.c%3E", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	result := eng.Evaluate(context.Background(), r)

	var matched932300 bool
	var gotMailProtection bool
	var blocked bool
	for _, d := range result.Decisions {
		t.Logf("decision: block=%v protection=%s matched=%v reason=%s",
			d.Block, d.Protection, d.MatchedRules, d.Reason)
		if d.Protection == "rce-mail-protocol-injection" {
			gotMailProtection = true
		}
		if d.Block {
			blocked = true
		}
		for _, id := range d.MatchedRules {
			if id == 932300 {
				matched932300 = true
			}
		}
	}
	if !matched932300 {
		t.Errorf("expected curated rule 932300 to fire on SMTP injection payload; got decisions %+v (anomaly_score=%d)",
			result.Decisions, result.AnomalyScore)
	}
	if !gotMailProtection {
		t.Errorf("expected rce-mail-protocol-injection decision; got %+v", result.Decisions)
	}
	// CRITICAL: a critical-severity match on its own meets the default
	// anomaly threshold of 5. The request must block. If this assertion
	// fails while matched932300=true, curated rules are firing but their
	// scores aren't aggregated into tx.blocking_inbound_anomaly_score —
	// typically because BLOCKING_PARANOIA_LEVEL=1 means rule 949061 never
	// folds pl2 into the blocking total, or because curated rules fire
	// after 949110 has already evaluated.
	if !blocked {
		t.Errorf("expected curated rule 932300 to block (score 5 >= threshold 5); got no blocking decision. anomaly_score=%d, decisions=%+v",
			result.AnomalyScore, result.Decisions)
	}
}

// TestCuratedRuleDisablePropagates verifies that adding the parent
// sub-protection to the route's Disable list suppresses all rules that
// share it, including curated additions. Without this, a user who
// disabled rce-mail-protocol-injection for a route would still see
// blocks from curated rule 932300.
func TestCuratedRuleDisablePropagates(t *testing.T) {
	route := testRoute()
	route.Disable = map[string]bool{"rce-mail-protocol-injection": true}

	eng, err := NewEngine(route)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	r := httptest.NewRequest("GET",
		"http://example.com/test?to=%5Cr%5CnRCPT%20TO%3A%3Ca%40b.c%3E", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	result := eng.Evaluate(context.Background(), r)

	for _, d := range result.Decisions {
		if d.Protection == "rce-mail-protocol-injection" {
			t.Errorf("disabled sub-protection still produced a decision: %+v", d)
		}
		for _, id := range d.MatchedRules {
			if id == 932300 || id == 932301 || id == 932310 || id == 932311 || id == 932320 || id == 932321 {
				t.Errorf("curated mail-protocol rule %d fired for disabled route; decision=%+v", id, d)
			}
		}
	}
}
