package crs

import (
	"context"
	"testing"

	"github.com/corazawaf/coraza/v3/types"
)

// contentTypeTrickLeaf owns CRS 922140/922150, the severity-less `pass`
// helpers that set up state for 922110. They match on any multipart body —
// including a clean upload — and run before every attack rule, which is why
// match order alone is the wrong way to attribute a block.
const contentTypeTrickLeaf = "file-upload-attacks-content-type-trick"

func TestSeverityScore(t *testing.T) {
	cases := []struct {
		sev  types.RuleSeverity
		want int
	}{
		{types.RuleSeverityCritical, 5},
		{types.RuleSeverityError, 4},
		{types.RuleSeverityWarning, 3},
		{types.RuleSeverityNotice, 2},
		// A rule with no severity action: CRS's pass/nolog setvar helpers.
		{types.RuleSeverityUnset, 0},
		{types.RuleSeverityInfo, 0},
		{types.RuleSeverityDebug, 0},
	}
	for _, c := range cases {
		if got := severityScore(c.sev); got != c.want {
			t.Errorf("severityScore(%v) = %d, want %d", c.sev, got, c.want)
		}
	}
}

// TestBlockAttributedToHeaviestLeaf pins which leaf a block is reported
// under. The pipeline acts on the first blocking decision, and that name is
// what reaches the audit log, RequestsBlockedTotal and the status code — so
// it must name the protection that earned the block, not whichever mapped
// rule happened to match first.
//
// Every one of these bodies is multipart, so every one also matches 922140
// (file-upload-attacks-content-type-trick, zero score) well before the
// 211xxx/212xxx rules, which load last of all. Before decisions were
// ordered by anomaly weight, all of these PHP2Shell blocks were reported as
// file-upload-attacks-content-type-trick / CWE-444 and the leaf that
// blocked them appeared nowhere — not in the audit log, not in the metrics.
func TestBlockAttributedToHeaviestLeaf(t *testing.T) {
	eng, err := NewEngine(testRoute())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	markerCT, markerBody := multipartBody(t, []multipartPart{
		{name: php2ShellField, value: "123"},
		{name: "comment", value: "hello"},
	})

	cases := []struct {
		name     string
		wantLeaf string
		wantRule int
		eval     func() EvaluationResult
	}{
		{
			name:     "upload-progress marker field",
			wantLeaf: php2ShellLeaf,
			wantRule: php2ShellRuleID,
			eval: func() EvaluationResult {
				return eng.Evaluate(context.Background(),
					php2ShellRequest("POST", "/upload", markerCT, markerBody))
			},
		},
		{
			name:     "part-header flood",
			wantLeaf: partHeadersLeaf,
			wantRule: partHeaderCountRule,
			eval: func() EvaluationResult {
				body := rawMultipart([]rawPart{fieldPart("x", "v", padHeaders(4000)...)})
				return eng.Evaluate(context.Background(), shapeRequest(body))
			},
		},
		{
			name:     "empty file controls",
			wantLeaf: emptyFileControlLeaf,
			wantRule: emptyFileControlRule,
			eval: func() EvaluationResult {
				body := rawMultipart(emptyFileControls(21))
				return eng.Evaluate(context.Background(), shapeRequest(body))
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := c.eval()
			if len(res.Decisions) == 0 {
				t.Fatalf("no decisions returned")
			}
			first := res.Decisions[0]
			if !first.Block {
				t.Fatalf("first decision is not a block: %+v", res.Decisions)
			}
			if first.Protection != c.wantLeaf {
				t.Errorf("block attributed to %q, want %q; decisions=%+v",
					first.Protection, c.wantLeaf, res.Decisions)
			}
			if !containsRuleID(first.MatchedRules, c.wantRule) {
				t.Errorf("rule %d missing from the attributed decision's matched rules; decisions=%+v",
					c.wantRule, res.Decisions)
			}
			if first.Reason == "" {
				t.Errorf("attributed decision has an empty reason (a nolog helper's message leaked through); decisions=%+v",
					res.Decisions)
			}
			// The zero-score multipart helper still matched; it just must
			// not be the leaf the block is reported under. If it stops
			// matching these bodies this test has lost its teeth.
			if !hasProtection(res, contentTypeTrickLeaf) {
				t.Errorf("expected %q among the decisions (922140 matches any multipart body); decisions=%+v",
					contentTypeTrickLeaf, res.Decisions)
			}
		})
	}
}

// TestDecisionsOrderedByAnomalyWeight checks the ordering rule directly on
// a request that matches leaves of differing weight: a critical PHP
// open-tag match must outrank the zero-score multipart helper.
func TestDecisionsOrderedByAnomalyWeight(t *testing.T) {
	eng, err := NewEngine(testRoute())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ct, body := multipartBody(t, []multipartPart{
		{name: "code", value: "<?php echo 1; ?>"},
	})
	res := eng.Evaluate(context.Background(), php2ShellRequest("POST", "/upload", ct, body))

	if len(res.Decisions) < 2 {
		t.Fatalf("expected both the PHP match and the multipart helper; decisions=%+v", res.Decisions)
	}
	if res.Decisions[0].Protection == contentTypeTrickLeaf {
		t.Errorf("zero-score helper leaf sorted first; decisions=%+v", res.Decisions)
	}
	if !hasProtection(res, contentTypeTrickLeaf) {
		t.Errorf("expected %q among the decisions; decisions=%+v", contentTypeTrickLeaf, res.Decisions)
	}
}

func containsRuleID(ids []int, want int) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func hasProtection(res EvaluationResult, leaf string) bool {
	for _, d := range res.Decisions {
		if d.Protection == leaf {
			return true
		}
	}
	return false
}
