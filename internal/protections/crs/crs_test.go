package crs

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/barbacana-waf/barbacana/internal/config"
)

func testRoute() config.Resolved {
	return config.Resolved{
		ID:      "test",
		Mode:    config.ModeBlocking,
		Disable: map[string]bool{},
		Inspection: config.ResolvedInspection{
			EvaluationTimeout:       5 * time.Second,
			MaxInspectSize:          128 * 1024,
			MaxMemoryBuffer:         128 * 1024,
			DecompressionRatioLimit: 100,
			JSONDepth:               20,
			JSONKeys:                1000,
			XMLDepth:                20,
			XMLEntities:             100,
		},
	}
}

// buildSetupDirectives must emit a SecAction that sets tx.allowed_methods
// from route.Accept.Methods. Otherwise CRS's REQUEST-901 fallback applies
// "GET HEAD POST OPTIONS" and rule 911100 blocks PUT/PATCH/DELETE with a
// critical anomaly score, even though the route config claims they are
// allowed.
func TestBuildSetupDirectivesWiresAllowedMethods(t *testing.T) {
	route := testRoute()
	route.Accept.Methods = []string{"GET", "POST", "put", "PATCH", "delete", "HEAD", "OPTIONS"}

	got, err := buildSetupDirectives(route)
	if err != nil {
		t.Fatalf("buildSetupDirectives: %v", err)
	}
	want := "setvar:'tx.allowed_methods=GET POST PUT PATCH DELETE HEAD OPTIONS'"
	if !strings.Contains(got, want) {
		t.Errorf("setup directives missing %q\n--- got ---\n%s", want, got)
	}
}

func TestNewEngine(t *testing.T) {
	route := testRoute()
	eng, err := NewEngine(route)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if eng == nil {
		t.Fatal("engine is nil")
	}
}

func TestEvaluateSQLi(t *testing.T) {
	route := testRoute()
	eng, err := NewEngine(route)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Use a classic SQLi payload with proper URL encoding.
	r := httptest.NewRequest("GET", "http://example.com/test?id=1%27+OR+%271%27%3D%271", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	result := eng.Evaluate(context.Background(), r)

	if len(result.Decisions) == 0 {
		t.Fatal("expected CRS to match SQLi payload, got 0 decisions")
	}

	foundSQLi := false
	for _, d := range result.Decisions {
		t.Logf("decision: block=%v protection=%s reason=%s", d.Block, d.Protection, d.Reason)
		if strings.HasPrefix(d.Protection, "sql-injection-") {
			foundSQLi = true
		}
	}
	if !foundSQLi {
		t.Errorf("expected sql-injection sub-protection match, got: %+v", result.Decisions)
	}
}

func TestEvaluateCleanRequest(t *testing.T) {
	route := testRoute()
	eng, err := NewEngine(route)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	r := httptest.NewRequest("GET", "http://example.com/api/users", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	result := eng.Evaluate(context.Background(), r)

	for _, d := range result.Decisions {
		if d.Block {
			t.Errorf("clean request should not be blocked, got: %+v", d)
		}
	}
}

func TestEvaluateWithDisabledProtection(t *testing.T) {
	route := testRoute()
	// Disable every leaf in the sql-injection L2 bucket (new taxonomy).
	route.Disable = map[string]bool{
		"sql-injection":                           true, // legacy bridge: still in legacy.go, harmless if present
		"sql-injection-generic":                   true,
		"sql-injection-generic-aggressive":        true,
		"sql-injection-operators":                 true,
		"sql-injection-function-calls":            true,
		"sql-injection-system-schema-names":       true,
		"sql-injection-sql-comments":              true,
		"sql-injection-comments-in-json":          true,
		"sql-injection-backticks":                 true,
		"sql-injection-hex-encoded":               true,
		"sql-injection-string-concatenation":      true,
		"sql-injection-special-character-density": true,
		"sql-injection-time-based":                true,
		"sql-injection-always-true":               true,
		"sql-injection-union-select":              true,
		"sql-injection-if-statements":             true,
		"sql-injection-multiple-statements":       true,
		"sql-injection-query-closers":             true,
		"sql-injection-overflow-probes":           true,
		"sql-injection-login-bypass":              true,
		"sql-injection-quotes-in-text":            true,
		"sql-injection-mssql-specific":            true,
		"sql-injection-stored-procedures":         true,
		"sql-injection-mongodb-operators":         true,
		"sql-injection-json-operators":            true,
		"sql-injection-scientific-notation":       true,
	}

	eng, err := NewEngine(route)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	r := httptest.NewRequest("GET", "http://example.com/test?id=1'+OR+'1'='1", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	result := eng.Evaluate(context.Background(), r)

	for _, d := range result.Decisions {
		if d.Block && (d.Protection == "sql-injection-login-bypass" ||
			d.Protection == "sql-injection-always-true" ||
			d.Protection == "sql-injection-generic") {
			t.Errorf("disabled sql-injection should not trigger, got: %+v", d)
		}
	}
}

func TestAnomalyScore(t *testing.T) {
	route := testRoute()
	eng, err := NewEngine(route)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	r := httptest.NewRequest("GET", "http://example.com/test?id=1%27+OR+%271%27%3D%271", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	result := eng.Evaluate(context.Background(), r)

	if result.AnomalyScore == 0 && len(result.Decisions) > 0 {
		t.Errorf("expected non-zero anomaly score when rules match, got 0")
	}
	t.Logf("anomaly score: %d, decisions: %d", result.AnomalyScore, len(result.Decisions))
}

func TestRuleIDToSubProtection(t *testing.T) {
	cases := []struct {
		ruleID int
		want   string
	}{
		{942100, "sql-injection-generic"},
		{941110, "cross-site-scripting-script-tags"},
		{913100, "scanner-detection-user-agent"},
		{955100, "web-shell-detection"},
		{955400, "web-shell-detection"},
		{956100, "ruby-data-leakage-version-info"},
		{956110, "ruby-data-leakage-source-code"},
		{901000, ""},  // orchestration, not mapped
		{955010, ""},  // 955 content-encoding gate (orchestration)
		{955011, ""},  // 955 paranoia marker (orchestration)
		{956010, ""},  // 956 content-encoding gate (orchestration)
		{980099, ""},  // 980 correlation rule (orchestration)
		{980170, ""},  // 980 correlation rule (orchestration)
	}
	for _, tc := range cases {
		got := RuleIDToSubProtection(tc.ruleID)
		if got != tc.want {
			t.Errorf("RuleIDToSubProtection(%d) = %q, want %q", tc.ruleID, got, tc.want)
		}
	}
}

func TestDisabledRuleIDs(t *testing.T) {
	disabled := map[string]bool{"scanner-detection-user-agent": true}
	ids := DisabledRuleIDs(disabled)
	if len(ids) != 1 || ids[0] != 913100 {
		t.Errorf("DisabledRuleIDs = %v, want [913100]", ids)
	}
}

func TestDisabledRuleIDsWebShell(t *testing.T) {
	disabled := map[string]bool{"web-shell-detection": true}
	ids := DisabledRuleIDs(disabled)
	// 955xxx file has 27 detection rules (paranoia markers are orchestration,
	// not included in the mapping).
	if len(ids) != 27 {
		t.Errorf("DisabledRuleIDs for web-shell-detection returned %d IDs, want 27", len(ids))
	}
	for _, id := range ids {
		if id < 955100 || id > 955400 {
			t.Errorf("web-shell-detection rule %d out of expected 955100-955400 range", id)
		}
	}
}

func TestDisabledRuleIDsRubyDataLeakage(t *testing.T) {
	// ruby-data-leakage-version-info and ruby-data-leakage-source-code
	// are now distinct leaves; disabling each individually maps to one
	// CRS rule. (The legacy single "data-leakage-ruby" sub-protection
	// covered both 956100 and 956110.)
	cases := []struct {
		leaf string
		want int
	}{
		{"ruby-data-leakage-version-info", 956100},
		{"ruby-data-leakage-source-code", 956110},
	}
	for _, tc := range cases {
		ids := DisabledRuleIDs(map[string]bool{tc.leaf: true})
		if len(ids) != 1 || ids[0] != tc.want {
			t.Errorf("DisabledRuleIDs(%q) = %v, want [%d]", tc.leaf, ids, tc.want)
		}
	}
}

// SubProtectionCategory remains useful only against the legacy two-level
// catalog while the legacy bridge survives. Phase 4 deletes both the
// function and this test.
