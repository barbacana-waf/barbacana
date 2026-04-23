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
	// Disable all sql-injection sub-protections.
	route.Disable = map[string]bool{
		"sql-injection":               true,
		"sql-injection-auth-bypass":   true,
		"sql-injection-boolean":       true,
		"sql-injection-libinjection":  true,
		"sql-injection-operator":      true,
		"sql-injection-common-dbnames": true,
		"sql-injection-function":      true,
		"sql-injection-blind":         true,
		"sql-injection-mssql":         true,
		"sql-injection-integer-overflow": true,
		"sql-injection-conditional":   true,
		"sql-injection-chained":       true,
		"sql-injection-union":         true,
		"sql-injection-nosql":         true,
		"sql-injection-stored-procedure": true,
		"sql-injection-classic-probe": true,
		"sql-injection-concat":        true,
		"sql-injection-char-anomaly":  true,
		"sql-injection-comment":       true,
		"sql-injection-hex-encoding":  true,
		"sql-injection-tick-bypass":   true,
		"sql-injection-termination":   true,
		"sql-injection-json":          true,
		"sql-injection-scientific-notation": true,
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
		if d.Block && (d.Protection == "sql-injection-auth-bypass" ||
			d.Protection == "sql-injection-boolean" ||
			d.Protection == "sql-injection-libinjection") {
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
		{942100, "sql-injection-libinjection"},
		{941110, "xss-script-tag"},
		{913100, "scanner-detection-user-agent"},
		{955100, "web-shell-detection"},
		{955400, "web-shell-detection"},
		{956100, "data-leakage-ruby"},
		{956110, "data-leakage-ruby"},
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

func TestDisabledRuleIDsDataLeakageRuby(t *testing.T) {
	disabled := map[string]bool{"data-leakage-ruby": true}
	ids := DisabledRuleIDs(disabled)
	if len(ids) != 2 {
		t.Errorf("DisabledRuleIDs for data-leakage-ruby returned %d IDs, want 2", len(ids))
	}
	want := map[int]bool{956100: true, 956110: true}
	for _, id := range ids {
		if !want[id] {
			t.Errorf("unexpected rule ID for data-leakage-ruby: %d", id)
		}
	}
}

func TestSubProtectionCategoryNewCategories(t *testing.T) {
	cases := []struct {
		sub      string
		wantCat  string
	}{
		{"web-shell-detection", "web-shell"},
		{"data-leakage-ruby", "data-leakage-ruby"},
		{"data-leakage-java-error", "data-leakage-java"},
	}
	for _, tc := range cases {
		got := SubProtectionCategory(tc.sub)
		if got != tc.wantCat {
			t.Errorf("SubProtectionCategory(%q) = %q, want %q", tc.sub, got, tc.wantCat)
		}
	}
}
