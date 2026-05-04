package curated

import "testing"

// TestRulesNoDuplicateIDs guards against a typo in Rules that would
// silently let SecRuleRemoveById emit the same ID twice or Lookup
// return the wrong protection for one of the duplicates.
func TestRulesNoDuplicateIDs(t *testing.T) {
	seen := make(map[int]string, len(Rules))
	for _, r := range Rules {
		if prior, ok := seen[r.ID]; ok {
			t.Errorf("rule ID %d declared twice: %q and %q", r.ID, prior, r.Protection)
		}
		seen[r.ID] = r.Protection
	}
}

// TestRulesProtectionsNonEmpty catches a future edit that accidentally
// leaves the Protection field blank — a curated match with no name
// drops silently out of audit logs.
func TestRulesProtectionsNonEmpty(t *testing.T) {
	for _, r := range Rules {
		if r.Protection == "" {
			t.Errorf("rule %d has empty Protection", r.ID)
		}
	}
}

func TestLookup(t *testing.T) {
	if got, ok := Lookup(932300); !ok || got != "mail-protocol-injection" {
		t.Errorf("Lookup(932300) = %q, %v; want mail-protocol-injection, true", got, ok)
	}
	if _, ok := Lookup(1); ok {
		t.Errorf("Lookup(1) should return ok=false")
	}
}

func TestIDsLengthMatchesRules(t *testing.T) {
	if got, want := len(IDs()), len(Rules); got != want {
		t.Errorf("IDs() returned %d IDs, Rules has %d", got, want)
	}
}

// TestSeverityOverridesAreValid pins that any Rule.Severity override
// uses one of the four CRS-recognized severity tokens. cmd/tools/rules
// rejects unknown severities at extraction time; this test surfaces the
// failure earlier (at unit-test time, before someone runs `make rules`)
// and locally to the curated package so a typo doesn't drift through.
func TestSeverityOverridesAreValid(t *testing.T) {
	allowed := map[string]bool{
		"":         true, // empty = use CRS-authored severity, no override
		"CRITICAL": true,
		"ERROR":    true,
		"WARNING":  true,
		"NOTICE":   true,
	}
	for _, r := range Rules {
		if !allowed[r.Severity] {
			t.Errorf("rule %d (%s) has invalid Severity %q; expect one of {CRITICAL, ERROR, WARNING, NOTICE} or empty", r.ID, r.Protection, r.Severity)
		}
	}
}
