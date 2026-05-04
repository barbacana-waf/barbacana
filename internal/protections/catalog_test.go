package protections

import (
	"regexp"
	"strings"
	"testing"
)

// TestCatalogIntegrity enforces invariants 1-8, 10, and 12 of the taxonomy
// proposal (.planning/protection_taxonomy_proposal.md §invariants).
//
// Invariant 11 (CRS-mapping cross-reference) is enforced by
// TestCatalogCRSMappingCrossReference in internal/protections/crs/.
// Deferred to phase 3 to avoid circular import: the test must live in a
// package that imports both protections and crs, and crs's mapping data
// is rewritten in phase 3 — checking it earlier would assert against a
// mapping that hasn't been migrated yet. Phase 3 must end with that test
// green; otherwise stale references in either direction (catalog leaf
// with no mapping, or mapping pointing at a non-existent leaf) survive
// into phase 4 and surface as fixture-rename failures.
func TestCatalogIntegrity(t *testing.T) {
	ruleIDPattern := regexp.MustCompile(`^(\d{6}|native)$`)

	// Invariant 10 exception list. Two distinct categories — keep them
	// labeled so future maintainers don't conflate them. Source of truth:
	// .planning/protection_taxonomy_proposal.md §invariants invariant 10.
	//
	// Symmetry exceptions: single-leaf L2 retained because the family has
	// multiple L2s and uniform structure across them is more valuable than
	// minimum hierarchy.
	//
	// Reserved-for-growth exceptions: single-leaf L2 retained because the
	// bucket name reserves room for future leaves AND represents a real
	// conceptual division. Apply sparingly — the default is to flatten.
	singleLeafL2Exceptions := map[string]bool{
		// symmetry
		"java-data-leakage":                 true,
		"ruby-data-leakage":                 true,
		"ruby-injection":                    true,
		"iis-data-leakage":                  true,
		"command-injection-embedded-shells": true,
		// reserved-for-growth
		"cross-site-scripting-legacy-browsers": true,
	}

	// Dedup state shared across the whole catalog walk.
	seenLeaves := map[string]string{} // leaf ID → "L1/L2/leaf" location, for dup error messages
	seenGroups := map[string]bool{}
	seenL2s := map[string]bool{}

	for _, g := range Catalog {
		checkGroup(t, ruleIDPattern, seenLeaves, seenGroups, seenL2s, singleLeafL2Exceptions, g)
	}
}

func checkGroup(
	t *testing.T,
	ruleIDPattern *regexp.Regexp,
	seenLeaves map[string]string,
	seenGroups, seenL2s map[string]bool,
	singleLeafL2Exceptions map[string]bool,
	g Group,
) {
	t.Helper()

	// Invariant 2: Group.ID uniqueness.
	if seenGroups[g.ID] {
		t.Errorf("invariant 2: duplicate Group.ID %q", g.ID)
	}
	seenGroups[g.ID] = true

	// Invariant 6: a group is either flat (Leaves) or bucketed (Buckets), not both, not neither.
	hasBuckets, hasLeaves := len(g.Buckets) > 0, len(g.Leaves) > 0
	if hasBuckets == hasLeaves {
		t.Errorf("invariant 6: group %q must have exactly one of Buckets or Leaves (buckets=%d leaves=%d)",
			g.ID, len(g.Buckets), len(g.Leaves))
	}

	for _, l := range g.Leaves {
		checkLeaf(t, ruleIDPattern, seenLeaves, g, L2{}, l)
	}
	for _, b := range g.Buckets {
		checkBucket(t, ruleIDPattern, seenLeaves, seenL2s, singleLeafL2Exceptions, g, b)
	}
}

func checkBucket(
	t *testing.T,
	ruleIDPattern *regexp.Regexp,
	seenLeaves map[string]string,
	seenL2s map[string]bool,
	singleLeafL2Exceptions map[string]bool,
	g Group,
	b L2,
) {
	t.Helper()

	// Invariant 2: L2.ID uniqueness.
	if seenL2s[b.ID] {
		t.Errorf("invariant 2: duplicate L2.ID %q", b.ID)
	}
	seenL2s[b.ID] = true

	// Invariant 7: L2.ID starts with its parent Group.ID prefix.
	if !strings.HasPrefix(b.ID, g.ID+"-") && b.ID != g.ID {
		t.Errorf("invariant 7: L2 %q must start with parent Group %q prefix", b.ID, g.ID)
	}

	// Invariant 10: single-leaf L2s are forbidden unless explicitly excepted.
	if len(b.Leaves) == 1 && !singleLeafL2Exceptions[b.ID] {
		t.Errorf("invariant 10: L2 %q has a single leaf and is not in the exception list", b.ID)
	}

	for _, l := range b.Leaves {
		checkLeaf(t, ruleIDPattern, seenLeaves, g, b, l)
	}
}

func checkLeaf(t *testing.T, ruleIDPattern *regexp.Regexp, seen map[string]string, g Group, b L2, l Leaf) {
	t.Helper()
	loc := g.ID
	if b.ID != "" {
		loc = g.ID + "/" + b.ID
	}
	loc += "/" + l.ID

	// Invariant 1: Leaf.ID uniqueness across the whole catalog.
	if prev, ok := seen[l.ID]; ok {
		t.Errorf("invariant 1: duplicate Leaf.ID %q at %s and %s", l.ID, prev, loc)
	}
	seen[l.ID] = loc

	// Invariant 3: WhatItDoes non-empty.
	if l.WhatItDoes == "" {
		t.Errorf("invariant 3: leaf %s has empty WhatItDoes", loc)
	}

	// Invariants 4 & 5: WhyDisable / WhyEnable required by default state.
	if l.Default == On && l.WhyDisable == "" {
		t.Errorf("invariant 4: on-by-default leaf %s has empty WhyDisable", loc)
	}
	if l.Default == Off && l.WhyEnable == "" {
		t.Errorf("invariant 5: off-by-default leaf %s has empty WhyEnable", loc)
	}

	// Invariant 7 (leaf prefix): Leaf.ID starts with its L1 family prefix.
	if !strings.HasPrefix(l.ID, g.ID+"-") && l.ID != g.ID {
		t.Errorf("invariant 7: leaf %q must start with L1 family prefix %q",
			l.ID, g.ID)
	}

	// Invariant 8: every RuleIDs entry matches ^(\d{6}|native)$.
	if len(l.RuleIDs) == 0 {
		t.Errorf("invariant 8: leaf %s has empty RuleIDs", loc)
	}
	for _, id := range l.RuleIDs {
		if !ruleIDPattern.MatchString(id) {
			t.Errorf("invariant 8: leaf %s RuleIDs entry %q does not match ^(\\d{6}|native)$",
				loc, id)
		}
	}

}

// TestAggressiveSuffixIsOffByDefault is a soft naming-convention check:
// leaves whose ID ends in "-aggressive" denote FP-prone variants gated off
// by default. Not an invariant — convention only; failure indicates a
// reader-confusing name, not a runtime bug.
func TestAggressiveSuffixIsOffByDefault(t *testing.T) {
	for _, id := range AllLeafIDs() {
		if !strings.HasSuffix(id, "-aggressive") {
			continue
		}
		l, _, _, ok := LookupLeaf(id)
		if !ok {
			t.Fatalf("LookupLeaf(%q) failed", id)
		}
		if l.Default != Off {
			t.Errorf("naming convention: leaf %q ends in -aggressive but Default=%s (expected off)", id, l.Default)
		}
	}
}

// TestCatalogStats verifies invariant 12 — Stats() matches direct counts.
func TestCatalogStats(t *testing.T) {
	s := Stats()

	// Recompute independently and compare.
	var l1, l2, flat, total, on, off int
	l1 = len(Catalog)
	for _, g := range Catalog {
		if len(g.Leaves) > 0 {
			flat++
			for _, l := range g.Leaves {
				total++
				if l.Default == On {
					on++
				} else {
					off++
				}
			}
		}
		l2 += len(g.Buckets)
		for _, bk := range g.Buckets {
			for _, l := range bk.Leaves {
				total++
				if l.Default == On {
					on++
				} else {
					off++
				}
			}
		}
	}

	if s.L1Families != l1 {
		t.Errorf("Stats.L1Families = %d, want %d", s.L1Families, l1)
	}
	if s.L2Buckets != l2 {
		t.Errorf("Stats.L2Buckets = %d, want %d", s.L2Buckets, l2)
	}
	if s.FlatL1s != flat {
		t.Errorf("Stats.FlatL1s = %d, want %d", s.FlatL1s, flat)
	}
	if s.TotalLeaves != total {
		t.Errorf("Stats.TotalLeaves = %d, want %d", s.TotalLeaves, total)
	}
	if s.OnLeaves != on {
		t.Errorf("Stats.OnLeaves = %d, want %d", s.OnLeaves, on)
	}
	if s.OffLeaves != off {
		t.Errorf("Stats.OffLeaves = %d, want %d", s.OffLeaves, off)
	}
}

// TestRenderMarkdown smoke-tests RenderMarkdown by checking that every leaf
// ID appears in the output and that L1/L2 headings render.
func TestRenderMarkdown(t *testing.T) {
	out := RenderMarkdown()
	if !strings.Contains(out, "# WAF Protection Catalog") {
		t.Error("RenderMarkdown output missing top-level title")
	}
	for _, g := range Catalog {
		if !strings.Contains(out, "## "+g.ID) {
			t.Errorf("RenderMarkdown output missing L1 heading for %q", g.ID)
		}
		for _, b := range g.Buckets {
			if !strings.Contains(out, "### "+b.ID) {
				t.Errorf("RenderMarkdown output missing L2 heading for %q", b.ID)
			}
		}
	}
	for _, id := range AllLeafIDs() {
		if !strings.Contains(out, "`"+id+"`") {
			t.Errorf("RenderMarkdown output missing leaf %q", id)
		}
	}
}

// TestRenderLeaf smoke-tests RenderLeaf for a known leaf and an unknown one.
func TestRenderLeaf(t *testing.T) {
	ids := AllLeafIDs()
	if len(ids) == 0 {
		t.Fatal("Catalog has no leaves; cannot run RenderLeaf smoke test")
	}
	out, err := RenderLeaf(ids[0])
	if err != nil {
		t.Fatalf("RenderLeaf(%q) returned unexpected error: %v", ids[0], err)
	}
	if !strings.Contains(out, "# "+ids[0]) {
		t.Errorf("RenderLeaf output missing leaf-name heading for %q", ids[0])
	}
	if !strings.Contains(out, "## What it does") {
		t.Errorf("RenderLeaf output missing What-it-does section")
	}

	if _, err := RenderLeaf("does-not-exist"); err == nil {
		t.Error("RenderLeaf for unknown leaf returned nil error; want ErrLeafNotFound")
	}
}
