package crs

import (
	"testing"

	"github.com/barbacana-waf/barbacana/internal/protections"
	"github.com/barbacana-waf/barbacana/internal/protections/crs/curated"
)

// TestCatalogCRSMappingCrossReference enforces invariant 11 of the
// taxonomy proposal (.planning/protection_taxonomy_proposal.md
// §invariants): every leaf in protections.Catalog with non-native
// RuleIDs is reachable from internal/protections/crs's mapping (either
// the derived ruleMapping or the curated set), and every entry in the
// crs mapping resolves to a leaf that exists in the catalog.
//
// Because ruleMapping is now derived from Catalog (see mapping.go), one
// half of the cross-reference is structural; the test still asserts it
// explicitly to catch a future refactor that breaks the derivation, and
// to verify the curated-set side which lives in its own subpackage.
func TestCatalogCRSMappingCrossReference(t *testing.T) {
	// Build the set of all known catalog leaf IDs once.
	catalogLeaves := map[string]bool{}
	for _, id := range protections.AllLeafIDs() {
		catalogLeaves[id] = true
	}

	// (a) Forward: every catalog leaf with non-native RuleIDs is reachable
	// from RuleIDToSubProtection for every one of those rule IDs.
	t.Run("catalog_leaves_resolvable", func(t *testing.T) {
		for _, gid := range protections.AllLeafIDs() {
			leaf, _, _, ok := protections.LookupLeaf(gid)
			if !ok {
				t.Fatalf("LookupLeaf(%q) returned ok=false", gid)
			}
			for _, raw := range leaf.RuleIDs {
				if raw == "native" {
					continue
				}
				ruleID := mustAtoi(t, raw, leaf.ID)
				got := RuleIDToSubProtection(ruleID)
				if got == "" {
					t.Errorf("leaf %q lists rule %d but RuleIDToSubProtection returns empty",
						leaf.ID, ruleID)
				} else if got != leaf.ID {
					// Curated rules legitimately resolve to a different leaf
					// than the catalog's listed one (e.g., rule 942180 is
					// curated under sql-injection-login-bypass, but the
					// derived ruleMapping wouldn't see it because curated
					// IDs aren't in the catalog's RuleIDs slices).
					if _, isCurated := curated.Lookup(ruleID); !isCurated {
						t.Errorf("rule %d listed under leaf %q but resolves to %q",
							ruleID, leaf.ID, got)
					}
				}
			}
		}
	})

	// (b) Reverse: every curated entry resolves to a catalog leaf.
	t.Run("curated_entries_in_catalog", func(t *testing.T) {
		for _, r := range curated.Rules {
			if !catalogLeaves[r.Protection] {
				t.Errorf("curated rule %d points at protection %q but no catalog leaf has that ID",
					r.ID, r.Protection)
			}
		}
	})

	// (c) Reverse for the derived map: every entry in ruleMapping points
	// at a catalog leaf. (Tautological under the current derivation; the
	// assertion guards a future refactor.)
	t.Run("rulemapping_entries_in_catalog", func(t *testing.T) {
		for ruleID, leafName := range ruleMapping {
			if !catalogLeaves[leafName] {
				t.Errorf("ruleMapping[%d] = %q but no catalog leaf has that ID",
					ruleID, leafName)
			}
		}
	})

	// (d) No overlap: a curated rule ID must not also live in ruleMapping.
	// If it did, DisabledRuleIDs would emit it twice, and an attribution
	// race could attach it to either Protection name.
	t.Run("no_curated_rulemapping_overlap", func(t *testing.T) {
		for _, r := range curated.Rules {
			if name, ok := ruleMapping[r.ID]; ok {
				t.Errorf("rule %d appears in both curated.Rules (as %q) and ruleMapping (as %q)",
					r.ID, r.Protection, name)
			}
		}
	})
}

func mustAtoi(t *testing.T, s, ctx string) int {
	t.Helper()
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("rule ID %q in leaf %q is non-numeric", s, ctx)
		}
		n = n*10 + int(c-'0')
	}
	return n
}
