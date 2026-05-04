// This file derives the CRS rule-to-leaf map from protections.Catalog
// and the curated rule list at package init. Do NOT add manual entries;
// add the rule to the appropriate catalog leaf's RuleIDs and (if
// curated) to internal/protections/crs/curated. The round-trip is
// enforced by TestCatalogCRSMappingCrossReference.

package crs

import (
	"strconv"

	"github.com/barbacana-waf/barbacana/internal/protections"
	"github.com/barbacana-waf/barbacana/internal/protections/crs/curated"
)

// ruleMapping maps each CRS rule ID to its canonical leaf name. Phase 3 of
// the taxonomy refactor: derived from protections.Catalog at package init
// time so the catalog is the single source of truth for which CRS rules
// belong to which leaf.
//
// Orchestration rules (paranoia markers, blocking eval, correlation) are
// not included — they are always-on and never exposed as leaves.
//
// Curated PL2/PL3 rule IDs are NOT listed here — they live in the
// curated subpackage as the single source of truth. RuleIDToSubProtection
// and DisabledRuleIDs consult both sources.
var ruleMapping = func() map[int]string {
	// Build the curated set once so we can exclude its IDs from the
	// derived mapping. Catalog leaves list every CRS rule that
	// contributes to the leaf (for audit and render purposes); the
	// derived ruleMapping is specifically the *non-curated* subset
	// because curated lookups go through curated.Lookup with priority
	// in RuleIDToSubProtection. Letting curated IDs survive both paths
	// would double-credit them in DisabledRuleIDs and create
	// attribution races.
	curatedIDs := map[int]bool{}
	for _, r := range curated.Rules {
		curatedIDs[r.ID] = true
	}

	m := map[int]string{}
	for _, g := range protections.Catalog {
		for _, l := range g.Leaves {
			collectRuleIDs(m, l, curatedIDs)
		}
		for _, b := range g.Buckets {
			for _, l := range b.Leaves {
				collectRuleIDs(m, l, curatedIDs)
			}
		}
	}
	return m
}()

func collectRuleIDs(m map[int]string, l protections.Leaf, curatedIDs map[int]bool) {
	for _, raw := range l.RuleIDs {
		if raw == "native" {
			continue
		}
		id, err := strconv.Atoi(raw)
		if err != nil {
			// Catalog integrity test (invariant 8) gates this: any non-numeric
			// non-"native" RuleIDs entry would already have failed in
			// internal/protections.TestCatalogIntegrity at build time.
			continue
		}
		if curatedIDs[id] {
			continue
		}
		m[id] = l.ID
	}
}


// RuleIDToSubProtection returns the canonical sub-protection name for a
// CRS rule ID, or "" if the rule is orchestration or unknown. The curated
// subpackage is consulted first so curated rule IDs always resolve to
// their declared Protection even if a future refactor reintroduces a
// duplicate entry in ruleMapping.
func RuleIDToSubProtection(id int) string {
	if name, ok := curated.Lookup(id); ok {
		return name
	}
	return ruleMapping[id]
}

// DisabledRuleIDs returns the set of CRS rule IDs that correspond to the
// given disabled sub-protection names. Used to build SecRuleRemoveById
// directives per route. Consults both the base mapping and the curated
// subpackage so disabling a parent sub-protection (e.g.
// "rce-mail-protocol-injection") suppresses curated rules too.
func DisabledRuleIDs(disabled map[string]bool) []int {
	var ids []int
	for id, sub := range ruleMapping {
		if disabled[sub] {
			ids = append(ids, id)
		}
	}
	for _, r := range curated.Rules {
		if disabled[r.Protection] {
			ids = append(ids, r.ID)
		}
	}
	return ids
}
