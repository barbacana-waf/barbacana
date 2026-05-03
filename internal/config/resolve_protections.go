package config

import (
	"github.com/barbacana-waf/barbacana/internal/protections"
)

// resolveDisableEnable computes the per-route effective protection state
// from the four user-provided lists (global disable/enable, route
// disable/enable). Returns a map keyed by leaf ID where true means the
// leaf is effectively OFF for this route. The map additionally
// preserves every literal L1/L2/leaf ID that appeared in either
// disable list, so legacy callers that look up by L1/L2 name (e.g.
// `disable["sql-injection"]` to ask "did the user drop the L2?")
// continue to work.
//
// Resolution rule — more-specific-wins, with route-over-global as tie
// breaker on equal specificity. For each leaf, walk every directive
// (across both layers, both disable and enable) that *covers* the leaf
// (the directive's ID equals the leaf's L1, L2, or leaf ID). Pick the
// directive with the highest specificity; on ties, the directive from
// the route layer wins. The chosen directive's polarity (disable vs
// enable) sets the effective state. If no directive covers the leaf,
// the leaf's catalog Default is used.
//
// L2 enable semantics: enabling an L2 covers every leaf in that bucket;
// already-on leaves stay on (the directive matches them but yields the
// same state, so it's a no-op). A leaf-level disable in the same scope
// or a route-layer override beats the L2 enable per the precedence
// rule.
//
// Same-level conflicts (literal name in both disable and enable at the
// same layer) are caught by validateNoSameLevelConflict at config-load
// time, not here.
func resolveDisableEnable(globalDisable, globalEnable, routeDisable, routeEnable []string) map[string]bool {
	type directive struct {
		id          string // L1, L2, or leaf
		enable      bool   // true = enable, false = disable
		layer       int    // 0 = global, 1 = route
		specificity int    // 0 = L1, 1 = L2, 2 = leaf
	}

	// Catalog the universe once.
	type leafLoc struct {
		l1, l2, id string
	}
	var leafLocs []leafLoc
	for _, g := range protections.Catalog {
		for _, l := range g.Leaves {
			leafLocs = append(leafLocs, leafLoc{l1: g.ID, id: l.ID})
		}
		for _, b := range g.Buckets {
			for _, l := range b.Leaves {
				leafLocs = append(leafLocs, leafLoc{l1: g.ID, l2: b.ID, id: l.ID})
			}
		}
	}

	// Catalog ID → specificity, for quickly classifying user-provided IDs.
	specs := map[string]int{}
	for _, g := range protections.Catalog {
		specs[g.ID] = 0
		for _, b := range g.Buckets {
			specs[b.ID] = 1
			for _, l := range b.Leaves {
				specs[l.ID] = 2
			}
		}
		for _, l := range g.Leaves {
			specs[l.ID] = 2
		}
	}

	directives := make([]directive, 0, len(globalDisable)+len(globalEnable)+len(routeDisable)+len(routeEnable))
	addDir := func(ids []string, layer int, enable bool) {
		for _, id := range ids {
			s, ok := specs[id]
			if !ok {
				continue // validate.go already errored on unknown names; skip silently here
			}
			directives = append(directives, directive{id: id, enable: enable, layer: layer, specificity: s})
		}
	}
	addDir(globalDisable, 0, false)
	addDir(globalEnable, 0, true)
	addDir(routeDisable, 1, false)
	addDir(routeEnable, 1, true)

	// Per-leaf evaluation.
	defaultOn := func(leafID string) bool {
		leaf, _, _, ok := protections.LookupLeaf(leafID)
		if !ok {
			return false
		}
		return leaf.Default == protections.On
	}

	result := map[string]bool{}
	for _, loc := range leafLocs {
		// Find the most-specific covering directive; tie-break by layer.
		var best *directive
		for i := range directives {
			d := &directives[i]
			if d.id != loc.id && d.id != loc.l1 && (loc.l2 == "" || d.id != loc.l2) {
				continue
			}
			if best == nil ||
				d.specificity > best.specificity ||
				(d.specificity == best.specificity && d.layer > best.layer) {
				best = d
			}
		}

		effectiveOn := defaultOn(loc.id)
		if best != nil {
			effectiveOn = best.enable
		}
		if !effectiveOn {
			result[loc.id] = true
		}
	}

	// Preserve literal L1/L2 IDs from disable lists so legacy lookups
	// by family/bucket name (e.g. `disable["sql-injection"]`) still
	// work for the duration of phase 4. Bridge entries are confined to
	// non-leaf specificities so they cannot clobber the per-leaf
	// resolution above — a route enable that wins the tie-break
	// against a global disable on a leaf must remain ON in the
	// resolved map even when the same leaf ID appears in the global
	// disable list (the bridge would otherwise re-stamp it false).
	// Phase 4 ends with the legacy bridge gone; until then the L1/L2
	// half is what pipeline/CRS code still consults in a few spots.
	for _, id := range globalDisable {
		if s, ok := specs[id]; ok && s < 2 {
			result[id] = true
		}
	}
	for _, id := range routeDisable {
		if s, ok := specs[id]; ok && s < 2 {
			result[id] = true
		}
	}

	return result
}
