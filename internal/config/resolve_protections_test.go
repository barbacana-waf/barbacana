package config

import "testing"

// TestEnableDisableInteraction covers the precedence rule
// (more-specific-wins, with route-over-global as tie breaker on equal
// specificity) across the L1 / L2 / leaf × disable / enable × global /
// route matrix. Source of truth:
// .planning/protection_taxonomy_proposal.md §"Enable and disable lists"
// (lines 142-181) and PLAN.md §2.2.
//
// The matrix is intentionally exhaustive on the tricky cases. Read each
// row top to bottom: directives applied, then asserted final state for
// the named leaves.
func TestEnableDisableInteraction(t *testing.T) {
	type leafState struct {
		leaf string
		off  bool // true = effectively disabled
	}
	cases := []struct {
		name        string
		gDisable    []string
		gEnable     []string
		rDisable    []string
		rEnable     []string
		assertions  []leafState
	}{
		// ── Single-layer cases ─────────────────────────────────────

		{
			name:     "L1 disable drops the whole family",
			gDisable: []string{"sql"},
			assertions: []leafState{
				{"sql-injection-generic", true},
				{"sql-data-leakage-mssql", true},
				{"javascript-injection-eval", false}, // unrelated leaf untouched
			},
		},
		{
			name:     "L2 disable drops the bucket but not the sibling bucket",
			gDisable: []string{"sql-injection"},
			assertions: []leafState{
				{"sql-injection-generic", true},
				{"sql-injection-union-select", true},
				{"sql-data-leakage-mssql", false}, // sibling L2 stays on
			},
		},
		{
			name:     "leaf disable affects only the leaf",
			gDisable: []string{"sql-injection-union-select"},
			assertions: []leafState{
				{"sql-injection-union-select", true},
				{"sql-injection-generic", false}, // sibling leaf stays on
			},
		},
		{
			name:    "leaf enable turns on an off-by-default leaf",
			gEnable: []string{"sql-injection-quotes-in-text"},
			assertions: []leafState{
				{"sql-injection-quotes-in-text", false}, // now effectively on
			},
		},
		{
			name:    "L2 enable turns on every off-by-default leaf in bucket",
			gEnable: []string{"sql-injection"},
			assertions: []leafState{
				{"sql-injection-quotes-in-text", false}, // off-by-default → on
				{"sql-injection-comments-in-json", false},
				{"sql-injection-generic", false}, // already on stays on (no-op)
			},
		},

		// ── More-specific-wins (within a single layer) ─────────────

		{
			name:     "L1 disable + leaf enable: leaf wins (proposal example)",
			gDisable: []string{"sql"},
			gEnable:  []string{"sql-injection-union-select"},
			assertions: []leafState{
				{"sql-injection-union-select", false}, // leaf enable wins
				{"sql-injection-generic", true},       // family-wide disable holds
			},
		},
		{
			name:     "L2 disable + leaf enable: leaf wins",
			gDisable: []string{"sql-injection"},
			gEnable:  []string{"sql-injection-union-select"},
			assertions: []leafState{
				{"sql-injection-union-select", false},
				{"sql-injection-generic", true},
			},
		},
		{
			name:     "L1 disable + L2 enable: L2 wins for that bucket only",
			gDisable: []string{"sql"},
			gEnable:  []string{"sql-injection"},
			assertions: []leafState{
				{"sql-injection-generic", false},  // L2 enable wins
				{"sql-injection-union-select", false},
				{"sql-data-leakage-mssql", true},  // sibling bucket still off
			},
		},
		{
			name:     "L2 enable + leaf disable: leaf wins",
			gEnable:  []string{"sql-injection"},
			gDisable: []string{"sql-injection-quotes-in-text"},
			assertions: []leafState{
				{"sql-injection-quotes-in-text", true},   // leaf disable wins
				{"sql-injection-comments-in-json", false}, // bucket-wide enable holds
			},
		},

		// ── Cross-layer (route overrides global) ───────────────────

		{
			name:     "global disable + route enable at same specificity: route wins",
			gDisable: []string{"sql"},
			rEnable:  []string{"sql"},
			assertions: []leafState{
				{"sql-injection-generic", false},
				{"sql-data-leakage-mssql", false},
			},
		},
		{
			name:     "global disable + route disable of leaf: leaf disable adds to family disable",
			gDisable: []string{"sql"},
			rDisable: []string{"javascript-injection-eval"},
			assertions: []leafState{
				{"sql-injection-generic", true},      // global L1 disable holds
				{"javascript-injection-eval", true},  // route leaf disable
				{"javascript-prototype-pollution", false}, // unrelated leaf in same family stays on
			},
		},
		{
			name:     "global L1 disable + route leaf enable: leaf wins regardless of layer",
			gDisable: []string{"sql"},
			rEnable:  []string{"sql-injection-backticks"},
			assertions: []leafState{
				{"sql-injection-backticks", false},  // leaf enable wins
				{"sql-injection-generic", true},     // family disable holds
			},
		},
		{
			name:     "global leaf disable + route L2 enable: leaf wins (specificity beats layer)",
			gDisable: []string{"sql-injection-backticks"},
			rEnable:  []string{"sql-injection"},
			assertions: []leafState{
				{"sql-injection-backticks", true},   // global leaf disable wins
				{"sql-injection-quotes-in-text", false}, // L2 enable lifts other off-by-default leaves
			},
		},

		// ── Default state preserved when no directive applies ──────

		{
			name:    "no directives: catalog defaults preserved",
			assertions: []leafState{
				{"sql-injection-generic", false},        // default on
				{"sql-injection-quotes-in-text", true},  // default off
				{"response-headers-add-hsts", false},    // default on
				{"response-headers-add-coop", true},     // default off (per the catalog as transcribed)
			},
		},

		// ── No-op for already-default-state directive ──────────────

		{
			name:    "leaf already-on appearing in enable: no-op",
			gEnable: []string{"sql-injection-generic"}, // already default-on
			assertions: []leafState{
				{"sql-injection-generic", false}, // unchanged
			},
		},
		{
			name:     "leaf already-off appearing in disable: no-op",
			gDisable: []string{"sql-injection-quotes-in-text"}, // already default-off
			assertions: []leafState{
				{"sql-injection-quotes-in-text", true}, // unchanged
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			disable := resolveDisableEnable(tc.gDisable, tc.gEnable, tc.rDisable, tc.rEnable)
			for _, want := range tc.assertions {
				got := disable[want.leaf]
				if got != want.off {
					t.Errorf("leaf %q: effective off = %v, want %v",
						want.leaf, got, want.off)
				}
			}
		})
	}
}

// TestResolveDisableEnable_LegacyL1L2Lookup pins the bridge behavior:
// L1 and L2 IDs that appeared in the user's disable list are kept as
// keys in the resolved Disable map so legacy callers querying by L1/L2
// name (`disable["sql-injection"]`) continue to work.
func TestResolveDisableEnable_LegacyL1L2Lookup(t *testing.T) {
	disable := resolveDisableEnable(nil, nil, []string{"sql-injection"}, nil)
	if !disable["sql-injection"] {
		t.Error("L2 ID 'sql-injection' should be a key in the resolved map when literally disabled")
	}
	// And every leaf in that L2 should also be off.
	if !disable["sql-injection-union-select"] {
		t.Error("leaf under disabled L2 should be off")
	}
}
