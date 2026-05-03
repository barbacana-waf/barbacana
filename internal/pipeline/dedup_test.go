package pipeline

import (
	"context"
	"net/http"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/protections"
)

// stubProtection is a minimal Protection used by TestNativeAndCrsDedup to
// stand in for a native detector. The name and CWE values are the only
// fields that flow into the auditCollector under test.
type stubProtection struct {
	name string
	cwe  string
}

func (s stubProtection) Name() string                                                      { return s.name }
func (s stubProtection) Category() string                                                  { return "" }
func (s stubProtection) CWE() string                                                       { return s.cwe }
func (s stubProtection) Evaluate(_ context.Context, _ *http.Request) protections.Decision { return protections.Allow() }

// TestNativeAndCrsDedup pins the auditCollector dedupe property for the
// merger map at .planning/protection_taxonomy_proposal.md §976-985.
//
// For each merged leaf, the table simulates a native detector firing
// followed by a CRS detector emitting the same canonical Decision.Protection
// (with one or more rule IDs in MatchedRules). The collector must:
//
//   - record the leaf in `protections` exactly once
//   - still accumulate the CRS rule IDs in `rules` (so the audit log shows
//     which CRS rule fired even though the leaf was already seen)
//
// The "both detectors fired" assertion is structural: addNativeDecision is
// called first (stage order), then addDecision; if dedupe were broken, the
// second call would re-append. We verify the post-state directly.
func TestNativeAndCrsDedup(t *testing.T) {
	cases := []struct {
		name        string
		leaf        string
		nativeCWE   string
		crsRules    []int
	}{
		{
			name:      "request-smuggling",
			leaf:      "http-attacks-request-smuggling",
			nativeCWE: "CWE-444",
			crsRules:  []int{921110},
		},
		{
			name:      "header-crlf-injection",
			leaf:      "http-attacks-header-crlf-injection",
			nativeCWE: "CWE-93",
			crsRules:  []int{921140, 921150},
		},
		{
			name:      "null-bytes",
			leaf:      "http-compliance-null-bytes",
			nativeCWE: "CWE-158",
			crsRules:  []int{920270},
		},
		{
			name:      "method-override-param",
			leaf:      "http-compliance-method-override-param",
			nativeCWE: "",
			crsRules:  []int{920650},
		},
		{
			name:      "double-url-encoding",
			leaf:      "http-compliance-double-url-encoding",
			nativeCWE: "CWE-174",
			crsRules:  []int{920230, 920240, 920460},
		},
		{
			name:      "utf8-tricks",
			leaf:      "http-compliance-utf8-tricks",
			nativeCWE: "CWE-176",
			crsRules:  []int{920250, 920260, 920540},
		},
		{
			name:      "dot-dot-paths",
			leaf:      "local-file-access-dot-dot-paths",
			nativeCWE: "CWE-22",
			crsRules:  []int{930100, 930110},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ac := newAuditCollector()

			// Pre-assertion #1: simulated native fire.
			nativeDec := protections.Decision{
				Block:      true,
				Protection: tc.leaf,
				Reason:     "synthetic native detection for dedupe test",
			}
			ac.addNativeDecision(nativeDec, stubProtection{name: tc.leaf, cwe: tc.nativeCWE})
			if len(ac.protections) != 1 || ac.protections[0] != tc.leaf {
				t.Fatalf("after native fire: protections = %v, want [%q]",
					ac.protections, tc.leaf)
			}

			// Pre-assertion #2: simulated CRS fire on the same leaf.
			crsDec := protections.Decision{
				Block:        true,
				Protection:   tc.leaf,
				MatchedRules: tc.crsRules,
				Reason:       "synthetic CRS detection for dedupe test",
			}
			ac.addDecision(crsDec)

			// Dedupe assertion: leaf appears exactly once.
			count := 0
			for _, p := range ac.protections {
				if p == tc.leaf {
					count++
				}
			}
			if count != 1 {
				t.Errorf("dedupe broken: leaf %q appears %d times in %v",
					tc.leaf, count, ac.protections)
			}

			// Belt-and-suspenders: CRS rule IDs must have been recorded
			// even though the leaf was already in seenProt. This proves
			// the CRS detector's contribution didn't get silently dropped
			// alongside the dedupe.
			rulesSeen := make(map[int]bool, len(ac.rules))
			for _, id := range ac.rules {
				rulesSeen[id] = true
			}
			for _, want := range tc.crsRules {
				if !rulesSeen[want] {
					t.Errorf("CRS rule %d missing from collector.rules %v (CRS detector fired but its rule ID was dropped)",
						want, ac.rules)
				}
			}

			// CWE attribution: the native CWE (if non-empty) should be
			// in the collector's CWE set. The CRS path doesn't add a CWE
			// because it relies on protections.CWEForProtection — which
			// during phase 4 is still the legacy lookup; the native CWE
			// captured at addNativeDecision time is the one that lands.
			if tc.nativeCWE != "" && !ac.cwes[tc.nativeCWE] {
				t.Errorf("native CWE %q missing from collector.cwes %v",
					tc.nativeCWE, ac.cwes)
			}
		})
	}
}

// TestAuditCollectorOrderIndependence verifies that the resulting CWE
// set after a (native, CRS) pair of decisions is identical regardless
// of which detector fired first, and that it equals the union of the
// catalog's declared CWEs for the leaf plus the native protection's
// self-declared CWE. This pins the property that motivated the dedupe
// design in the first place — operators reading audit logs see the
// same Entry.CWE for the same threat regardless of pipeline ordering.
func TestAuditCollectorOrderIndependence(t *testing.T) {
	leaf := "http-attacks-request-smuggling"
	nativeProt := stubProtection{name: leaf, cwe: "CWE-444"}
	nativeDec := protections.Decision{Block: true, Protection: leaf}
	crsDec := protections.Decision{Block: true, Protection: leaf, MatchedRules: []int{921110}}

	nativeFirst := newAuditCollector()
	nativeFirst.addNativeDecision(nativeDec, nativeProt)
	nativeFirst.addDecision(crsDec)

	crsFirst := newAuditCollector()
	crsFirst.addDecision(crsDec)
	crsFirst.addNativeDecision(nativeDec, nativeProt)

	// Dedupe holds in both orderings.
	if len(nativeFirst.protections) != 1 {
		t.Errorf("native-first dedupe broken: protections = %v", nativeFirst.protections)
	}
	if len(crsFirst.protections) != 1 {
		t.Errorf("CRS-first dedupe broken: protections = %v", crsFirst.protections)
	}

	// Union-equality on the CWE set.
	if !cweSetsEqual(nativeFirst.cwes, crsFirst.cwes) {
		t.Errorf("CWE sets differ across stage orderings:\n  native-first: %v\n  CRS-first:    %v",
			nativeFirst.cwes, crsFirst.cwes)
	}

	// And the union should be a superset of the catalog's CWEs for the
	// leaf, plus the native's self-declared CWE.
	for _, want := range protections.CWEForProtection(leaf) {
		if !nativeFirst.cwes[want] {
			t.Errorf("catalog CWE %q missing from collector after native-first; have %v",
				want, nativeFirst.cwes)
		}
	}
	if !nativeFirst.cwes[nativeProt.cwe] {
		t.Errorf("native self-declared CWE %q missing from collector; have %v",
			nativeProt.cwe, nativeFirst.cwes)
	}
}

func cweSetsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
