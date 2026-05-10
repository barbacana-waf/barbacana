package audit

// Vendor-namespaced flat fields. Both OCSF and ECS allow vendor
// extensions outside the standard schema as long as the namespace
// doesn't collide with a registered field. We emit the same
// `barbacana` object on both formats so a single jq path
// (`.barbacana.matched_protections`, etc.) works regardless of which
// wire schema the operator picked.
//
// The schema-mapped representations (OCSF `attacks[]`/`firewall_rule`,
// ECS `rule`/`vulnerability`) stay intact for SIEMs that index the
// standard fields. This namespace exists for grep/jq ergonomics, not
// as a replacement.

import "strconv"

func barbacanaNamespace(e Event) map[string]any {
	if len(e.Protections) == 0 && len(e.RuleIDs) == 0 && len(e.CWE) == 0 {
		return nil
	}
	bb := map[string]any{}
	if len(e.Protections) > 0 {
		bb["matched_protections"] = e.Protections
	}
	if len(e.RuleIDs) > 0 {
		ids := make([]string, 0, len(e.RuleIDs))
		for _, rid := range e.RuleIDs {
			ids = append(ids, strconv.Itoa(rid))
		}
		bb["matched_rules"] = ids
	}
	if len(e.CWE) > 0 {
		bb["cwe"] = e.CWE
	}
	return bb
}
