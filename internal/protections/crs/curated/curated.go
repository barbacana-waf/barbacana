// Package curated is the single source of truth for the CRS rule IDs
// Barbacana force-enables on top of the PL1 baseline. Each entry maps a
// rule ID to the canonical sub-protection name it matches, so a curated
// match attributes correctly in audit logs and obeys the user's
// disable list.
//
// This list is consumed by:
//   - cmd/tools/rules — to know which rule bodies to extract from the
//     CRS source into curated-rules.conf and which score accumulators
//     to rewrite (pl2/pl3 → pl1, see docs/design/security-evaluation.md).
//   - internal/protections/crs — to emit SecRuleRemoveById for the
//     dormant originals before loading curated-rules.conf, and to
//     resolve curated rule IDs back to sub-protection names.
//
// Changing this list is a security decision: it requires a code change,
// rebuild, release, and PR review. See docs/design/security-evaluation.md
// for the methodology used to select each rule.
package curated

// Rule pairs a CRS rule ID with the canonical sub-protection name that
// rule belongs to. The name must match an entry in
// internal/protections/catalog.go.
type Rule struct {
	ID         int
	Protection string
}

// Rules is the curated PL2/PL3 set. Grouped by sub-protection for
// readability; order within the slice is not semantically significant.
var Rules = []Rule{
	// RCE — Unix shell / command families
	//
	// NOTE 932236 (rce-unix-command, PL2) was considered and rejected.
	// Its regex fires on common English words like "echo", "curl",
	// "exec", "bash", "nc", "java" followed by any token — in gotestwaf's
	// false-positive "texts" corpus that is 14 of 15 new blocks. Before
	// the PL1 blocking fix this rule was dormant and its FPs were
	// hidden. See docs/design/security-evaluation.md.
	{ID: 932161, Protection: "rce-unix-shell-expression"},
	{ID: 932220, Protection: "rce-unix-command"},
	{ID: 932231, Protection: "rce-unix-command"},
	{ID: 932371, Protection: "rce-windows-command"},
	{ID: 932390, Protection: "rce-unix-fork-bomb"},

	// RCE — SMTP / mail protocol injection
	{ID: 932300, Protection: "rce-mail-protocol-injection"},
	{ID: 932301, Protection: "rce-mail-protocol-injection"},
	{ID: 932310, Protection: "rce-mail-protocol-injection"},
	{ID: 932311, Protection: "rce-mail-protocol-injection"},
	{ID: 932320, Protection: "rce-mail-protocol-injection"},
	{ID: 932321, Protection: "rce-mail-protocol-injection"},

	// SQLi — auth bypass, hex, tick bypass, termination.
	//
	// NOTE 942200 (sql-injection-comment) was considered and rejected.
	// Its regex includes a branch that matches a comma followed by a
	// quoted string (", "key":" in JSON), so it blocks any JSON body
	// with two or more keys. Before the blocking-pipeline fix this
	// rule was dormant, so its false positives never surfaced. See
	// docs/design/security-evaluation.md.
	{ID: 942180, Protection: "sql-injection-auth-bypass"},
	{ID: 942260, Protection: "sql-injection-auth-bypass"},
	{ID: 942340, Protection: "sql-injection-auth-bypass"},
	{ID: 942450, Protection: "sql-injection-hex-encoding"},
	{ID: 942510, Protection: "sql-injection-tick-bypass"},
	{ID: 942511, Protection: "sql-injection-tick-bypass"},
	// NOTE 942521 (sql-injection-auth-bypass, PL3) was considered and
	// rejected. Its pattern matches an apostrophe-or-digit shorthand
	// ("d'or 1st") common in product names and French-loanword English.
	{ID: 942530, Protection: "sql-injection-termination"},

	// Language-specific
	{ID: 934101, Protection: "nodejs-injection"},
	{ID: 934140, Protection: "perl-injection"},
}

// IDs returns a fresh slice of just the curated rule IDs, in Rules order.
func IDs() []int {
	ids := make([]int, len(Rules))
	for i, r := range Rules {
		ids[i] = r.ID
	}
	return ids
}

// Lookup returns the canonical sub-protection name for a curated rule ID,
// and reports whether the ID is in the curated set.
func Lookup(id int) (string, bool) {
	for _, r := range Rules {
		if r.ID == id {
			return r.Protection, true
		}
	}
	return "", false
}
