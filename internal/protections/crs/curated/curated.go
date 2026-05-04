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
//
// Severity, when set, overrides the CRS-authored severity for the
// curated copy of the rule. The override is applied at extraction time
// by cmd/tools/rules: the `severity:'<old>'` line and every
// `tx.<old>_anomaly_score` reference in the rule body are rewritten to
// the override. This is how a NOTICE/WARNING/ERROR rule that would
// otherwise contribute too little score to cross the blocking
// threshold (5) on its own match becomes actionable when curation
// expresses an act-on intent — see docs/design/security-evaluation.md.
//
// Leave Severity empty when curating a CRS-CRITICAL rule: the
// extraction is a no-op for those entries.
//
// Allowed values: "CRITICAL", "ERROR", "WARNING", "NOTICE".
type Rule struct {
	ID         int
	Protection string
	Severity   string
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
	{ID: 932161, Protection: "command-injection-shell-substitution"},
	{ID: 932220, Protection: "command-injection-unix-commands"},
	{ID: 932231, Protection: "command-injection-unix-commands"},
	{ID: 932371, Protection: "command-injection-windows-cmd"},
	{ID: 932390, Protection: "command-injection-fork-bomb"},

	// SMTP / mail protocol injection
	{ID: 932300, Protection: "mail-protocol-injection"},
	{ID: 932301, Protection: "mail-protocol-injection"},
	{ID: 932310, Protection: "mail-protocol-injection"},
	{ID: 932311, Protection: "mail-protocol-injection"},
	{ID: 932320, Protection: "mail-protocol-injection"},
	{ID: 932321, Protection: "mail-protocol-injection"},

	// SQLi — auth bypass, hex, tick bypass, termination.
	//
	// NOTE 942200 (sql-injection-comment) was considered and rejected.
	// Its regex includes a branch that matches a comma followed by a
	// quoted string (", "key":" in JSON), so it blocks any JSON body
	// with two or more keys. Before the blocking-pipeline fix this
	// rule was dormant, so its false positives never surfaced. See
	// docs/design/security-evaluation.md.
	//
	// NOTE 942340 (sql-injection-auth-bypass, PL2) was considered and
	// rejected for the same family of reason: CRS exposes JSON body
	// fields as ARGS values, and the rule's quote-comment bypass
	// pattern matches structures found in ordinary JSON bodies like
	// {"test":"value"}. Surfaced by the proxy-conformance blackbox
	// suite after blocking was fixed in v0.2.0.
	{ID: 942180, Protection: "sql-injection-login-bypass"},
	{ID: 942260, Protection: "sql-injection-login-bypass"},
	{ID: 942450, Protection: "sql-injection-hex-encoded"},
	{ID: 942510, Protection: "sql-injection-backticks"},
	{ID: 942511, Protection: "sql-injection-backticks"},
	// NOTE 942521 (sql-injection-quotes-in-text, off-by-default
	// aggressive) was considered for the curated set and rejected. Its
	// pattern matches an apostrophe-or-digit shorthand ("d'or 1st")
	// common in product names and French-loanword English.
	{ID: 942530, Protection: "sql-injection-query-closers"},

	// Language-specific
	{ID: 934101, Protection: "javascript-injection-eval"},
	{ID: 934140, Protection: "perl-injection-system-calls"},

	// ── Opt-in curation ─────────────────────────────────────────────
	//
	// Every rule below maps to a Default: Off leaf. DisabledRuleIDs
	// strips them from the engine when the leaf is off (the default
	// state), so they impose no cost or FP risk on default deployments.
	// They load and fire only when the user puts the leaf in `enable:`.
	//
	// Curating a rule here promotes it to PL1 score-bucket and (via
	// rewriteScoreAccumulators) normalizes NOTICE/WARNING/ERROR severities
	// to CRITICAL — see docs/design/security-evaluation.md. Without this
	// bridge, a default-off CRS-only leaf cannot block end-to-end at the
	// engine's fixed PL1, and `enable:` is a dead lever.
	//
	// HTTP compliance — opt-in strictness
	//
	// 920320 fires on missing UA header (`&UA @eq 0`); 920330 on empty
	// UA (`UA @rx ^$`). Hurl can't fully suppress the header from a
	// libcurl-driven request, so any blackbox scenario that asserts
	// "enable produces a 403" relies on 920330. Both belong to the same
	// leaf, so curating both together is consistent with the operator's
	// opt-in: empty and missing both signal "no client identity" and
	// should be treated identically.
	//
	// CRS authored both as NOTICE; promoting to CRITICAL is the
	// correctness call for opt-in — see Rule.Severity godoc.
	{ID: 920320, Protection: "http-compliance-user-agent-header", Severity: "CRITICAL"},
	{ID: 920330, Protection: "http-compliance-user-agent-header", Severity: "CRITICAL"},
	{ID: 920271, Protection: "http-compliance-non-printable-characters"},

	// HTTP attacks — opt-in detections
	//
	// 921170 and 921180 are a cross-rule chain: 921170 fills
	// tx.paramcounter_<NAME> per arg, 921180 fires when any counter > 1.
	// Removing either breaks HPP detection end-to-end. Both must stay
	// curated together; a future change that drops one without the other
	// regresses the leaf silently.
	{ID: 921170, Protection: "http-attacks-duplicate-parameters"},
	{ID: 921180, Protection: "http-attacks-duplicate-parameters"},
	{ID: 921230, Protection: "http-attacks-range-dos"},

	// XSS / template injection — opt-in detections
	{ID: 941380, Protection: "cross-site-scripting-angular-templates"},
	{ID: 934180, Protection: "template-injection"},

	// RCE — opt-in detections
	//
	// 932236 was previously rejected from default-on curation due to FP
	// rates on free-text inputs. Opt-in is the correct surface: the leaf
	// stays default-off, so the rule is only loaded when the operator
	// explicitly accepts the FP cost via `enable:`.
	{ID: 932236, Protection: "command-injection-english-words"},
	{ID: 932190, Protection: "command-injection-shell-wildcards"},
	{ID: 932200, Protection: "command-injection-evasion-tricks"},
	{ID: 932210, Protection: "command-injection-sqlite-shell"},

	// PHP / Java — opt-in detections
	{ID: 933151, Protection: "php-injection-suspicious-functions-aggressive"},
	{ID: 944300, Protection: "java-injection-base64-encoded-keywords"},

	// SQLi — opt-in detections
	//
	// 942200 (sql-injection-comments-in-json) was rejected from default-on
	// curation due to FPs on multi-key JSON bodies. Opt-in is the correct
	// surface for the same reason as 932236.
	{ID: 942200, Protection: "sql-injection-comments-in-json"},
	{ID: 942130, Protection: "sql-injection-always-true"},
	{ID: 942210, Protection: "sql-injection-multiple-statements"},
	{ID: 942521, Protection: "sql-injection-quotes-in-text"},
	{ID: 942330, Protection: "sql-injection-generic-aggressive"},
	// CRS authored 942430 as WARNING (statistical heuristic); the
	// opt-in act-on stance promotes it to CRITICAL.
	{ID: 942430, Protection: "sql-injection-special-character-density", Severity: "CRITICAL"},

	// File / RFI — opt-in detection
	{ID: 931130, Protection: "remote-file-fetch-external-urls"},

	// Response data leakage — opt-in detections
	//
	// CRS authored both as ERROR; promoting to CRITICAL so a single
	// match crosses the blocking threshold without stacking.
	{ID: 950100, Protection: "server-data-leakage-5xx-bodies", Severity: "CRITICAL"},
	{ID: 956110, Protection: "ruby-data-leakage-source-code", Severity: "CRITICAL"},
}

// IDs returns a fresh slice of just the curated rule IDs, in Rules order.
func IDs() []int {
	ids := make([]int, len(Rules))
	for i, r := range Rules {
		ids[i] = r.ID
	}
	return ids
}

// PhaseSplit partitions curated rule IDs by request vs response phase.
// The split mirrors CRS file conventions: rule IDs in 950–959, 956,
// etc. live in RESPONSE-* files and run in phase 3+, all others run
// in phase 1–2. crs.go uses this to place each phase's curated body
// before its respective blocking-evaluation marker so the score lands
// where the aggregator can read it.
func PhaseSplit() (request, response []int) {
	for _, r := range Rules {
		switch r.ID / 1000 {
		case 950, 951, 952, 953, 954, 955, 956, 959, 980:
			response = append(response, r.ID)
		default:
			request = append(request, r.ID)
		}
	}
	return request, response
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
