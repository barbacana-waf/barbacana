package crs

import (
	"github.com/barbacana-waf/barbacana/internal/protections"
	"github.com/barbacana-waf/barbacana/internal/protections/crs/curated"
)

// ruleMapping maps each CRS rule ID to its canonical sub-protection name.
// This is the Go embodiment of docs/design/protections-crs-mapping.md.
// Orchestration rules (paranoia markers, blocking eval, correlation) are
// NOT included — they are always-on and never exposed as sub-protections.
//
// Curated PL2/PL3 rule IDs are NOT listed here — they live in the
// curated subpackage as the single source of truth. RuleIDToSubProtection
// and DisabledRuleIDs consult both sources.
var ruleMapping = map[int]string{
	// ── scanner-detection (913xxx) ────────────────────────
	913100: "scanner-detection-user-agent",

	// ── protocol-enforcement (920xxx) ─────────────────────
	920100: "protocol-enforcement-request-line",
	920120: "protocol-enforcement-multipart-bypass",
	920121: "protocol-enforcement-multipart-bypass",
	920160: "protocol-enforcement-content-length",
	920170: "protocol-enforcement-get-head-body",
	920171: "protocol-enforcement-get-head-body",
	920180: "protocol-enforcement-post-content-length",
	920181: "protocol-enforcement-ambiguous-length",
	920190: "protocol-enforcement-range",
	920200: "protocol-enforcement-range",
	920201: "protocol-enforcement-range",
	920202: "protocol-enforcement-range",
	920660: "protocol-enforcement-range",
	920210: "protocol-enforcement-connection-header",
	920230: "protocol-enforcement-url-encoding",
	920240: "protocol-enforcement-url-encoding",
	920460: "protocol-enforcement-url-encoding",
	920250: "protocol-enforcement-utf8-abuse",
	920260: "protocol-enforcement-utf8-abuse",
	920540: "protocol-enforcement-utf8-abuse",
	920270: "protocol-enforcement-null-byte",
	920271: "protocol-enforcement-invalid-chars",
	920272: "protocol-enforcement-invalid-chars",
	920273: "protocol-enforcement-invalid-chars",
	920274: "protocol-enforcement-invalid-chars",
	920275: "protocol-enforcement-invalid-chars",
	920280: "protocol-enforcement-host-header",
	920290: "protocol-enforcement-host-header",
	920350: "protocol-enforcement-host-header",
	920300: "protocol-enforcement-accept-header",
	920310: "protocol-enforcement-accept-header",
	920311: "protocol-enforcement-accept-header",
	920600: "protocol-enforcement-accept-header",
	920320: "protocol-enforcement-user-agent-header",
	920330: "protocol-enforcement-user-agent-header",
	920340: "protocol-enforcement-content-type-header",
	920470: "protocol-enforcement-content-type-header",
	920480: "protocol-enforcement-content-type-header",
	920530: "protocol-enforcement-content-type-header",
	920620: "protocol-enforcement-content-type-header",
	920640: "protocol-enforcement-content-type-header",
	920360: "protocol-enforcement-argument-limits",
	920370: "protocol-enforcement-argument-limits",
	920380: "protocol-enforcement-argument-limits",
	920390: "protocol-enforcement-argument-limits",
	920400: "protocol-enforcement-upload-size",
	920410: "protocol-enforcement-upload-size",
	920420: "protocol-enforcement-content-type-policy",
	920430: "protocol-enforcement-http-version",
	920440: "protocol-enforcement-file-extension",
	920450: "protocol-enforcement-restricted-header",
	920451: "protocol-enforcement-restricted-header",
	920490: "protocol-enforcement-restricted-header",
	920510: "protocol-enforcement-restricted-header",
	920500: "protocol-enforcement-backup-file-access",
	920520: "protocol-enforcement-accept-encoding",
	920521: "protocol-enforcement-accept-encoding",
	920539: "protocol-enforcement-reqbody-processor",
	920610: "protocol-enforcement-raw-uri-fragment",
	920650: "protocol-enforcement-method-override",

	// ── protocol-attack (921xxx) ──────────────────────────
	921110: "protocol-attack-smuggling",
	921120: "protocol-attack-response-splitting",
	921130: "protocol-attack-response-splitting",
	921140: "protocol-attack-header-injection",
	921150: "protocol-attack-header-injection",
	921151: "protocol-attack-header-injection",
	921160: "protocol-attack-header-injection",
	921190: "protocol-attack-header-injection",
	921200: "protocol-attack-ldap-injection",
	921170: "protocol-attack-parameter-pollution",
	921180: "protocol-attack-parameter-pollution",
	921210: "protocol-attack-parameter-pollution",
	921220: "protocol-attack-parameter-pollution",
	921230: "protocol-attack-range-header",
	921240: "protocol-attack-mod-proxy",
	921250: "protocol-attack-legacy-cookie",
	921421: "protocol-attack-dangerous-content-type",
	921422: "protocol-attack-dangerous-content-type",

	// ── multipart-attack (922xxx) ─────────────────────────
	922100: "multipart-attack-global-charset",
	922110: "multipart-attack-content-type",
	922140: "multipart-attack-content-type",
	922150: "multipart-attack-content-type",
	922120: "multipart-attack-transfer-encoding",
	922130: "multipart-attack-header-chars",

	// ── local-file-inclusion (930xxx) ─────────────────────
	930100: "lfi-path-traversal",
	930110: "lfi-path-traversal",
	930120: "lfi-system-files",
	930121: "lfi-system-files",
	930130: "lfi-restricted-files",
	930140: "lfi-ai-artifacts",

	// ── remote-file-inclusion (931xxx) ────────────────────
	931100: "rfi-ip-parameter",
	931110: "rfi-vulnerable-parameter",
	931120: "rfi-trailing-question",
	931130: "rfi-off-domain",
	931131: "rfi-off-domain",

	// ── remote-code-execution (932xxx) ────────────────────
	// Curated additions (932161, 932220, 932231, 932236, 932300, 932301,
	// 932310, 932311, 932320, 932321, 932371, 932390) live in
	// internal/protections/crs/curated — do not duplicate here.
	932230: "rce-unix-command",
	932232: "rce-unix-command",
	932235: "rce-unix-command",
	932239: "rce-unix-command",
	932240: "rce-unix-command",
	932250: "rce-unix-command",
	932260: "rce-unix-command",
	932340: "rce-unix-command",
	932350: "rce-unix-command",
	932130: "rce-unix-shell-expression",
	932131: "rce-unix-shell-expression",
	932160: "rce-unix-shell-expression",
	932237: "rce-unix-shell-expression",
	932238: "rce-unix-shell-expression",
	932270: "rce-unix-shell-expression",
	932271: "rce-unix-shell-expression",
	932175: "rce-unix-shell-alias",
	932330: "rce-unix-shell-history",
	932331: "rce-unix-shell-history",
	932280: "rce-unix-brace-expansion",
	932281: "rce-unix-brace-expansion",
	932190: "rce-unix-wildcard-bypass",
	932200: "rce-unix-bypass-technique",
	932205: "rce-unix-bypass-technique",
	932206: "rce-unix-bypass-technique",
	932207: "rce-unix-bypass-technique",
	932140: "rce-windows-command",
	932370: "rce-windows-command",
	932380: "rce-windows-command",
	932120: "rce-windows-powershell",
	932125: "rce-windows-powershell",
	932170: "rce-shellshock",
	932171: "rce-shellshock",
	932180: "rce-executable-upload",
	932210: "rce-sqlite-shell",

	// ── php-injection (933xxx) ────────────────────────────
	933100: "php-open-tag",
	933190: "php-open-tag",
	933110: "php-file-upload",
	933111: "php-file-upload",
	933220: "php-file-upload",
	933120: "php-config-directive",
	933130: "php-variable-abuse",
	933131: "php-variable-abuse",
	933135: "php-variable-abuse",
	933140: "php-stream-wrapper",
	933200: "php-stream-wrapper",
	933150: "php-function-high-risk",
	933160: "php-function-high-risk",
	933151: "php-function-medium-risk",
	933152: "php-function-medium-risk",
	933153: "php-function-medium-risk",
	933161: "php-function-low-value",
	933170: "php-object-injection",
	933180: "php-variable-function-call",
	933210: "php-variable-function-call",
	933211: "php-variable-function-call",

	// ── generic-injection (934xxx) ────────────────────────
	// Curated additions (934101, 934140) live in the curated subpackage.
	934100: "nodejs-injection",
	934160: "nodejs-dos",
	934110: "ssrf-cloud-metadata",
	934120: "ssrf-url-scheme",
	934190: "ssrf-url-scheme",
	934130: "prototype-pollution",
	934150: "ruby-injection",
	934170: "data-scheme-injection",
	934180: "template-injection",

	// ── xss (941xxx) ──────────────────────────────────────
	941100: "xss-libinjection",
	941101: "xss-libinjection",
	941110: "xss-script-tag",
	941120: "xss-event-handler",
	941130: "xss-attribute-injection",
	941150: "xss-attribute-injection",
	941170: "xss-attribute-injection",
	941140: "xss-javascript-uri",
	941160: "xss-html-injection",
	941320: "xss-html-injection",
	941180: "xss-denylist-keyword",
	941181: "xss-denylist-keyword",
	941190: "xss-ie-filter",
	941200: "xss-ie-filter",
	941220: "xss-ie-filter",
	941230: "xss-ie-filter",
	941240: "xss-ie-filter",
	941250: "xss-ie-filter",
	941260: "xss-ie-filter",
	941270: "xss-ie-filter",
	941280: "xss-ie-filter",
	941290: "xss-ie-filter",
	941300: "xss-ie-filter",
	941330: "xss-ie-filter",
	941340: "xss-ie-filter",
	941210: "xss-javascript-keyword",
	941370: "xss-javascript-keyword",
	941390: "xss-javascript-keyword",
	941400: "xss-javascript-keyword",
	941310: "xss-encoding-evasion",
	941350: "xss-encoding-evasion",
	941360: "xss-obfuscation",
	941380: "xss-angularjs-csti",

	// ── sql-injection (942xxx) ────────────────────────────
	942100: "sql-injection-libinjection",
	942101: "sql-injection-libinjection",
	942120: "sql-injection-operator",
	942250: "sql-injection-operator",
	942251: "sql-injection-operator",
	942130: "sql-injection-boolean",
	942131: "sql-injection-boolean",
	942140: "sql-injection-common-dbnames",
	942150: "sql-injection-function",
	942151: "sql-injection-function",
	942152: "sql-injection-function",
	942410: "sql-injection-function",
	942160: "sql-injection-blind",
	942170: "sql-injection-blind",
	942280: "sql-injection-blind",
	// Curated additions to sql-injection-auth-bypass (942180, 942260,
	// 942340, 942521) live in the curated subpackage.
	942520: "sql-injection-auth-bypass",
	942522: "sql-injection-auth-bypass",
	942540: "sql-injection-auth-bypass",
	942190: "sql-injection-mssql",
	942240: "sql-injection-mssql",
	942220: "sql-injection-integer-overflow",
	942230: "sql-injection-conditional",
	942300: "sql-injection-conditional",
	942210: "sql-injection-chained",
	942310: "sql-injection-chained",
	942270: "sql-injection-union",
	942361: "sql-injection-union",
	942290: "sql-injection-nosql",
	942320: "sql-injection-stored-procedure",
	942321: "sql-injection-stored-procedure",
	942350: "sql-injection-stored-procedure",
	942330: "sql-injection-classic-probe",
	942370: "sql-injection-classic-probe",
	942380: "sql-injection-classic-probe",
	942390: "sql-injection-classic-probe",
	942400: "sql-injection-classic-probe",
	942470: "sql-injection-classic-probe",
	942480: "sql-injection-classic-probe",
	942490: "sql-injection-classic-probe",
	942360: "sql-injection-concat",
	942362: "sql-injection-concat",
	942420: "sql-injection-char-anomaly",
	942421: "sql-injection-char-anomaly",
	942430: "sql-injection-char-anomaly",
	942431: "sql-injection-char-anomaly",
	942432: "sql-injection-char-anomaly",
	942460: "sql-injection-char-anomaly",
	// Curated additions (942200 comment, 942450 hex, 942510/942511 tick,
	// 942530 termination) live in the curated subpackage.
	942440: "sql-injection-comment",
	942500: "sql-injection-comment",
	942550: "sql-injection-json",
	942560: "sql-injection-scientific-notation",

	// ── session-fixation (943xxx) ─────────────────────────
	943100: "session-fixation-set-cookie-html",
	943110: "session-fixation-sessionid-off-domain-referer",
	943120: "session-fixation-sessionid-no-referer",

	// ── java-injection (944xxx) ───────────────────────────
	944100: "java-class-loading",
	944130: "java-class-loading",
	944250: "java-class-loading",
	944260: "java-class-loading",
	944110: "java-process-spawn",
	944120: "java-deserialization",
	944200: "java-deserialization",
	944210: "java-deserialization",
	944240: "java-deserialization",
	944140: "java-script-upload",
	944150: "java-log4j",
	944151: "java-log4j",
	944152: "java-log4j",
	944300: "java-base64-keyword",

	// ── data-leakage (950xxx) ─────────────────────────────
	950130: "data-leakage-directory-listing",
	950140: "data-leakage-cgi-source",
	950150: "data-leakage-aspnet-exception",
	950100: "data-leakage-5xx-status",

	// ── data-leakage-sql (951xxx) ─────────────────────────
	951110: "data-leakage-sql-msaccess",
	951120: "data-leakage-sql-oracle",
	951130: "data-leakage-sql-db2",
	951140: "data-leakage-sql-emc",
	951150: "data-leakage-sql-firebird",
	951160: "data-leakage-sql-frontbase",
	951170: "data-leakage-sql-hsqldb",
	951180: "data-leakage-sql-informix",
	951190: "data-leakage-sql-ingres",
	951200: "data-leakage-sql-interbase",
	951210: "data-leakage-sql-maxdb",
	951220: "data-leakage-sql-mssql",
	951230: "data-leakage-sql-mysql",
	951240: "data-leakage-sql-postgres",
	951250: "data-leakage-sql-sqlite",
	951260: "data-leakage-sql-sybase",

	// ── data-leakage-java (952xxx) ────────────────────────
	952110: "data-leakage-java-error",

	// ── data-leakage-php (953xxx) ─────────────────────────
	953100: "data-leakage-php-info",
	953101: "data-leakage-php-info",
	953110: "data-leakage-php-source",
	953120: "data-leakage-php-source",

	// ── data-leakage-iis (954xxx) ─────────────────────────
	954100: "data-leakage-iis-install-location",
	954101: "data-leakage-iis-install-location",
	954110: "data-leakage-iis-availability",
	954120: "data-leakage-iis-info",
	954130: "data-leakage-iis-info",

	// ── web-shell (955xxx) ────────────────────────────────
	955100: "web-shell-detection",
	955110: "web-shell-detection",
	955120: "web-shell-detection",
	955130: "web-shell-detection",
	955140: "web-shell-detection",
	955150: "web-shell-detection",
	955160: "web-shell-detection",
	955170: "web-shell-detection",
	955180: "web-shell-detection",
	955190: "web-shell-detection",
	955200: "web-shell-detection",
	955210: "web-shell-detection",
	955220: "web-shell-detection",
	955230: "web-shell-detection",
	955240: "web-shell-detection",
	955250: "web-shell-detection",
	955260: "web-shell-detection",
	955270: "web-shell-detection",
	955280: "web-shell-detection",
	955290: "web-shell-detection",
	955300: "web-shell-detection",
	955310: "web-shell-detection",
	955320: "web-shell-detection",
	955330: "web-shell-detection",
	955340: "web-shell-detection",
	955350: "web-shell-detection",
	955400: "web-shell-detection",

	// ── data-leakage-ruby (956xxx) ────────────────────────
	956100: "data-leakage-ruby",
	956110: "data-leakage-ruby",
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

// SubProtectionCategory returns the parent category for a sub-protection
// canonical name by consulting the protections catalog. Returns "" if unknown.
func SubProtectionCategory(subProtection string) string {
	for cat, subs := range protections.Catalog() {
		for _, s := range subs {
			if s == subProtection {
				return cat
			}
		}
	}
	return ""
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
