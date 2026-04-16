// Package protections defines the Protection interface, the registry, and
// the canonical-name catalog used for config validation and disable-list
// resolution.
//
// The catalog in this file is the source of truth for known names. It is
// consumed by config validation (B1) and by the Registry (B2) at startup.
package protections

// Catalog returns the canonical-name hierarchy.
//
// The outer map key is the category name (e.g. "sql-injection"); the value
// is the list of sub-protection names under that category. Native single-level
// protections appear as a category with an empty slice.
//
// Canonical names must match docs/design/protections.md exactly. Tests pin
// the count per category against the doc so drift is caught early.
func Catalog() map[string][]string {
	return map[string][]string{
		// ── CRS-backed ────────────────────────────────────────
		"scanner-detection": {
			"scanner-detection-user-agent",
		},
		"protocol-enforcement": {
			"protocol-enforcement-request-line",
			"protocol-enforcement-multipart-bypass",
			"protocol-enforcement-content-length",
			"protocol-enforcement-get-head-body",
			"protocol-enforcement-post-content-length",
			"protocol-enforcement-ambiguous-length",
			"protocol-enforcement-range",
			"protocol-enforcement-connection-header",
			"protocol-enforcement-url-encoding",
			"protocol-enforcement-utf8-abuse",
			"protocol-enforcement-null-byte",
			"protocol-enforcement-invalid-chars",
			"protocol-enforcement-host-header",
			"protocol-enforcement-accept-header",
			"protocol-enforcement-user-agent-header",
			"protocol-enforcement-content-type-header",
			"protocol-enforcement-argument-limits",
			"protocol-enforcement-upload-size",
			"protocol-enforcement-content-type-policy",
			"protocol-enforcement-http-version",
			"protocol-enforcement-file-extension",
			"protocol-enforcement-restricted-header",
			"protocol-enforcement-backup-file-access",
			"protocol-enforcement-accept-encoding",
			"protocol-enforcement-reqbody-processor",
			"protocol-enforcement-raw-uri-fragment",
			"protocol-enforcement-method-override",
		},
		"protocol-attack": {
			"protocol-attack-smuggling",
			"protocol-attack-response-splitting",
			"protocol-attack-header-injection",
			"protocol-attack-ldap-injection",
			"protocol-attack-parameter-pollution",
			"protocol-attack-range-header",
			"protocol-attack-mod-proxy",
			"protocol-attack-legacy-cookie",
			"protocol-attack-dangerous-content-type",
		},
		"multipart-attack": {
			"multipart-attack-global-charset",
			"multipart-attack-content-type",
			"multipart-attack-transfer-encoding",
			"multipart-attack-header-chars",
		},
		"local-file-inclusion": {
			"lfi-path-traversal",
			"lfi-system-files",
			"lfi-restricted-files",
			"lfi-ai-artifacts",
		},
		"remote-file-inclusion": {
			"rfi-ip-parameter",
			"rfi-vulnerable-parameter",
			"rfi-trailing-question",
			"rfi-off-domain",
		},
		"remote-code-execution": {
			"rce-unix-command",
			"rce-unix-command-evasion",
			"rce-unix-shell-expression",
			"rce-unix-shell-alias",
			"rce-unix-shell-history",
			"rce-unix-brace-expansion",
			"rce-unix-wildcard-bypass",
			"rce-unix-bypass-technique",
			"rce-unix-fork-bomb",
			"rce-windows-command",
			"rce-windows-powershell",
			"rce-shellshock",
			"rce-file-upload",
			"rce-sqlite-shell",
			"rce-smtp-command",
			"rce-imap-command",
			"rce-pop3-command",
		},
		"php-injection": {
			"php-open-tag",
			"php-file-upload",
			"php-config-directive",
			"php-variable-abuse",
			"php-io-stream",
			"php-wrapper",
			"php-function-high-risk",
			"php-function-medium-risk",
			"php-function-low-value",
			"php-object-injection",
			"php-variable-function-call",
		},
		"generic-injection": {
			"nodejs-injection",
			"nodejs-dos",
			"ssrf",
			"prototype-pollution",
			"perl-injection",
			"ruby-injection",
			"data-scheme-injection",
			"template-injection",
		},
		"xss": {
			"xss-libinjection",
			"xss-script-tag",
			"xss-event-handler",
			"xss-attribute-injection",
			"xss-javascript-uri",
			"xss-html-injection",
			"xss-denylist-keyword",
			"xss-ie-filter",
			"xss-javascript-keyword",
			"xss-encoding-evasion",
			"xss-obfuscation",
			"xss-angularjs-csti",
		},
		"sql-injection": {
			"sql-injection-libinjection",
			"sql-injection-operator",
			"sql-injection-boolean",
			"sql-injection-common-dbnames",
			"sql-injection-function",
			"sql-injection-blind",
			"sql-injection-auth-bypass",
			"sql-injection-mssql",
			"sql-injection-integer-overflow",
			"sql-injection-conditional",
			"sql-injection-chained",
			"sql-injection-union",
			"sql-injection-mongodb",
			"sql-injection-stored-procedure",
			"sql-injection-classic-probe",
			"sql-injection-concat",
			"sql-injection-char-anomaly",
			"sql-injection-comment",
			"sql-injection-hex-encoding",
			"sql-injection-tick-bypass",
			"sql-injection-termination",
			"sql-injection-json",
			"sql-injection-scientific-notation",
		},
		"session-fixation": {
			"session-fixation-set-cookie-html",
			"session-fixation-sessionid-off-domain-referer",
			"session-fixation-sessionid-no-referer",
		},
		"java-injection": {
			"java-class-loading",
			"java-process-spawn",
			"java-deserialization",
			"java-script-upload",
			"java-log4j",
			"java-base64-keyword",
		},
		"data-leakage": {
			"data-leakage-directory-listing",
			"data-leakage-cgi-source",
			"data-leakage-aspnet-exception",
			"data-leakage-5xx-status",
		},
		"data-leakage-sql": {
			"data-leakage-sql-msaccess",
			"data-leakage-sql-oracle",
			"data-leakage-sql-db2",
			"data-leakage-sql-emc",
			"data-leakage-sql-firebird",
			"data-leakage-sql-frontbase",
			"data-leakage-sql-hsqldb",
			"data-leakage-sql-informix",
			"data-leakage-sql-ingres",
			"data-leakage-sql-interbase",
			"data-leakage-sql-maxdb",
			"data-leakage-sql-mssql",
			"data-leakage-sql-mysql",
			"data-leakage-sql-postgres",
			"data-leakage-sql-sqlite",
			"data-leakage-sql-sybase",
		},
		"data-leakage-java": {
			"data-leakage-java-error",
		},
		"data-leakage-php": {
			"data-leakage-php-info",
			"data-leakage-php-source",
		},
		"data-leakage-iis": {
			"data-leakage-iis-install-location",
			"data-leakage-iis-availability",
			"data-leakage-iis-info",
		},

		// ── Native protocol hardening (no sub-protections) ──
		"request-smuggling":        {},
		"crlf-injection":           {},
		"null-byte-injection":      {},
		"method-override":          {},
		"double-encoding":          {},
		"unicode-normalization":    {},
		"path-normalization":       {},
		"parameter-pollution":      {},
		"slow-request":             {},
		"http2-continuation-flood": {},
		"http2-hpack-bomb":         {},
		"http2-stream-limit":       {},

		// ── Request validation ──────────────────────────────
		"max-body-size":        {},
		"max-url-length":       {},
		"max-header-size":      {},
		"max-header-count":     {},
		"allowed-methods":      {},
		"require-host-header":  {},
		"require-content-type": {},

		// ── Body parsing ────────────────────────────────────
		"json-depth-limit":     {},
		"json-key-limit":       {},
		"xml-depth-limit":      {},
		"xml-entity-expansion": {},

		// ── Resource protections ────────────────────────────
		"max-inspection-size":       {},
		"max-memory-buffer":         {},
		"decompression-ratio-limit": {},
		"waf-evaluation-timeout":    {},

		// ── File upload ─────────────────────────────────────
		"multipart-file-limit":       {},
		"multipart-file-size":        {},
		"multipart-allowed-types":    {},
		"multipart-double-extension": {},

		// ── OpenAPI ─────────────────────────────────────────
		"openapi-path":         {},
		"openapi-method":       {},
		"openapi-params":       {},
		"openapi-body":         {},
		"openapi-content-type": {},

		// ── Security headers: injection ─────────────────────
		"header-hsts":                  {},
		"header-csp":                   {},
		"header-x-frame-options":       {},
		"header-x-content-type-options": {},
		"header-referrer-policy":       {},
		"header-x-dns-prefetch":        {},
		"header-coop":                  {},
		"header-coep":                  {},
		"header-corp":                  {},
		"header-permissions-policy":    {},
		"header-cache-control":         {},

		// ── Security headers: stripping ─────────────────────
		"strip-server":         {},
		"strip-x-powered-by":   {},
		"strip-aspnet-version": {},
		"strip-generator":      {},
		"strip-drupal":         {},
		"strip-varnish":        {},
		"strip-via":            {},
		"strip-runtime":        {},
		"strip-debug":          {},
		"strip-backend-server": {},
		"strip-version":        {},

		// ── Response inspection (opt-in) ────────────────────
		"response-open-redirect": {},
		"response-openapi":       {},
	}
}

// AllNames returns every canonical name (categories and sub-protections)
// as a flat set. Used by config validation to check disable-list entries.
func AllNames() map[string]bool {
	out := map[string]bool{}
	for cat, subs := range Catalog() {
		out[cat] = true
		for _, s := range subs {
			out[s] = true
		}
	}
	return out
}

// ExpandDisable resolves a disable list (which may contain category and/or
// sub-protection names) into the full set of disabled sub-protection names.
// Category names expand to every sub-protection under them. Unknown names are
// silently dropped (config validation rejects them upfront).
//
// Native top-level names (e.g. "request-smuggling") map to themselves since
// they have no sub-protections.
func ExpandDisable(disable []string) map[string]bool {
	cat := Catalog()
	out := map[string]bool{}
	for _, n := range disable {
		subs, isCategory := cat[n]
		if isCategory {
			out[n] = true
			for _, s := range subs {
				out[s] = true
			}
			continue
		}
		// Sub-protection: record it, plus verify it's a real name.
		if isKnownSub(n, cat) {
			out[n] = true
		}
	}
	return out
}

func isKnownSub(name string, cat map[string][]string) bool {
	for _, subs := range cat {
		for _, s := range subs {
			if s == name {
				return true
			}
		}
	}
	return false
}
