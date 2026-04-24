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
			"rce-executable-upload",
			"rce-sqlite-shell",
			"rce-mail-protocol-injection",
		},
		"php-injection": {
			"php-open-tag",
			"php-file-upload",
			"php-config-directive",
			"php-variable-abuse",
			"php-stream-wrapper",
			"php-function-high-risk",
			"php-function-medium-risk",
			"php-function-low-value",
			"php-object-injection",
			"php-variable-function-call",
		},
		"generic-injection": {
			"nodejs-injection",
			"nodejs-dos",
			"ssrf-cloud-metadata",
			"ssrf-url-scheme",
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
			"sql-injection-nosql",
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
		"web-shell": {
			"web-shell-detection",
		},
		"data-leakage-ruby": {
			"data-leakage-ruby",
		},

		// ── Native protocol hardening (no sub-protections) ──
		"request-smuggling":        {},
		"crlf-injection":           {},
		"null-byte-injection":      {},
		"method-override":          {},
		"double-encoding":          {},
		"unicode-normalization":    {},
		"path-normalization":       {},
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

// CWEMap returns the canonical protection name → CWE identifier mapping.
// Values come from docs/design/protections.md. Empty string means no CWE
// is applicable for that protection.
func CWEMap() map[string]string {
	return map[string]string{
		// ── CRS-backed sub-protections ──────────────────────
		"scanner-detection-user-agent": "CWE-200",

		"protocol-enforcement-request-line":       "CWE-20",
		"protocol-enforcement-multipart-bypass":   "CWE-20",
		"protocol-enforcement-content-length":     "CWE-20",
		"protocol-enforcement-get-head-body":      "CWE-20",
		"protocol-enforcement-post-content-length": "CWE-20",
		"protocol-enforcement-ambiguous-length":   "CWE-444",
		"protocol-enforcement-range":              "CWE-400",
		"protocol-enforcement-connection-header":  "CWE-20",
		"protocol-enforcement-url-encoding":       "CWE-174",
		"protocol-enforcement-utf8-abuse":         "CWE-176",
		"protocol-enforcement-null-byte":          "CWE-158",
		"protocol-enforcement-invalid-chars":      "CWE-20",
		"protocol-enforcement-host-header":        "CWE-20",
		"protocol-enforcement-accept-header":      "CWE-20",
		"protocol-enforcement-user-agent-header":  "CWE-20",
		"protocol-enforcement-content-type-header": "CWE-20",
		"protocol-enforcement-argument-limits":    "CWE-400",
		"protocol-enforcement-upload-size":        "CWE-400",
		"protocol-enforcement-content-type-policy": "CWE-20",
		"protocol-enforcement-http-version":       "CWE-20",
		"protocol-enforcement-file-extension":     "CWE-20",
		"protocol-enforcement-restricted-header":  "CWE-20",
		"protocol-enforcement-backup-file-access": "CWE-538",
		"protocol-enforcement-accept-encoding":    "CWE-20",
		"protocol-enforcement-reqbody-processor":  "CWE-20",
		"protocol-enforcement-raw-uri-fragment":   "CWE-20",
		"protocol-enforcement-method-override":    "",

		"protocol-attack-smuggling":              "CWE-444",
		"protocol-attack-response-splitting":     "CWE-113",
		"protocol-attack-header-injection":       "CWE-93",
		"protocol-attack-ldap-injection":         "CWE-90",
		"protocol-attack-parameter-pollution":    "CWE-235",
		"protocol-attack-range-header":           "CWE-400",
		"protocol-attack-mod-proxy":              "CWE-441",
		"protocol-attack-legacy-cookie":          "CWE-20",
		"protocol-attack-dangerous-content-type": "CWE-20",

		"multipart-attack-global-charset":      "CWE-20",
		"multipart-attack-content-type":        "CWE-20",
		"multipart-attack-transfer-encoding":   "CWE-20",
		"multipart-attack-header-chars":        "CWE-20",

		"lfi-path-traversal":   "CWE-22",
		"lfi-system-files":     "CWE-98",
		"lfi-restricted-files": "CWE-98",
		"lfi-ai-artifacts":     "CWE-540",

		"rfi-ip-parameter":        "CWE-98",
		"rfi-vulnerable-parameter": "CWE-98",
		"rfi-trailing-question":   "CWE-98",
		"rfi-off-domain":          "CWE-98",

		"rce-unix-command":            "CWE-78",
		"rce-unix-shell-expression":   "CWE-78",
		"rce-unix-shell-alias":        "CWE-78",
		"rce-unix-shell-history":      "CWE-78",
		"rce-unix-brace-expansion":    "CWE-78",
		"rce-unix-wildcard-bypass":    "CWE-78",
		"rce-unix-bypass-technique":   "CWE-78",
		"rce-unix-fork-bomb":          "CWE-400",
		"rce-windows-command":         "CWE-78",
		"rce-windows-powershell":      "CWE-78",
		"rce-shellshock":              "CWE-78",
		"rce-executable-upload":       "CWE-434",
		"rce-sqlite-shell":            "CWE-78",
		"rce-mail-protocol-injection": "CWE-77",

		"php-open-tag":               "CWE-94",
		"php-file-upload":            "CWE-434",
		"php-config-directive":       "CWE-94",
		"php-variable-abuse":         "CWE-94",
		"php-stream-wrapper":         "CWE-94",
		"php-function-high-risk":     "CWE-94",
		"php-function-medium-risk":   "CWE-94",
		"php-function-low-value":     "CWE-94",
		"php-object-injection":       "CWE-502",
		"php-variable-function-call": "CWE-94",

		"nodejs-injection":      "CWE-94",
		"nodejs-dos":            "CWE-400",
		"ssrf-cloud-metadata":   "CWE-918",
		"ssrf-url-scheme":       "CWE-918",
		"prototype-pollution":   "CWE-1321",
		"perl-injection":        "CWE-94",
		"ruby-injection":        "CWE-94",
		"data-scheme-injection": "CWE-94",
		"template-injection":    "CWE-1336",

		"xss-libinjection":      "CWE-79",
		"xss-script-tag":        "CWE-79",
		"xss-event-handler":     "CWE-79",
		"xss-attribute-injection": "CWE-79",
		"xss-javascript-uri":    "CWE-79",
		"xss-html-injection":    "CWE-79",
		"xss-denylist-keyword":  "CWE-79",
		"xss-ie-filter":         "CWE-79",
		"xss-javascript-keyword": "CWE-79",
		"xss-encoding-evasion":  "CWE-79",
		"xss-obfuscation":       "CWE-79",
		"xss-angularjs-csti":    "CWE-79",

		"sql-injection-libinjection":      "CWE-89",
		"sql-injection-operator":          "CWE-89",
		"sql-injection-boolean":           "CWE-89",
		"sql-injection-common-dbnames":    "CWE-89",
		"sql-injection-function":          "CWE-89",
		"sql-injection-blind":             "CWE-89",
		"sql-injection-auth-bypass":       "CWE-89",
		"sql-injection-mssql":             "CWE-89",
		"sql-injection-integer-overflow":  "CWE-89",
		"sql-injection-conditional":       "CWE-89",
		"sql-injection-chained":           "CWE-89",
		"sql-injection-union":             "CWE-89",
		"sql-injection-nosql":             "CWE-943",
		"sql-injection-stored-procedure":  "CWE-89",
		"sql-injection-classic-probe":     "CWE-89",
		"sql-injection-concat":            "CWE-89",
		"sql-injection-char-anomaly":      "CWE-89",
		"sql-injection-comment":           "CWE-89",
		"sql-injection-hex-encoding":      "CWE-89",
		"sql-injection-tick-bypass":       "CWE-89",
		"sql-injection-termination":       "CWE-89",
		"sql-injection-json":              "CWE-89",
		"sql-injection-scientific-notation": "CWE-89",

		"session-fixation-set-cookie-html":            "CWE-384",
		"session-fixation-sessionid-off-domain-referer": "CWE-384",
		"session-fixation-sessionid-no-referer":       "CWE-384",

		"java-class-loading":    "CWE-94",
		"java-process-spawn":    "CWE-78",
		"java-deserialization":  "CWE-502",
		"java-script-upload":    "CWE-434",
		"java-log4j":            "CWE-917",
		"java-base64-keyword":   "CWE-502",

		"data-leakage-directory-listing":  "CWE-548",
		"data-leakage-cgi-source":         "CWE-540",
		"data-leakage-aspnet-exception":   "CWE-209",
		"data-leakage-5xx-status":         "CWE-209",

		"data-leakage-sql-msaccess":  "CWE-209",
		"data-leakage-sql-oracle":    "CWE-209",
		"data-leakage-sql-db2":       "CWE-209",
		"data-leakage-sql-emc":       "CWE-209",
		"data-leakage-sql-firebird":  "CWE-209",
		"data-leakage-sql-frontbase": "CWE-209",
		"data-leakage-sql-hsqldb":    "CWE-209",
		"data-leakage-sql-informix":  "CWE-209",
		"data-leakage-sql-ingres":    "CWE-209",
		"data-leakage-sql-interbase": "CWE-209",
		"data-leakage-sql-maxdb":     "CWE-209",
		"data-leakage-sql-mssql":     "CWE-209",
		"data-leakage-sql-mysql":     "CWE-209",
		"data-leakage-sql-postgres":  "CWE-209",
		"data-leakage-sql-sqlite":    "CWE-209",
		"data-leakage-sql-sybase":    "CWE-209",

		"data-leakage-java-error": "CWE-209",

		"data-leakage-php-info":   "CWE-209",
		"data-leakage-php-source": "CWE-540",

		"data-leakage-iis-install-location": "CWE-200",
		"data-leakage-iis-availability":     "CWE-209",
		"data-leakage-iis-info":             "CWE-209",

		"web-shell-detection": "CWE-506",

		"data-leakage-ruby": "CWE-209",

		// ── Native protocol hardening ───────────────────────
		"request-smuggling":        "CWE-444",
		"crlf-injection":           "CWE-93",
		"null-byte-injection":      "CWE-158",
		"method-override":          "",
		"double-encoding":          "CWE-174",
		"unicode-normalization":    "CWE-176",
		"path-normalization":       "CWE-22",
		"slow-request":             "CWE-400",
		"http2-continuation-flood": "",
		"http2-hpack-bomb":         "CWE-400",
		"http2-stream-limit":       "CWE-400",

		// ── Request validation ───────────────────────────────
		"max-body-size":        "CWE-400",
		"max-url-length":       "CWE-400",
		"max-header-size":      "CWE-400",
		"max-header-count":     "CWE-400",
		"allowed-methods":      "",
		"require-host-header":  "CWE-20",
		"require-content-type": "CWE-20",

		// ── Body parsing ─────��──────────────────────────────
		"json-depth-limit":     "CWE-400",
		"json-key-limit":       "CWE-400",
		"xml-depth-limit":      "CWE-400",
		"xml-entity-expansion": "CWE-776",

		// ── Resource protections ─────────────────────────────
		"max-inspection-size":       "CWE-400",
		"max-memory-buffer":         "CWE-400",
		"decompression-ratio-limit": "CWE-409",
		"waf-evaluation-timeout":    "CWE-400",

		// ── File upload ─────────────────────────────────────
		"multipart-file-limit":       "CWE-400",
		"multipart-file-size":        "CWE-400",
		"multipart-allowed-types":    "CWE-434",
		"multipart-double-extension": "CWE-434",

		// ── OpenAPI ─────────────────────────────────────────
		"openapi-path":         "",
		"openapi-method":       "",
		"openapi-params":       "",
		"openapi-body":         "",
		"openapi-content-type": "",

		// ── Response inspection ──────────────────────────────
		"response-open-redirect": "CWE-601",
		"response-openapi":       "",
	}
}

// CWEForProtection returns the CWE identifier for a canonical protection name,
// or "" if the protection has no associated CWE.
func CWEForProtection(name string) string {
	return CWEMap()[name]
}
