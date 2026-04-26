// Package protections defines the Protection interface and the canonical-name
// catalog used for config validation, disable-list resolution, audit-log CWE
// enrichment, and HTTP block-status resolution.
//
// Protections is the single source of truth: every protection appears as one
// row carrying its canonical name, parent category (if any), CWE identifier
// (if any), and the HTTP status code to write on a block (if non-default).
// All other accessors in this file derive from this slice. Adding a new
// protection means appending one row.
//
// Canonical names must match docs/design/protections.md exactly. Tests pin
// the count per category against the doc so drift is caught early.
package protections

import "net/http"

// ProtectionMeta is one row of the protection catalog. Categories carry an
// empty Parent; sub-protections name their parent category. Native top-level
// protections (no children) also have an empty Parent.
type ProtectionMeta struct {
	Name   string // canonical name used in config, metrics, audit logs
	Parent string // parent category name; "" for categories and native top-level
	CWE    string // e.g. "CWE-89"; "" if not applicable
	Status int    // HTTP status code on block; 0 means "use the default" (403)
}

// Protections is the canonical-name registry. Order within a parent matters:
// AllNames() / ExpandDisable() / Catalog() preserve the slice order in their
// derived structures.
var Protections = []ProtectionMeta{
	// ── CRS-backed: scanner detection ────────────────────────────
	{Name: "scanner-detection"},
	{Name: "scanner-detection-user-agent", Parent: "scanner-detection", CWE: "CWE-200"},

	// ── CRS-backed: protocol enforcement ─────────────────────────
	{Name: "protocol-enforcement"},
	{Name: "protocol-enforcement-request-line", Parent: "protocol-enforcement", CWE: "CWE-20"},
	{Name: "protocol-enforcement-multipart-bypass", Parent: "protocol-enforcement", CWE: "CWE-20"},
	{Name: "protocol-enforcement-content-length", Parent: "protocol-enforcement", CWE: "CWE-20"},
	{Name: "protocol-enforcement-get-head-body", Parent: "protocol-enforcement", CWE: "CWE-20"},
	{Name: "protocol-enforcement-post-content-length", Parent: "protocol-enforcement", CWE: "CWE-20"},
	{Name: "protocol-enforcement-ambiguous-length", Parent: "protocol-enforcement", CWE: "CWE-444"},
	{Name: "protocol-enforcement-range", Parent: "protocol-enforcement", CWE: "CWE-400"},
	{Name: "protocol-enforcement-connection-header", Parent: "protocol-enforcement", CWE: "CWE-20"},
	{Name: "protocol-enforcement-url-encoding", Parent: "protocol-enforcement", CWE: "CWE-174"},
	{Name: "protocol-enforcement-utf8-abuse", Parent: "protocol-enforcement", CWE: "CWE-176"},
	{Name: "protocol-enforcement-null-byte", Parent: "protocol-enforcement", CWE: "CWE-158"},
	{Name: "protocol-enforcement-invalid-chars", Parent: "protocol-enforcement", CWE: "CWE-20"},
	{Name: "protocol-enforcement-host-header", Parent: "protocol-enforcement", CWE: "CWE-20"},
	{Name: "protocol-enforcement-accept-header", Parent: "protocol-enforcement", CWE: "CWE-20"},
	{Name: "protocol-enforcement-user-agent-header", Parent: "protocol-enforcement", CWE: "CWE-20"},
	{Name: "protocol-enforcement-content-type-header", Parent: "protocol-enforcement", CWE: "CWE-20"},
	{Name: "protocol-enforcement-argument-limits", Parent: "protocol-enforcement", CWE: "CWE-400"},
	{Name: "protocol-enforcement-upload-size", Parent: "protocol-enforcement", CWE: "CWE-400"},
	{Name: "protocol-enforcement-content-type-policy", Parent: "protocol-enforcement", CWE: "CWE-20"},
	{Name: "protocol-enforcement-http-version", Parent: "protocol-enforcement", CWE: "CWE-20"},
	{Name: "protocol-enforcement-file-extension", Parent: "protocol-enforcement", CWE: "CWE-20"},
	{Name: "protocol-enforcement-restricted-header", Parent: "protocol-enforcement", CWE: "CWE-20"},
	{Name: "protocol-enforcement-backup-file-access", Parent: "protocol-enforcement", CWE: "CWE-538"},
	{Name: "protocol-enforcement-accept-encoding", Parent: "protocol-enforcement", CWE: "CWE-20"},
	{Name: "protocol-enforcement-reqbody-processor", Parent: "protocol-enforcement", CWE: "CWE-20"},
	{Name: "protocol-enforcement-raw-uri-fragment", Parent: "protocol-enforcement", CWE: "CWE-20"},
	{Name: "protocol-enforcement-method-override", Parent: "protocol-enforcement"},

	// ── CRS-backed: protocol attacks ─────────────────────────────
	{Name: "protocol-attack"},
	{Name: "protocol-attack-smuggling", Parent: "protocol-attack", CWE: "CWE-444"},
	{Name: "protocol-attack-response-splitting", Parent: "protocol-attack", CWE: "CWE-113"},
	{Name: "protocol-attack-header-injection", Parent: "protocol-attack", CWE: "CWE-93"},
	{Name: "protocol-attack-ldap-injection", Parent: "protocol-attack", CWE: "CWE-90"},
	{Name: "protocol-attack-parameter-pollution", Parent: "protocol-attack", CWE: "CWE-235"},
	{Name: "protocol-attack-range-header", Parent: "protocol-attack", CWE: "CWE-400"},
	{Name: "protocol-attack-mod-proxy", Parent: "protocol-attack", CWE: "CWE-441"},
	{Name: "protocol-attack-legacy-cookie", Parent: "protocol-attack", CWE: "CWE-20"},
	{Name: "protocol-attack-dangerous-content-type", Parent: "protocol-attack", CWE: "CWE-20"},

	// ── CRS-backed: multipart attacks ────────────────────────────
	{Name: "multipart-attack"},
	{Name: "multipart-attack-global-charset", Parent: "multipart-attack", CWE: "CWE-20"},
	{Name: "multipart-attack-content-type", Parent: "multipart-attack", CWE: "CWE-20"},
	{Name: "multipart-attack-transfer-encoding", Parent: "multipart-attack", CWE: "CWE-20"},
	{Name: "multipart-attack-header-chars", Parent: "multipart-attack", CWE: "CWE-20"},

	// ── CRS-backed: local file inclusion ─────────────────────────
	{Name: "local-file-inclusion"},
	{Name: "lfi-path-traversal", Parent: "local-file-inclusion", CWE: "CWE-22"},
	{Name: "lfi-system-files", Parent: "local-file-inclusion", CWE: "CWE-98"},
	{Name: "lfi-restricted-files", Parent: "local-file-inclusion", CWE: "CWE-98"},
	{Name: "lfi-ai-artifacts", Parent: "local-file-inclusion", CWE: "CWE-540"},

	// ── CRS-backed: remote file inclusion ────────────────────────
	{Name: "remote-file-inclusion"},
	{Name: "rfi-ip-parameter", Parent: "remote-file-inclusion", CWE: "CWE-98"},
	{Name: "rfi-vulnerable-parameter", Parent: "remote-file-inclusion", CWE: "CWE-98"},
	{Name: "rfi-trailing-question", Parent: "remote-file-inclusion", CWE: "CWE-98"},
	{Name: "rfi-off-domain", Parent: "remote-file-inclusion", CWE: "CWE-98"},

	// ── CRS-backed: remote code execution ────────────────────────
	{Name: "remote-code-execution"},
	{Name: "rce-unix-command", Parent: "remote-code-execution", CWE: "CWE-78"},
	{Name: "rce-unix-shell-expression", Parent: "remote-code-execution", CWE: "CWE-78"},
	{Name: "rce-unix-shell-alias", Parent: "remote-code-execution", CWE: "CWE-78"},
	{Name: "rce-unix-shell-history", Parent: "remote-code-execution", CWE: "CWE-78"},
	{Name: "rce-unix-brace-expansion", Parent: "remote-code-execution", CWE: "CWE-78"},
	{Name: "rce-unix-wildcard-bypass", Parent: "remote-code-execution", CWE: "CWE-78"},
	{Name: "rce-unix-bypass-technique", Parent: "remote-code-execution", CWE: "CWE-78"},
	{Name: "rce-unix-fork-bomb", Parent: "remote-code-execution", CWE: "CWE-400"},
	{Name: "rce-windows-command", Parent: "remote-code-execution", CWE: "CWE-78"},
	{Name: "rce-windows-powershell", Parent: "remote-code-execution", CWE: "CWE-78"},
	{Name: "rce-shellshock", Parent: "remote-code-execution", CWE: "CWE-78"},
	{Name: "rce-executable-upload", Parent: "remote-code-execution", CWE: "CWE-434"},
	{Name: "rce-sqlite-shell", Parent: "remote-code-execution", CWE: "CWE-78"},
	{Name: "rce-mail-protocol-injection", Parent: "remote-code-execution", CWE: "CWE-77"},

	// ── CRS-backed: PHP injection ────────────────────────────────
	{Name: "php-injection"},
	{Name: "php-open-tag", Parent: "php-injection", CWE: "CWE-94"},
	{Name: "php-file-upload", Parent: "php-injection", CWE: "CWE-434"},
	{Name: "php-config-directive", Parent: "php-injection", CWE: "CWE-94"},
	{Name: "php-variable-abuse", Parent: "php-injection", CWE: "CWE-94"},
	{Name: "php-stream-wrapper", Parent: "php-injection", CWE: "CWE-94"},
	{Name: "php-function-high-risk", Parent: "php-injection", CWE: "CWE-94"},
	{Name: "php-function-medium-risk", Parent: "php-injection", CWE: "CWE-94"},
	{Name: "php-function-low-value", Parent: "php-injection", CWE: "CWE-94"},
	{Name: "php-object-injection", Parent: "php-injection", CWE: "CWE-502"},
	{Name: "php-variable-function-call", Parent: "php-injection", CWE: "CWE-94"},

	// ── CRS-backed: generic injection ────────────────────────────
	{Name: "generic-injection"},
	{Name: "nodejs-injection", Parent: "generic-injection", CWE: "CWE-94"},
	{Name: "nodejs-dos", Parent: "generic-injection", CWE: "CWE-400"},
	{Name: "ssrf-cloud-metadata", Parent: "generic-injection", CWE: "CWE-918"},
	{Name: "ssrf-url-scheme", Parent: "generic-injection", CWE: "CWE-918"},
	{Name: "prototype-pollution", Parent: "generic-injection", CWE: "CWE-1321"},
	{Name: "perl-injection", Parent: "generic-injection", CWE: "CWE-94"},
	{Name: "ruby-injection", Parent: "generic-injection", CWE: "CWE-94"},
	{Name: "data-scheme-injection", Parent: "generic-injection", CWE: "CWE-94"},
	{Name: "template-injection", Parent: "generic-injection", CWE: "CWE-1336"},

	// ── CRS-backed: XSS ──────────────────────────────────────────
	{Name: "xss"},
	{Name: "xss-libinjection", Parent: "xss", CWE: "CWE-79"},
	{Name: "xss-script-tag", Parent: "xss", CWE: "CWE-79"},
	{Name: "xss-event-handler", Parent: "xss", CWE: "CWE-79"},
	{Name: "xss-attribute-injection", Parent: "xss", CWE: "CWE-79"},
	{Name: "xss-javascript-uri", Parent: "xss", CWE: "CWE-79"},
	{Name: "xss-html-injection", Parent: "xss", CWE: "CWE-79"},
	{Name: "xss-denylist-keyword", Parent: "xss", CWE: "CWE-79"},
	{Name: "xss-ie-filter", Parent: "xss", CWE: "CWE-79"},
	{Name: "xss-javascript-keyword", Parent: "xss", CWE: "CWE-79"},
	{Name: "xss-encoding-evasion", Parent: "xss", CWE: "CWE-79"},
	{Name: "xss-obfuscation", Parent: "xss", CWE: "CWE-79"},
	{Name: "xss-angularjs-csti", Parent: "xss", CWE: "CWE-79"},

	// ── CRS-backed: SQL injection ────────────────────────────────
	{Name: "sql-injection"},
	{Name: "sql-injection-libinjection", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-operator", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-boolean", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-common-dbnames", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-function", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-blind", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-auth-bypass", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-mssql", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-integer-overflow", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-conditional", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-chained", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-union", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-nosql", Parent: "sql-injection", CWE: "CWE-943"},
	{Name: "sql-injection-stored-procedure", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-classic-probe", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-concat", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-char-anomaly", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-comment", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-hex-encoding", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-tick-bypass", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-termination", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-json", Parent: "sql-injection", CWE: "CWE-89"},
	{Name: "sql-injection-scientific-notation", Parent: "sql-injection", CWE: "CWE-89"},

	// ── CRS-backed: session fixation ─────────────────────────────
	{Name: "session-fixation"},
	{Name: "session-fixation-set-cookie-html", Parent: "session-fixation", CWE: "CWE-384"},
	{Name: "session-fixation-sessionid-off-domain-referer", Parent: "session-fixation", CWE: "CWE-384"},
	{Name: "session-fixation-sessionid-no-referer", Parent: "session-fixation", CWE: "CWE-384"},

	// ── CRS-backed: Java injection ───────────────────────────────
	{Name: "java-injection"},
	{Name: "java-class-loading", Parent: "java-injection", CWE: "CWE-94"},
	{Name: "java-process-spawn", Parent: "java-injection", CWE: "CWE-78"},
	{Name: "java-deserialization", Parent: "java-injection", CWE: "CWE-502"},
	{Name: "java-script-upload", Parent: "java-injection", CWE: "CWE-434"},
	{Name: "java-log4j", Parent: "java-injection", CWE: "CWE-917"},
	{Name: "java-base64-keyword", Parent: "java-injection", CWE: "CWE-502"},

	// ── CRS-backed: data leakage (generic) ───────────────────────
	{Name: "data-leakage"},
	{Name: "data-leakage-directory-listing", Parent: "data-leakage", CWE: "CWE-548"},
	{Name: "data-leakage-cgi-source", Parent: "data-leakage", CWE: "CWE-540"},
	{Name: "data-leakage-aspnet-exception", Parent: "data-leakage", CWE: "CWE-209"},
	{Name: "data-leakage-5xx-status", Parent: "data-leakage", CWE: "CWE-209"},

	// ── CRS-backed: data leakage (SQL) ───────────────────────────
	{Name: "data-leakage-sql"},
	{Name: "data-leakage-sql-msaccess", Parent: "data-leakage-sql", CWE: "CWE-209"},
	{Name: "data-leakage-sql-oracle", Parent: "data-leakage-sql", CWE: "CWE-209"},
	{Name: "data-leakage-sql-db2", Parent: "data-leakage-sql", CWE: "CWE-209"},
	{Name: "data-leakage-sql-emc", Parent: "data-leakage-sql", CWE: "CWE-209"},
	{Name: "data-leakage-sql-firebird", Parent: "data-leakage-sql", CWE: "CWE-209"},
	{Name: "data-leakage-sql-frontbase", Parent: "data-leakage-sql", CWE: "CWE-209"},
	{Name: "data-leakage-sql-hsqldb", Parent: "data-leakage-sql", CWE: "CWE-209"},
	{Name: "data-leakage-sql-informix", Parent: "data-leakage-sql", CWE: "CWE-209"},
	{Name: "data-leakage-sql-ingres", Parent: "data-leakage-sql", CWE: "CWE-209"},
	{Name: "data-leakage-sql-interbase", Parent: "data-leakage-sql", CWE: "CWE-209"},
	{Name: "data-leakage-sql-maxdb", Parent: "data-leakage-sql", CWE: "CWE-209"},
	{Name: "data-leakage-sql-mssql", Parent: "data-leakage-sql", CWE: "CWE-209"},
	{Name: "data-leakage-sql-mysql", Parent: "data-leakage-sql", CWE: "CWE-209"},
	{Name: "data-leakage-sql-postgres", Parent: "data-leakage-sql", CWE: "CWE-209"},
	{Name: "data-leakage-sql-sqlite", Parent: "data-leakage-sql", CWE: "CWE-209"},
	{Name: "data-leakage-sql-sybase", Parent: "data-leakage-sql", CWE: "CWE-209"},

	// ── CRS-backed: data leakage (Java) ──────────────────────────
	{Name: "data-leakage-java"},
	{Name: "data-leakage-java-error", Parent: "data-leakage-java", CWE: "CWE-209"},

	// ── CRS-backed: data leakage (PHP) ───────────────────────────
	{Name: "data-leakage-php"},
	{Name: "data-leakage-php-info", Parent: "data-leakage-php", CWE: "CWE-209"},
	{Name: "data-leakage-php-source", Parent: "data-leakage-php", CWE: "CWE-540"},

	// ── CRS-backed: data leakage (IIS) ───────────────────────────
	{Name: "data-leakage-iis"},
	{Name: "data-leakage-iis-install-location", Parent: "data-leakage-iis", CWE: "CWE-200"},
	{Name: "data-leakage-iis-availability", Parent: "data-leakage-iis", CWE: "CWE-209"},
	{Name: "data-leakage-iis-info", Parent: "data-leakage-iis", CWE: "CWE-209"},

	// ── CRS-backed: web shell ────────────────────────────────────
	{Name: "web-shell"},
	{Name: "web-shell-detection", Parent: "web-shell", CWE: "CWE-506"},

	// ── CRS-backed: data leakage (Ruby) ──────────────────────────
	// Single-sub category whose sub shares the parent name. Both rows carry
	// the same CWE so CWEForProtection resolves by linear scan to the right
	// value regardless of which row matches first.
	{Name: "data-leakage-ruby", CWE: "CWE-209"},
	{Name: "data-leakage-ruby", Parent: "data-leakage-ruby", CWE: "CWE-209"},

	// ── Native protocol hardening ────────────────────────────────
	{Name: "request-smuggling", CWE: "CWE-444"},
	{Name: "crlf-injection", CWE: "CWE-93"},
	{Name: "null-byte-injection", CWE: "CWE-158"},
	{Name: "method-override"},
	{Name: "double-encoding", CWE: "CWE-174"},
	{Name: "unicode-normalization", CWE: "CWE-176"},
	{Name: "path-normalization", CWE: "CWE-22"},
	{Name: "slow-request", CWE: "CWE-400"},
	{Name: "http2-continuation-flood"},
	{Name: "http2-hpack-bomb", CWE: "CWE-400"},
	{Name: "http2-stream-limit", CWE: "CWE-400"},

	// ── Request validation ───────────────────────────────────────
	{Name: "max-body-size", CWE: "CWE-400", Status: http.StatusRequestEntityTooLarge},
	{Name: "max-url-length", CWE: "CWE-400", Status: http.StatusRequestURITooLong},
	{Name: "max-header-size", CWE: "CWE-400", Status: http.StatusRequestHeaderFieldsTooLarge},
	{Name: "max-header-count", CWE: "CWE-400", Status: http.StatusRequestHeaderFieldsTooLarge},
	{Name: "allowed-methods", Status: http.StatusMethodNotAllowed},
	{Name: "require-host-header", CWE: "CWE-20", Status: http.StatusBadRequest},
	{Name: "require-content-type", CWE: "CWE-20", Status: http.StatusUnsupportedMediaType},

	// ── Body parsing ─────────────────────────────────────────────
	{Name: "json-depth-limit", CWE: "CWE-400"},
	{Name: "json-key-limit", CWE: "CWE-400"},
	{Name: "xml-depth-limit", CWE: "CWE-400"},
	{Name: "xml-entity-expansion", CWE: "CWE-776"},

	// ── Resource protections ─────────────────────────────────────
	{Name: "max-inspection-size", CWE: "CWE-400"},
	{Name: "max-memory-buffer", CWE: "CWE-400"},
	{Name: "decompression-ratio-limit", CWE: "CWE-409"},
	{Name: "waf-evaluation-timeout", CWE: "CWE-400"},

	// ── File upload ──────────────────────────────────────────────
	{Name: "multipart-file-limit", CWE: "CWE-400"},
	{Name: "multipart-file-size", CWE: "CWE-400"},
	{Name: "multipart-allowed-types", CWE: "CWE-434"},
	{Name: "multipart-double-extension", CWE: "CWE-434"},

	// ── OpenAPI ──────────────────────────────────────────────────
	{Name: "openapi-path", Status: http.StatusNotFound},
	{Name: "openapi-method", Status: http.StatusMethodNotAllowed},
	{Name: "openapi-params", Status: http.StatusUnprocessableEntity},
	{Name: "openapi-body", Status: http.StatusUnprocessableEntity},
	{Name: "openapi-content-type", Status: http.StatusUnsupportedMediaType},

	// ── Security headers: injection ──────────────────────────────
	{Name: "header-hsts"},
	{Name: "header-csp"},
	{Name: "header-x-frame-options"},
	{Name: "header-x-content-type-options"},
	{Name: "header-referrer-policy"},
	{Name: "header-x-dns-prefetch"},
	{Name: "header-coop"},
	{Name: "header-coep"},
	{Name: "header-corp"},
	{Name: "header-permissions-policy"},
	{Name: "header-cache-control"},

	// ── Security headers: stripping ──────────────────────────────
	{Name: "strip-server"},
	{Name: "strip-x-powered-by"},
	{Name: "strip-aspnet-version"},
	{Name: "strip-generator"},
	{Name: "strip-drupal"},
	{Name: "strip-varnish"},
	{Name: "strip-via"},
	{Name: "strip-runtime"},
	{Name: "strip-debug"},
	{Name: "strip-backend-server"},
	{Name: "strip-version"},

	// ── Response inspection (opt-in) ─────────────────────────────
	{Name: "response-open-redirect", CWE: "CWE-601"},
	{Name: "response-openapi"},
}

// Catalog returns the canonical-name hierarchy: category → sub-protections.
// Native top-level protections (no children) appear as a key with an empty
// slice.
func Catalog() map[string][]string {
	out := map[string][]string{}
	for _, p := range Protections {
		if p.Parent == "" {
			if _, exists := out[p.Name]; !exists {
				out[p.Name] = []string{}
			}
			continue
		}
		out[p.Parent] = append(out[p.Parent], p.Name)
	}
	return out
}

// AllNames returns every canonical name (categories and sub-protections) as a
// flat set. Used by config validation to check disable-list entries.
func AllNames() map[string]bool {
	out := map[string]bool{}
	for _, p := range Protections {
		out[p.Name] = true
	}
	return out
}

// ExpandDisable resolves a disable list (which may contain category and/or
// sub-protection names) into the full set of disabled sub-protection names.
// Category names expand to the category plus every sub-protection under it.
// Sub-protection names map to themselves. Native top-level names map to
// themselves. Unknown names are silently dropped.
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

// CWEForProtection returns the CWE identifier for a canonical protection name,
// or "" if the protection has no associated CWE or is unknown. Walks the slice
// linearly — fine for audit-emit cadence.
func CWEForProtection(name string) string {
	for _, p := range Protections {
		if p.Name == name {
			return p.CWE
		}
	}
	return ""
}

// StatusFor returns the HTTP status code to write when the named protection
// blocks a request. Defaults to 403 Forbidden for any protection that does not
// declare a custom Status (and for unknown names). This is the unified
// replacement for the per-stage status switches.
func StatusFor(name string) int {
	for _, p := range Protections {
		if p.Name == name {
			if p.Status == 0 {
				return http.StatusForbidden
			}
			return p.Status
		}
	}
	return http.StatusForbidden
}

// IsDisabled reports whether the given canonical name is in the disabled set.
// The disabled set should be produced by ExpandDisable at config resolution
// time. This is the per-request hot-path check.
func IsDisabled(name string, disabled map[string]bool) bool {
	return disabled[name]
}
