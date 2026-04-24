# Protections

> **When to read**: implementing or modifying a protection, adding a new protection, mapping protections to ASVS/CWE, checking the canonical name for a protection, or deciding what to put in a `disable` list. **Not needed for**: feature scope decisions (use `features.md`), build/CI tasks (use `build.md`).

Every protection is enabled by default. Teams disable per route using canonical names in the `disable` list.

## Hierarchy model

Protections use a two-level hierarchy: **categories** and **sub-protections**.

- A **category** (e.g. `sql-injection`) is a shorthand that controls all sub-protections beneath it.
- A **sub-protection** (e.g. `sql-injection-union`) is a specific attack technique mapped to a cluster of CRS rules.
- Both levels work in the `disable` list. Disabling `sql-injection` disables all `sql-injection-*` sub-protections. Disabling `sql-injection-union` only disables that specific technique.
- Metrics use the sub-protection level: `waf_requests_blocked_total{protection="sql-injection-union"}`.
- Audit logs include both: `matched_protections: ["sql-injection", "sql-injection-union"]`.

The full sub-protection enumeration is derived from the CRS v4 rule files (see `protections-crs-mapping.md` for the internal CRS-rule-ID mapping). The tables below are the user-facing surface: canonical name, description, CWE.

## CRS-backed protections

### `scanner-detection` — CRS 913xxx

Known vulnerability scanner signatures.

| Sub-protection | Description | CWE |
|---|---|---|
| `scanner-detection-user-agent` | Requests whose User-Agent matches known security-scanner signatures | CWE-200 |

### `protocol-enforcement` — CRS 920xxx

HTTP specification conformance. Detects malformed requests, abusive encoding, policy violations on headers and URLs.

| Sub-protection | Description | CWE |
|---|---|---|
| `protocol-enforcement-request-line` | Invalid HTTP request line | CWE-20 |
| `protocol-enforcement-multipart-bypass` | Attempted `multipart/form-data` parser bypass | CWE-20 |
| `protocol-enforcement-content-length` | Non-numeric `Content-Length` | CWE-20 |
| `protocol-enforcement-get-head-body` | GET/HEAD request carrying a body or `Transfer-Encoding` | CWE-20 |
| `protocol-enforcement-post-content-length` | POST without `Content-Length` and without `Transfer-Encoding` | CWE-20 |
| `protocol-enforcement-ambiguous-length` | Both `Content-Length` and `Transfer-Encoding` present (overlaps native `request-smuggling`) | CWE-444 |
| `protocol-enforcement-range` | Invalid, abusive, or obsolete `Range`/`Request-Range` headers | CWE-400 |
| `protocol-enforcement-connection-header` | Multiple or conflicting `Connection` headers | CWE-20 |
| `protocol-enforcement-url-encoding` | URL-encoding abuse, double-encoding, abnormal escapes | CWE-174 |
| `protocol-enforcement-utf8-abuse` | UTF-8 abuse, full/half-width Unicode bypass attempts | CWE-176 |
| `protocol-enforcement-null-byte` | Null byte in request (overlaps native `null-byte-injection`) | CWE-158 |
| `protocol-enforcement-invalid-chars` | Non-printable or out-of-set characters in request or headers | CWE-20 |
| `protocol-enforcement-host-header` | Missing, empty, or numeric-IP `Host` header | CWE-20 |
| `protocol-enforcement-accept-header` | Missing, empty, or illegal `Accept` header | CWE-20 |
| `protocol-enforcement-user-agent-header` | Missing or empty `User-Agent` header | CWE-20 |
| `protocol-enforcement-content-type-header` | Missing, illegal, or duplicated `Content-Type` header | CWE-20 |
| `protocol-enforcement-argument-limits` | Too many arguments, overlong name/value, total size exceeded | CWE-400 |
| `protocol-enforcement-upload-size` | Individual or combined upload size exceeds policy | CWE-400 |
| `protocol-enforcement-content-type-policy` | Request `Content-Type` not allowed by policy | CWE-20 |
| `protocol-enforcement-http-version` | HTTP protocol version not allowed by policy | CWE-20 |
| `protocol-enforcement-file-extension` | URL file extension restricted by policy | CWE-20 |
| `protocol-enforcement-restricted-header` | Restricted or deprecated header present (e.g. `x-up-devcap-post-charset`, invalid `Cache-Control`) | CWE-20 |
| `protocol-enforcement-backup-file-access` | Attempt to access backup or working file (`.bak`, `.old`, `~`) | CWE-538 |
| `protocol-enforcement-accept-encoding` | Oversized or illegal `Accept-Encoding` header | CWE-20 |
| `protocol-enforcement-reqbody-processor` | Request body processor error or mismatch | CWE-20 |
| `protocol-enforcement-raw-uri-fragment` | Raw (unencoded) fragment in request URI | CWE-20 |
| `protocol-enforcement-method-override` | HTTP method override attempt via `_method` parameter (overlaps native `method-override`) | — |

ASVS: 13.1

### `protocol-attack` — CRS 921xxx

Smuggling-like protocol attacks.

| Sub-protection | Description | CWE |
|---|---|---|
| `protocol-attack-smuggling` | HTTP request smuggling (overlaps native `request-smuggling`) | CWE-444 |
| `protocol-attack-response-splitting` | HTTP response splitting in request inputs | CWE-113 |
| `protocol-attack-header-injection` | Header injection via CR/LF in payload or headers (overlaps native `crlf-injection`) | CWE-93 |
| `protocol-attack-ldap-injection` | LDAP query injection | CWE-90 |
| `protocol-attack-parameter-pollution` | HTTP parameter pollution (duplicate/array-notation abuse) | CWE-235 |
| `protocol-attack-range-header` | Suspicious `Range` header detected | CWE-400 |
| `protocol-attack-mod-proxy` | `mod_proxy`/CVE-2021-40438-style proxy bypass attempts | CWE-441 |
| `protocol-attack-legacy-cookie` | Legacy RFC2109 (Cookies v1) syntax used | CWE-20 |
| `protocol-attack-dangerous-content-type` | Dangerous content type outside the declared MIME (e.g. HTML smuggling) | CWE-20 |

### `multipart-attack` — CRS 922xxx

Multipart request abuse.

| Sub-protection | Description | CWE |
|---|---|---|
| `multipart-attack-global-charset` | `multipart/form-data` global `_charset_` definition not allowed by policy | CWE-20 |
| `multipart-attack-content-type` | Illegal or unexpected `Content-Type` inside multipart part | CWE-20 |
| `multipart-attack-transfer-encoding` | Deprecated `Content-Transfer-Encoding` in multipart part (RFC 7578) | CWE-20 |
| `multipart-attack-header-chars` | Multipart header contains characters outside valid range | CWE-20 |

### `local-file-inclusion` — CRS 930xxx

Local file inclusion and path traversal in parameters.

| Sub-protection | Description | CWE |
|---|---|---|
| `lfi-path-traversal` | Directory traversal sequences (`../`, `....//`, encoded variants) | CWE-22 |
| `lfi-system-files` | Access to known sensitive OS files (`/etc/passwd`, `web.config`, etc.) | CWE-98 |
| `lfi-restricted-files` | Access to restricted file paths or extensions (`.ini`, `.log`, `.bak`, `.sql`) | CWE-98 |
| `lfi-ai-artifacts` | Access to AI coding-assistant artifact files (e.g. `.aider*`, `.cursorrules`) | CWE-540 |

ASVS: 1.2.7

### `remote-file-inclusion` — CRS 931xxx

Remote file inclusion attempts.

| Sub-protection | Description | CWE |
|---|---|---|
| `rfi-ip-parameter` | IP address as URL in parameter value | CWE-98 |
| `rfi-vulnerable-parameter` | Known-vulnerable parameter name used with URL payload | CWE-98 |
| `rfi-trailing-question` | URL payload with trailing `?` (null-terminator evasion) | CWE-98 |
| `rfi-off-domain` | Off-domain URL reference in parameter | CWE-98 |

ASVS: 1.2.7

### `remote-code-execution` — CRS 932xxx

OS command injection and code execution detection.

| Sub-protection | Description | CWE |
|---|---|---|
| `rce-unix-command` | Unix command injection (cat, ls, wget, curl, nc, etc.) including pipe/evasion variants | CWE-78 |
| `rce-unix-shell-expression` | Shell expressions: `$(...)`, `` `...` ``, `${...}`, `<()` | CWE-78 |
| `rce-unix-shell-alias` | Unix shell alias invocation | CWE-78 |
| `rce-unix-shell-history` | Unix shell history invocation (`!!`, `!-1`) | CWE-78 |
| `rce-unix-brace-expansion` | Unix brace expansion (`{a,b}`) abuse | CWE-78 |
| `rce-unix-wildcard-bypass` | Wildcard and glob bypass technique | CWE-78 |
| `rce-unix-bypass-technique` | Quote/backslash/tilde RCE bypass techniques | CWE-78 |
| `rce-unix-fork-bomb` | Shell fork-bomb pattern | CWE-400 |
| `rce-windows-command` | Windows command injection (cmd.exe, FOR/IF) | CWE-78 |
| `rce-windows-powershell` | Windows PowerShell command or alias injection | CWE-78 |
| `rce-shellshock` | Bash Shellshock (CVE-2014-6271) | CVE-2014-6271 |
| `rce-executable-upload` | Restricted script/executable file upload attempt | CWE-434 |
| `rce-sqlite-shell` | SQLite dot-command system execution | CWE-78 |
| `rce-mail-protocol-injection` | Mail-protocol command injection (SMTP/IMAP/POP3) via CRLF-prefixed command in parameter | CWE-77 |

ASVS: 1.2.5

### `php-injection` — CRS 933xxx

PHP-specific code injection.

| Sub-protection | Description | CWE |
|---|---|---|
| `php-open-tag` | PHP open/close tag injection (`<?php`, `?>`) | CWE-94 |
| `php-file-upload` | PHP script file upload (`.php`, `.phtml`, `.phar`, session file) | CWE-434 |
| `php-config-directive` | PHP configuration directive manipulation (`allow_url_fopen`, `auto_prepend_file`, etc.) | CWE-94 |
| `php-variable-abuse` | PHP superglobal or variable-variable abuse | CWE-94 |
| `php-stream-wrapper` | PHP stream I/O wrapper access: `php://input`, `php://filter`, `data://`, `phar://`, `expect://`, `ssh2://` | CWE-94 |
| `php-function-high-risk` | High-risk PHP functions (`eval`, `exec`, `system`, `passthru`, `popen`) | CWE-94 |
| `php-function-medium-risk` | Medium-risk PHP functions | CWE-94 |
| `php-function-low-value` | Low-value PHP functions (higher false-positive rate, paranoia-gated) | CWE-94 |
| `php-object-injection` | PHP serialized-object injection (`O:`, `C:`) | CWE-502 |
| `php-variable-function-call` | Variable function call / callable abuse | CWE-94 |

ASVS: 1.2.5

### `generic-injection` — CRS 934xxx

Language-agnostic and less-common injection attacks.

| Sub-protection | Description | CWE |
|---|---|---|
| `nodejs-injection` | Node.js code injection (`require`, `child_process`, `eval`) | CWE-94 |
| `nodejs-dos` | Node.js specific DoS pattern | CWE-400 |
| `ssrf-cloud-metadata` | Cloud-provider metadata-service URL: `169.254.169.254`, `metadata.google.internal`, etc. | CWE-918 |
| `ssrf-url-scheme` | Server-side request forgery via IP-as-URL or internal-scheme reference in parameter | CWE-918 |
| `prototype-pollution` | JavaScript prototype pollution (`__proto__`, `constructor.prototype`) | CWE-1321 |
| `perl-injection` | Perl code injection | CWE-94 |
| `ruby-injection` | Ruby code injection | CWE-94 |
| `data-scheme-injection` | `data:` scheme payload injection | CWE-94 |
| `template-injection` | Server-side template injection (Jinja2, Twig, Freemarker, etc.) | CWE-1336 |

ASVS: 1.2.5

### `xss` — CRS 941xxx

Cross-site scripting detection in request fields.

| Sub-protection | Description | CWE |
|---|---|---|
| `xss-libinjection` | XSS detected via libinjection engine | CWE-79 |
| `xss-script-tag` | `<script>` tag injection and variants | CWE-79 |
| `xss-event-handler` | Event-handler injection (`onload`, `onerror`, `onclick`, etc.) | CWE-79 |
| `xss-attribute-injection` | Attribute-based XSS (disallowed attributes, NoScript attribute injection) | CWE-79 |
| `xss-javascript-uri` | `javascript:` URI scheme injection | CWE-79 |
| `xss-html-injection` | HTML tag injection (iframe, object, embed, svg, HTML tag handlers) | CWE-79 |
| `xss-denylist-keyword` | Node-Validator deny-list keyword match | CWE-79 |
| `xss-ie-filter` | Legacy IE XSS-filter signatures (broad pattern library) | CWE-79 |
| `xss-javascript-keyword` | Bare JavaScript keyword / global / method / call without parentheses | CWE-79 |
| `xss-encoding-evasion` | Malformed US-ASCII or UTF-7 XSS encoding evasion | CWE-79 |
| `xss-obfuscation` | JSFuck / Hieroglyphy-style obfuscation | CWE-79 |
| `xss-angularjs-csti` | AngularJS client-side template injection | CWE-79 |

ASVS: 1.1.1

### `sql-injection` — CRS 942xxx

SQL injection detection across all request fields (URL, query params, headers, body).

| Sub-protection | Description | CWE |
|---|---|---|
| `sql-injection-libinjection` | SQLi detected via libinjection engine | CWE-89 |
| `sql-injection-operator` | SQL operator abuse (`BETWEEN`, `LIKE`, `HAVING`, `MATCH AGAINST`) | CWE-89 |
| `sql-injection-boolean` | Boolean-based SQLi (`OR 1=1`, `AND 1=1`) | CWE-89 |
| `sql-injection-common-dbnames` | Known database/schema names (`information_schema`, `mysql.user`, etc.) | CWE-89 |
| `sql-injection-function` | SQL function abuse (`CONCAT`, `CHAR`, `CONV`, `HEX`, JSON functions) | CWE-89 |
| `sql-injection-blind` | Blind and time-based SQLi (`SLEEP`, `BENCHMARK`, `WAITFOR`, `pg_sleep`) | CWE-89 |
| `sql-injection-auth-bypass` | Authentication bypass payloads (`' OR ''='`, escaped-quote tricks) | CWE-89 |
| `sql-injection-mssql` | MSSQL-specific syntax (code execution, charset DoS) | CWE-89 |
| `sql-injection-integer-overflow` | Integer-overflow payloads (from skipfish test corpus) | CWE-89 |
| `sql-injection-conditional` | Conditional SQLi (`CASE WHEN`, `IF(...)`, `LIKE`) | CWE-89 |
| `sql-injection-chained` | Chained/stacked SQL injection probes | CWE-89 |
| `sql-injection-union` | UNION-based SQLi | CWE-89 |
| `sql-injection-nosql` | NoSQL operator injection (`$where`, `$ne`, `$gt`, etc.) | CWE-943 |
| `sql-injection-stored-procedure` | Stored procedure / UDF injection (CREATE FUNCTION/PROCEDURE) | CWE-89 |
| `sql-injection-classic-probe` | Classic keyword probes (`HAVING`, `OR`, `AND`, plus broad DB-function sets) | CWE-89 |
| `sql-injection-concat` | Concatenated SQLi / SQLLFI attempts | CWE-89 |
| `sql-injection-char-anomaly` | Anomalous count of SQL meta-characters in cookies or args | CWE-89 |
| `sql-injection-comment` | Comment-based SQLi (`--`, `#`, `/**/`, backtick-termination) | CWE-89 |
| `sql-injection-hex-encoding` | Binary/hex encoded payloads (`0x...`, `x'...'`, `b'...'`) | CWE-89 |
| `sql-injection-tick-bypass` | Backtick or tick-only bypass attempts | CWE-89 |
| `sql-injection-termination` | Query termination payload (`';`) | CWE-89 |
| `sql-injection-json` | JSON-based SQL injection | CWE-89 |
| `sql-injection-scientific-notation` | MySQL scientific-notation payload | CWE-89 |

ASVS: 1.2.1, 1.2.2

### `session-fixation` — CRS 943xxx

Session fixation attempts.

| Sub-protection | Description | CWE |
|---|---|---|
| `session-fixation-set-cookie-html` | Attempt to set cookie values via injected HTML | CWE-384 |
| `session-fixation-sessionid-off-domain-referer` | SessionID parameter with off-domain `Referer` | CWE-384 |
| `session-fixation-sessionid-no-referer` | SessionID parameter with no `Referer` | CWE-384 |

ASVS: 3.2.1

### `java-injection` — CRS 944xxx

Java-specific injection patterns.

| Sub-protection | Description | CWE |
|---|---|---|
| `java-class-loading` | Suspicious Java class loading, reflection, or malicious class-loading payload | CWE-94 |
| `java-process-spawn` | Java process spawn (CVE-2017-9805 and similar) | CWE-78 |
| `java-deserialization` | Java deserialization (CVE-2015-4852, magic bytes raw or base64) | CWE-502 |
| `java-script-upload` | JSP/JSPX file upload | CWE-434 |
| `java-log4j` | Log4Shell / JNDI injection (`${jndi:ldap://}`) | CWE-917 |
| `java-base64-keyword` | Base64-encoded suspicious Java keyword | CWE-502 |

ASVS: 1.2.5

### `data-leakage` — CRS 950xxx

Generic data leakage in responses.

| Sub-protection | Description | CWE |
|---|---|---|
| `data-leakage-directory-listing` | Directory-listing response body | CWE-548 |
| `data-leakage-cgi-source` | CGI script source code leaked | CWE-540 |
| `data-leakage-aspnet-exception` | ASP.NET exception details in response | CWE-209 |
| `data-leakage-5xx-status` | Application returned a 5xx status (probable information disclosure) | CWE-209 |

ASVS: 7.4.1

### `data-leakage-sql` — CRS 951xxx

SQL error messages leaked in response bodies. One sub-protection per database engine.

| Sub-protection | Description | CWE |
|---|---|---|
| `data-leakage-sql-msaccess` | Microsoft Access SQL error | CWE-209 |
| `data-leakage-sql-oracle` | Oracle SQL error (`ORA-NNNNN`, `java.sql.SQLException`) | CWE-209 |
| `data-leakage-sql-db2` | IBM DB2 SQL error | CWE-209 |
| `data-leakage-sql-emc` | EMC SQL error | CWE-209 |
| `data-leakage-sql-firebird` | Firebird SQL error | CWE-209 |
| `data-leakage-sql-frontbase` | Frontbase SQL error | CWE-209 |
| `data-leakage-sql-hsqldb` | HSQLDB SQL error | CWE-209 |
| `data-leakage-sql-informix` | Informix SQL error | CWE-209 |
| `data-leakage-sql-ingres` | Ingres SQL error | CWE-209 |
| `data-leakage-sql-interbase` | Interbase SQL error | CWE-209 |
| `data-leakage-sql-maxdb` | MaxDB SQL error | CWE-209 |
| `data-leakage-sql-mssql` | Microsoft SQL Server error (`System.Data.SqlClient`, OLEDB) | CWE-209 |
| `data-leakage-sql-mysql` | MySQL SQL error | CWE-209 |
| `data-leakage-sql-postgres` | PostgreSQL SQL error | CWE-209 |
| `data-leakage-sql-sqlite` | SQLite SQL error | CWE-209 |
| `data-leakage-sql-sybase` | Sybase SQL error | CWE-209 |

### `data-leakage-java` — CRS 952xxx

| Sub-protection | Description | CWE |
|---|---|---|
| `data-leakage-java-error` | Java stack trace or framework error in response | CWE-209 |

### `data-leakage-php` — CRS 953xxx

| Sub-protection | Description | CWE |
|---|---|---|
| `data-leakage-php-info` | PHP information leakage (errors, warnings, notices) | CWE-209 |
| `data-leakage-php-source` | PHP source code leaked in response | CWE-540 |

### `data-leakage-iis` — CRS 954xxx

| Sub-protection | Description | CWE |
|---|---|---|
| `data-leakage-iis-install-location` | IIS install path disclosure | CWE-200 |
| `data-leakage-iis-availability` | IIS application availability error | CWE-209 |
| `data-leakage-iis-info` | IIS information leakage (version, ADODB errors) | CWE-209 |

### `web-shell` — CRS 955xxx

Web shell signatures in response bodies. Detects installed backdoors by matching known shell UI markers.

| Sub-protection | Description | CWE |
|---|---|---|
| `web-shell-detection` | Known web shell signatures in response body (PHP, ASP, and generic shell UIs) | CWE-506 |

### `data-leakage-ruby` — CRS 956xxx

| Sub-protection | Description | CWE |
|---|---|---|
| `data-leakage-ruby` | Ruby error messages, stack traces, and ERB template fragments in response body | CWE-209 |

---

## Protocol hardening protections

These are implemented natively in the barbacana module, independent of CRS. No sub-protections — each is a single control.

| Canonical name | Description | CWE |
|---|---|---|
| `request-smuggling` | Reject ambiguous Content-Length / Transfer-Encoding | CWE-444 |
| `crlf-injection` | Reject CR/LF (%0d%0a) in headers, URLs, params | CWE-93 |
| `null-byte-injection` | Reject %00 in URLs, params, headers | CWE-158 |
| `method-override` | Strip X-HTTP-Method-Override headers | — |
| `double-encoding` | Reject multi-encoded payloads | CWE-174 |
| `unicode-normalization` | NFC normalize before CRS evaluation | CWE-176 |
| `path-normalization` | Resolve `../`, `./`, double slashes, encoded variants | CWE-22 |
| `slow-request` | Min data rate + header receive timeout | CWE-400 |
| `http2-continuation-flood` | CONTINUATION frame count/size limits | CVE-2024-24549 |
| `http2-hpack-bomb` | Decompressed header size limit | CWE-400 |
| `http2-stream-limit` | Max concurrent HTTP/2 streams per connection | CWE-400 |

## Request validation protections

Single-level controls, no sub-protections.

| Canonical name | Description | Default | CWE |
|---|---|---|---|
| `max-body-size` | Reject bodies exceeding limit | 10MB | CWE-400 |
| `max-url-length` | Reject URLs exceeding limit | 8192 bytes | CWE-400 |
| `max-header-size` | Reject headers exceeding limit | 16KB | CWE-400 |
| `max-header-count` | Reject requests with too many headers | 100 | CWE-400 |
| `allowed-methods` | Reject unlisted HTTP methods | GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS | — |
| `require-host-header` | Reject requests without Host | — | CWE-20 |
| `require-content-type` | Reject POST/PUT/PATCH without Content-Type | — | CWE-20 |

## Body parsing protections

Controls for structured request body depth and complexity. Single-level, no sub-protections. Only active for content types declared in `accept.content_types` — XML parsers don't run if the route only accepts JSON.

| Canonical name | Description | Default | CWE |
|---|---|---|---|
| `json-depth-limit` | Max nesting depth for JSON bodies | 20 | CWE-400 |
| `json-key-limit` | Max key count in JSON objects | 1000 | CWE-400 |
| `xml-depth-limit` | Max nesting depth for XML bodies | 20 | CWE-400 |
| `xml-entity-expansion` | Max entity expansions (billion laughs / XML bomb) | 100 | CWE-776 |

## Resource protections (anti-DoS for the WAF itself)

Controls that prevent attackers from weaponizing the WAF's own inspection against the process. Single-level, no sub-protections.

| Canonical name | Description | Default | CWE |
|---|---|---|---|
| `max-inspection-size` | Max bytes of non-file body evaluated by CRS rules. Maps to SecRequestBodyNoFilesLimit. Larger bodies are proxied but only the first N bytes are inspected. | 128KB | CWE-400 |
| `max-memory-buffer` | Max bytes of request body held in RAM during inspection. Bodies exceeding this are spooled to a temp file on disk. Maps to SecRequestBodyInMemoryLimit. | 128KB | CWE-400 |
| `decompression-ratio-limit` | Max ratio of uncompressed to compressed body size. Rejects compressed payloads (gzip, deflate) that would expand beyond this ratio. Prevents decompression bombs. | 100:1 | CWE-409 |
| `waf-evaluation-timeout` | Context deadline for CRS rule evaluation per request. If evaluation exceeds this, the goroutine is killed and the request is handled per the route's `onTimeout` policy (block or allow). Prevents ReDoS and pathological regex patterns from pinning CPU. | 50ms | CWE-400 |

## File upload protections

Controls for multipart file uploads. Single-level, configurable per route.

| Canonical name | Description | Default | CWE |
|---|---|---|---|
| `multipart-file-limit` | Max files in a multipart upload | 10 | CWE-400 |
| `multipart-file-size` | Max individual file size | 10MB | CWE-400 |
| `multipart-allowed-types` | Allowed MIME types for uploads (configurable per route) | all | CWE-434 |
| `multipart-double-extension` | Reject filenames with double extensions (shell.php.jpg) | — | CWE-434 |

## OpenAPI contract enforcement protections

Single-level controls activated when an OpenAPI spec is provided for a route.

| Canonical name | Description | ASVS |
|---|---|---|
| `openapi-path` | Reject paths not in spec | 13.1 |
| `openapi-method` | Reject methods not declared for path | 13.1 |
| `openapi-params` | Validate query/path params against declared types | 5.1 |
| `openapi-body` | Validate request body against JSON schema | 5.1 |
| `openapi-content-type` | Reject undeclared Content-Type for operation | 13.1 |

## Security headers — injection

All injected by default. Each can be individually disabled or overridden per route.

| Canonical name | Header | Default |
|---|---|---|
| `header-hsts` | `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` |
| `header-csp` | `Content-Security-Policy` | `default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests` |
| `header-x-frame-options` | `X-Frame-Options` | `DENY` |
| `header-x-content-type-options` | `X-Content-Type-Options` | `nosniff` |
| `header-referrer-policy` | `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `header-x-dns-prefetch` | `X-DNS-Prefetch-Control` | `off` |
| `header-coop` | `Cross-Origin-Opener-Policy` | `same-origin` |
| `header-coep` | `Cross-Origin-Embedder-Policy` | `unsafe-none` |
| `header-corp` | `Cross-Origin-Resource-Policy` | `same-origin` |
| `header-permissions-policy` | `Permissions-Policy` | `accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()` |
| `header-cache-control` | `Cache-Control` | `no-store, no-cache, must-revalidate, max-age=0` |

## Security headers — stripping

All stripped by default.

| Canonical name | Header stripped |
|---|---|
| `strip-server` | `Server` |
| `strip-x-powered-by` | `X-Powered-By` |
| `strip-aspnet-version` | `X-AspNet-Version`, `X-AspNetMvc-Version` |
| `strip-generator` | `X-Generator` |
| `strip-drupal` | `X-Drupal-Dynamic-Cache`, `X-Drupal-Cache` |
| `strip-varnish` | `X-Varnish` |
| `strip-via` | `Via` |
| `strip-runtime` | `X-Runtime` |
| `strip-debug` | `X-Debug-Token`, `X-Debug-Token-Link` |
| `strip-backend-server` | `X-Backend-Server` |
| `strip-version` | `X-Version` |

## Response inspection (tier 2, opt-in)

Disabled by default due to latency impact (response buffering). Enable per route.

| Canonical name | Description | ASVS | CWE |
|---|---|---|---|
| `response-open-redirect` | Validate Location header on 3xx against allowed domains | 5.1 | CWE-601 |
| `response-openapi` | Response body against OpenAPI response schema | 13.1 | — |

## Deprecated headers — NOT injected

| Header | Reason |
|---|---|
| `X-XSS-Protection` | Removed from browsers. Can introduce XSS. CSP replaces it. |
| `Expect-CT` | CT enforced by default in all browsers. |
| `Public-Key-Pins` | High self-DoS risk. Replaced by CT + HSTS. |