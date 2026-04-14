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

The full sub-protection enumeration is generated from the CRS v4 rule files in WBS task A2b and documented in `protections-crs-mapping.md`. This file lists categories with representative sub-protections to show the pattern.

## CRS-backed protections

### `sql-injection` — CRS 942xxx

SQL injection detection across all request fields (URL, query params, headers, body).

| Sub-protection | Description | CWE |
|---|---|---|
| `sql-injection-union` | UNION-based SQLi | CWE-89 |
| `sql-injection-blind` | Blind and time-based SQLi (SLEEP, BENCHMARK, WAITFOR) | CWE-89 |
| `sql-injection-error` | Error-based SQLi extraction | CWE-89 |
| `sql-injection-auth` | Authentication bypass (OR 1=1, ' OR ''=') | CWE-89 |
| `sql-injection-function` | SQL function abuse (CONCAT, CHAR, CONV, HEX) | CWE-89 |
| `sql-injection-operator` | SQL operator abuse (BETWEEN, LIKE, HAVING, GROUP BY) | CWE-89 |
| `sql-injection-comment` | Comment-based SQLi (--, #, /**/) | CWE-89 |
| `sql-injection-mysql` | MySQL-specific syntax (@@version, LOAD_FILE, INTO OUTFILE) | CWE-89 |
| `sql-injection-mssql` | MSSQL-specific syntax (xp_cmdshell, EXEC, sp_) | CWE-89 |
| `sql-injection-pgsql` | PostgreSQL-specific syntax (pg_sleep, COPY, lo_) | CWE-89 |
| `sql-injection-oracle` | Oracle-specific syntax (UTL_HTTP, DBMS_) | CWE-89 |
| `sql-injection-sqlite` | SQLite-specific syntax | CWE-89 |
| ... | *Full list generated in A2b from CRS 942xxx rules* | |

ASVS: 1.2.1, 1.2.2

### `xss-reflected` / `xss-stored` — CRS 941xxx

Cross-site scripting detection in request fields.

| Sub-protection | Description | CWE |
|---|---|---|
| `xss-script-tag` | `<script>` tag injection and variants | CWE-79 |
| `xss-event-handler` | Event handler injection (onload, onerror, onclick, etc.) | CWE-79 |
| `xss-javascript-uri` | `javascript:` URI scheme injection | CWE-79 |
| `xss-html-injection` | HTML tag injection (iframe, object, embed, svg) | CWE-79 |
| `xss-attribute-injection` | Attribute-based XSS (style, src, href with data:) | CWE-79 |
| `xss-encoding-evasion` | Encoded XSS evasion (HTML entities, Unicode, base64) | CWE-79 |
| ... | *Full list generated in A2b from CRS 941xxx rules* | |

ASVS: 1.1.1

### `remote-code-execution` — CRS 932xxx

OS command injection and code execution detection.

| Sub-protection | Description | CWE |
|---|---|---|
| `rce-unix-command` | Unix command injection (cat, ls, wget, curl, nc, etc.) | CWE-78 |
| `rce-windows-command` | Windows command injection (cmd.exe, powershell, etc.) | CWE-78 |
| `rce-unix-shell` | Shell metacharacters (backticks, $(), pipes, redirects) | CWE-78 |
| `rce-wildcard-abuse` | Wildcard and glob abuse for command injection | CWE-78 |
| `rce-bash-expansion` | Bash tilde and brace expansion abuse | CWE-78 |
| ... | *Full list generated in A2b from CRS 932xxx rules* | |

ASVS: 1.2.5

### `local-file-inclusion` — CRS 930xxx

Local file inclusion and path traversal in parameters.

| Sub-protection | Description | CWE |
|---|---|---|
| `lfi-path-traversal` | Directory traversal sequences (../, ....//,  etc.) | CWE-22 |
| `lfi-system-files` | Access to known sensitive files (/etc/passwd, web.config, etc.) | CWE-98 |
| `lfi-restricted-extension` | Access to restricted file extensions (.ini, .log, .bak, .sql) | CWE-98 |
| ... | *Full list generated in A2b from CRS 930xxx rules* | |

ASVS: 1.2.7

### `remote-file-inclusion` — CRS 931xxx

Remote file inclusion attempts.

| Sub-protection | Description | CWE |
|---|---|---|
| `rfi-url-parameter` | URL in parameter values (http://, https://, ftp://) | CWE-98 |
| `rfi-ip-parameter` | IP address in parameter values | CWE-98 |
| ... | *Full list generated in A2b from CRS 931xxx rules* | |

ASVS: 1.2.7

### `php-injection` — CRS 933xxx

PHP-specific code injection.

| Sub-protection | Description | CWE |
|---|---|---|
| `php-function-abuse` | Dangerous functions (eval, exec, system, passthru, popen, etc.) | CWE-94 |
| `php-wrapper` | PHP stream wrappers (php://input, php://filter, data://, expect://) | CWE-94 |
| `php-config-directive` | Config manipulation (auto_prepend_file, disable_functions, etc.) | CWE-94 |
| `php-object-injection` | Serialization/deserialization attacks (O:, unserialize) | CWE-502 |
| `php-variable-abuse` | Variable manipulation ($_GET, $_POST, $GLOBALS, extract) | CWE-94 |
| ... | *Full list generated in A2b from CRS 933xxx rules* | |

ASVS: 1.2.5

### `java-injection` — CRS 944xxx

Java-specific injection patterns.

| Sub-protection | Description | CWE |
|---|---|---|
| `java-class-loading` | Java class loading and reflection abuse | CWE-94 |
| `java-ognl` | OGNL expression injection (Struts, etc.) | CWE-917 |
| `java-spel` | Spring Expression Language injection | CWE-917 |
| `java-el` | Unified Expression Language injection (JSP/JSF) | CWE-917 |
| `java-deserialization` | Java deserialization attacks (ObjectInputStream, readObject) | CWE-502 |
| `java-log4j` | Log4Shell and JNDI injection (${jndi:ldap://}) | CWE-917 |
| ... | *Full list generated in A2b from CRS 944xxx rules* | |

ASVS: 1.2.5

### `generic-injection` — CRS 934xxx

Language-agnostic and less-common injection attacks.

| Sub-protection | Description | CWE |
|---|---|---|
| `nodejs-injection` | Node.js code injection (require, child_process, eval) | CWE-94 |
| `template-injection` | Server-side template injection / SSTI (Jinja2, Twig, Freemarker, etc.) | CWE-1336 |
| `ldap-injection` | LDAP query injection | CWE-90 |
| `ssi-injection` | Server-Side Include injection | CWE-97 |
| `el-injection` | Expression language injection (generic) | CWE-917 |
| ... | *Full list generated in A2b from CRS 934xxx rules* | |

ASVS: 1.2.5

### `shell-injection` — CRS 932xxx (subset)

Shell command injection via metacharacters. Overlaps with `remote-code-execution` — implementation may merge or keep separate depending on CRS rule structure.

ASVS: 1.2.5 | CWE: CWE-78

### `session-fixation` — CRS 943xxx

Session fixation attempts.

ASVS: 3.2.1 | CWE: CWE-384

### `scanner-detection` — CRS 913xxx

Known vulnerability scanner signatures and behavioral patterns.

CWE: CWE-200

### `xml-external-entity` — CRS (within 930/934)

XXE attacks in XML request bodies.

ASVS: 1.2.6 | CWE: CWE-611

### `multipart-attack` — CRS 922xxx

Multipart request abuse.

| Sub-protection | Description | CWE |
|---|---|---|
| `multipart-boundary` | Invalid or duplicate multipart boundary manipulation | CWE-20 |
| `multipart-header-injection` | Missing or malformed Content-Disposition in multipart parts | CWE-20 |
| `multipart-file-name` | Malicious file names in multipart uploads | CWE-20 |
| ... | *Full list generated in A2b from CRS 922xxx rules* | |

### `metadata-leakage` — CRS 950xxx

Generic data leakage detection in responses.

ASVS: 7.4.1 | CWE: CWE-200

### `data-leakage-sql` — CRS 951xxx

SQL error messages leaked in response bodies (MySQL, PostgreSQL, MSSQL, Oracle, SQLite error patterns).

CWE: CWE-209

### `data-leakage-java` — CRS 952xxx

Java stack traces, exception details, and framework error messages in responses.

CWE: CWE-209

### `data-leakage-php` — CRS 953xxx

PHP errors, warnings, notices, and stack traces in responses.

CWE: CWE-209

### `data-leakage-iis` — CRS 954xxx

IIS error messages, ASP.NET stack traces, and ADODB error details in responses.

CWE: CWE-209

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
| `parameter-pollution` | Duplicate query param policy (configurable: reject/first/last) | — |
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

Controls for structured request body depth and complexity. Single-level, no sub-protections.

| Canonical name | Description | Default | CWE |
|---|---|---|---|
| `json-depth-limit` | Max nesting depth for JSON bodies | 20 | CWE-400 |
| `json-key-limit` | Max key count in JSON objects | 1000 | CWE-400 |
| `xml-depth-limit` | Max nesting depth for XML bodies | 20 | CWE-400 |
| `xml-entity-expansion` | Max entity expansions (billion laughs / XML bomb) | 100 | CWE-776 |

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