# CRS rule mapping (internal)

> Internal reference. Maps sub-protection canonical names to OWASP CRS v4 rule IDs.
> Not user-facing — consumers see only canonical names.

CRS version: v4.25.0

Source of truth: rule files under `internal/protections/crs/rules/`. Every in-scope rule ID is accounted for exactly once in this document (see "Coverage audit" at the end). Rule IDs MUST NOT leak into user-facing surfaces (config, CLI output, metrics labels, audit logs, error messages).

## Curated PL2/PL3 rules

Barbacana runs CRS at paranoia level 1 but force-enables a small set of PL2/PL3 rules that were individually evaluated for low false-positive risk. The list is the single source of truth in `internal/protections/crs/curated/curated.go` (`Rules`), pairing each rule ID with its canonical Barbacana sub-protection name. `cmd/tools/rules` copies each rule body from its source CRS file into `internal/protections/crs/rules/curated-rules.conf`, loaded between the attack rule files and `REQUEST-949-BLOCKING-EVALUATION.conf` so curated matches are aggregated into the blocking score in the same phase 2 pass. The CRS originals are stripped with `SecRuleRemoveById` at engine construction so the IDs remain unique — audit-log entries continue to report the same CRS rule IDs that SIEM tooling expects. `tx.inbound_anomaly_score_pl2`/`pl3` setvars in curated rule bodies are rewritten to `pl1` so scores count at the configured paranoia level. See `docs/design/security-evaluation.md` for rationale. Curated rule IDs are marked **(curated)** in the sub-protection tables below.

## Always-enabled orchestration rules (not user-controllable)

These rules do not detect attacks. They initialise CRS state, skip rules based on paranoia level, evaluate anomaly scores, emit blocking decisions, and correlate inbound/outbound events. They are always loaded and are NEVER exposed as sub-protections.

| CRS range | File | Purpose |
|---|---|---|
| 901xxx | `REQUEST-901-INITIALIZATION.conf` | CRS variable initialisation, default thresholds, engine configuration |
| 905xxx | `REQUEST-905-COMMON-EXCEPTIONS.conf` | Known-good-client exceptions applied before rules run |
| 911xxx | `REQUEST-911-METHOD-ENFORCEMENT.conf` | Phase routing for method policy (actual method policy lives in native `allowed-methods`) |
| 949xxx | `REQUEST-949-BLOCKING-EVALUATION.conf` | Inbound anomaly score evaluation and blocking decision |
| 959xxx | `RESPONSE-959-BLOCKING-EVALUATION.conf` | Outbound anomaly score evaluation and blocking decision |
| 980xxx | `RESPONSE-980-CORRELATION.conf` | Correlates inbound and outbound events for audit |
| 999xxx | `REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf` | Post-rule exceptions hook |

In addition, every per-category rule file contains paranoia-level skip markers with IDs `NNN011`, `NNN012`, `NNN013`, `NNN014`, `NNN015`, `NNN016`, `NNN017`, `NNN018` (and for response data-leakage files: `NNN010`, `NNN021`). These `SecRule` statements inspect `TX:DETECTION_PARANOIA_LEVEL` and `skipAfter` the entire block when the active paranoia level is below the rule's tier. They are orchestration, not attack signatures, and are always loaded alongside their category. They are listed here rather than under any sub-protection.

| Marker IDs (per file) | Role |
|---|---|
| `NNN011`, `NNN012` | Paranoia level 1 (PL1) skip guards for phases 1 and 2 |
| `NNN013`, `NNN014` | Paranoia level 2 (PL2) skip guards for phases 1 and 2 |
| `NNN015`, `NNN016` | Paranoia level 3 (PL3) skip guards for phases 1 and 2 |
| `NNN017`, `NNN018` | Paranoia level 4 (PL4) skip guards for phases 1 and 2 |
| `950010`, `951010`, `952010`, `953010`, `954010`, `955010`, `956010` | Content-encoding gate: skips response inspection when body is compressed with an unsupported encoding |
| `941010` | XSS REQUEST_FILENAME exclusion setup (disables XSS rules against paths tagged `xss-perf-disable`) |
| `950021` | Response phase dispatch helper |

Concretely, the following rule IDs are always-on orchestration and are **not** mapped to any user-facing sub-protection:

- 913: 913011, 913012, 913013, 913014, 913015, 913016, 913017, 913018
- 920: 920011, 920012, 920013, 920014, 920015, 920016, 920017, 920018
- 921: 921011, 921012, 921013, 921014, 921015, 921016, 921017, 921018
- 930: 930011, 930012, 930013, 930014, 930015, 930016, 930017, 930018
- 931: 931011, 931012, 931013, 931014, 931015, 931016, 931017, 931018
- 932: 932011, 932012, 932013, 932014, 932015, 932016, 932017, 932018
- 933: 933011, 933012, 933013, 933014, 933015, 933016, 933017, 933018
- 934: 934011, 934012, 934013, 934014, 934015, 934016, 934017, 934018
- 941: 941010, 941011, 941012, 941013, 941014, 941015, 941016, 941017, 941018
- 942: 942011, 942012, 942013, 942014, 942015, 942016, 942017, 942018
- 943: 943011, 943012, 943013, 943014, 943015, 943016, 943017, 943018
- 944: 944011, 944012, 944013, 944014, 944015, 944016, 944017, 944018
- 950: 950010, 950011, 950012, 950013, 950014, 950015, 950016, 950017, 950018, 950021
- 951: 951010, 951011, 951012, 951013, 951014, 951015, 951016, 951017, 951018, 951100
- 952: 952010, 952011, 952012, 952013, 952014, 952015, 952016, 952017, 952018
- 953: 953010, 953011, 953012, 953013, 953014, 953015, 953016, 953017, 953018
- 954: 954010, 954011, 954012, 954013, 954014, 954015, 954016, 954017, 954018
- 955: 955010, 955011, 955012, 955013, 955014, 955015, 955016, 955017, 955018
- 956: 956010, 956011, 956012, 956013, 956014, 956015, 956016, 956017, 956018
- 980: 980011, 980012, 980013, 980014, 980015, 980016, 980017, 980018, 980041, 980042, 980043, 980044, 980045, 980046, 980047, 980048, 980049, 980050, 980051, 980099, 980170

`REQUEST-922-MULTIPART-ATTACK.conf` does not contain paranoia-level markers in the canonical `NNN011-NNN018` form; its setup rules are folded into the multipart-attack sub-protections below.

`951100` is a multi-engine SQL-error macro: it inspects the response body against `sql-errors.data` and `skipAfter:END-SQL-ERROR-MATCH-PL1` when nothing matches. It gates rules 951110–951260 and is treated as orchestration for the `data-leakage-sql` category.

Each of these rules uses `pass` and either `nolog` or `skipAfter:` — they never set `block` or increment the anomaly score.

---

## `scanner-detection` (CRS 913xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `scanner-detection-user-agent` | 913100 |

## `protocol-enforcement` (CRS 920xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `protocol-enforcement-request-line` | 920100 |
| `protocol-enforcement-multipart-bypass` | 920120, 920121 |
| `protocol-enforcement-content-length` | 920160 |
| `protocol-enforcement-get-head-body` | 920170, 920171 |
| `protocol-enforcement-post-content-length` | 920180 |
| `protocol-enforcement-ambiguous-length` | 920181 |
| `protocol-enforcement-range` | 920190, 920200, 920201, 920202, 920660 |
| `protocol-enforcement-connection-header` | 920210 |
| `protocol-enforcement-url-encoding` | 920230, 920240, 920460 |
| `protocol-enforcement-utf8-abuse` | 920250, 920260, 920540 |
| `protocol-enforcement-null-byte` | 920270 |
| `protocol-enforcement-invalid-chars` | 920271, 920272, 920273, 920274, 920275 |
| `protocol-enforcement-host-header` | 920280, 920290, 920350 |
| `protocol-enforcement-accept-header` | 920300, 920310, 920311, 920600 |
| `protocol-enforcement-user-agent-header` | 920320, 920330 |
| `protocol-enforcement-content-type-header` | 920340, 920470, 920480, 920530, 920620, 920640 |
| `protocol-enforcement-argument-limits` | 920360, 920370, 920380, 920390 |
| `protocol-enforcement-upload-size` | 920400, 920410 |
| `protocol-enforcement-content-type-policy` | 920420 |
| `protocol-enforcement-http-version` | 920430 |
| `protocol-enforcement-file-extension` | 920440 |
| `protocol-enforcement-restricted-header` | 920450, 920451, 920490, 920510 |
| `protocol-enforcement-backup-file-access` | 920500 |
| `protocol-enforcement-accept-encoding` | 920520, 920521 |
| `protocol-enforcement-reqbody-processor` | 920539 |
| `protocol-enforcement-raw-uri-fragment` | 920610 |
| `protocol-enforcement-method-override` | 920650 |

## `protocol-attack` (CRS 921xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `protocol-attack-smuggling` | 921110 |
| `protocol-attack-response-splitting` | 921120, 921130 |
| `protocol-attack-header-injection` | 921140, 921150, 921151, 921160, 921190 |
| `protocol-attack-ldap-injection` | 921200 |
| `protocol-attack-parameter-pollution` | 921170, 921180, 921210, 921220 |
| `protocol-attack-range-header` | 921230 |
| `protocol-attack-mod-proxy` | 921240 |
| `protocol-attack-legacy-cookie` | 921250 |
| `protocol-attack-dangerous-content-type` | 921421, 921422 |

## `multipart-attack` (CRS 922xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `multipart-attack-global-charset` | 922100 |
| `multipart-attack-content-type` | 922110, 922140, 922150 |
| `multipart-attack-transfer-encoding` | 922120 |
| `multipart-attack-header-chars` | 922130 |

## `local-file-inclusion` (CRS 930xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `lfi-path-traversal` | 930100, 930110 |
| `lfi-system-files` | 930120, 930121 |
| `lfi-restricted-files` | 930130 |
| `lfi-ai-artifacts` | 930140 |

## `remote-file-inclusion` (CRS 931xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `rfi-ip-parameter` | 931100 |
| `rfi-vulnerable-parameter` | 931110 |
| `rfi-trailing-question` | 931120 |
| `rfi-off-domain` | 931130, 931131 |

## `remote-code-execution` (CRS 932xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `rce-unix-command` | 932220 **(curated PL2)**, 932230, 932231 **(curated PL2)**, 932232, 932235, 932236, 932239, 932240, 932250, 932260, 932340, 932350 |
| `rce-unix-shell-expression` | 932130, 932131, 932160, 932161 **(curated PL2)**, 932237, 932238, 932270, 932271 |
| `rce-unix-shell-alias` | 932175 |
| `rce-unix-shell-history` | 932330, 932331 |
| `rce-unix-brace-expansion` | 932280, 932281 |
| `rce-unix-wildcard-bypass` | 932190 |
| `rce-unix-bypass-technique` | 932200, 932205, 932206, 932207 |
| `rce-unix-fork-bomb` | 932390 **(curated PL3)** |
| `rce-windows-command` | 932140, 932370, 932380, 932371 **(curated PL3)** |
| `rce-windows-powershell` | 932120, 932125 |
| `rce-shellshock` | 932170, 932171 |
| `rce-executable-upload` | 932180 |
| `rce-sqlite-shell` | 932210 |
| `rce-mail-protocol-injection` | 932300 **(curated PL2)**, 932301 **(curated PL3)**, 932310 **(curated PL2)**, 932311 **(curated PL3)**, 932320 **(curated PL2)**, 932321 **(curated PL3)** |

## `php-injection` (CRS 933xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `php-open-tag` | 933100, 933190 |
| `php-file-upload` | 933110, 933111, 933220 |
| `php-config-directive` | 933120 |
| `php-variable-abuse` | 933130, 933131, 933135 |
| `php-stream-wrapper` | 933140, 933200 |
| `php-function-high-risk` | 933150, 933160 |
| `php-function-medium-risk` | 933151, 933152, 933153 |
| `php-function-low-value` | 933161 |
| `php-object-injection` | 933170 |
| `php-variable-function-call` | 933180, 933210, 933211 |

## `generic-injection` (CRS 934xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `nodejs-injection` | 934100, 934101 **(curated PL2)** |
| `nodejs-dos` | 934160 |
| `ssrf-cloud-metadata` | 934110 |
| `ssrf-url-scheme` | 934120, 934190 |
| `prototype-pollution` | 934130 |
| `perl-injection` | 934140 **(curated PL2)** |
| `ruby-injection` | 934150 |
| `data-scheme-injection` | 934170 |
| `template-injection` | 934180 |

## `xss` (CRS 941xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `xss-libinjection` | 941100, 941101 |
| `xss-script-tag` | 941110 |
| `xss-event-handler` | 941120 |
| `xss-attribute-injection` | 941130, 941150, 941170 |
| `xss-javascript-uri` | 941140 |
| `xss-html-injection` | 941160, 941320 |
| `xss-denylist-keyword` | 941180, 941181 |
| `xss-ie-filter` | 941190, 941200, 941220, 941230, 941240, 941250, 941260, 941270, 941280, 941290, 941300, 941330, 941340 |
| `xss-javascript-keyword` | 941210, 941370, 941390, 941400 |
| `xss-encoding-evasion` | 941310, 941350 |
| `xss-obfuscation` | 941360 |
| `xss-angularjs-csti` | 941380 |

## `sql-injection` (CRS 942xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `sql-injection-libinjection` | 942100, 942101 |
| `sql-injection-operator` | 942120, 942250, 942251 |
| `sql-injection-boolean` | 942130, 942131 |
| `sql-injection-common-dbnames` | 942140 |
| `sql-injection-function` | 942150, 942151, 942152, 942410 |
| `sql-injection-blind` | 942160, 942170, 942280 |
| `sql-injection-auth-bypass` | 942180 **(curated PL2)**, 942260 **(curated PL2)**, 942340, 942520, 942521, 942522, 942540 |
| `sql-injection-mssql` | 942190, 942240 |
| `sql-injection-integer-overflow` | 942220 |
| `sql-injection-conditional` | 942230, 942300 |
| `sql-injection-chained` | 942210, 942310 |
| `sql-injection-union` | 942270, 942361 |
| `sql-injection-nosql` | 942290 |
| `sql-injection-stored-procedure` | 942320, 942321, 942350 |
| `sql-injection-classic-probe` | 942330, 942370, 942380, 942390, 942400, 942470, 942480, 942490 |
| `sql-injection-concat` | 942360, 942362 |
| `sql-injection-char-anomaly` | 942420, 942421, 942430, 942431, 942432, 942460 |
| `sql-injection-comment` | 942200, 942440, 942500 |
| `sql-injection-hex-encoding` | 942450 **(curated PL2)** |
| `sql-injection-tick-bypass` | 942510 **(curated PL2)**, 942511 **(curated PL3)** |
| `sql-injection-termination` | 942530 **(curated PL2)** |
| `sql-injection-json` | 942550 |
| `sql-injection-scientific-notation` | 942560 |

## `session-fixation` (CRS 943xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `session-fixation-set-cookie-html` | 943100 |
| `session-fixation-sessionid-off-domain-referer` | 943110 |
| `session-fixation-sessionid-no-referer` | 943120 |

## `java-injection` (CRS 944xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `java-class-loading` | 944100, 944130, 944250, 944260 |
| `java-process-spawn` | 944110 |
| `java-deserialization` | 944120, 944200, 944210, 944240 |
| `java-script-upload` | 944140 |
| `java-log4j` | 944150, 944151, 944152 |
| `java-base64-keyword` | 944300 |

## `data-leakage` (CRS 950xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `data-leakage-directory-listing` | 950130 |
| `data-leakage-cgi-source` | 950140 |
| `data-leakage-aspnet-exception` | 950150 |
| `data-leakage-5xx-status` | 950100 |

## `data-leakage-sql` (CRS 951xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `data-leakage-sql-msaccess` | 951110 |
| `data-leakage-sql-oracle` | 951120 |
| `data-leakage-sql-db2` | 951130 |
| `data-leakage-sql-emc` | 951140 |
| `data-leakage-sql-firebird` | 951150 |
| `data-leakage-sql-frontbase` | 951160 |
| `data-leakage-sql-hsqldb` | 951170 |
| `data-leakage-sql-informix` | 951180 |
| `data-leakage-sql-ingres` | 951190 |
| `data-leakage-sql-interbase` | 951200 |
| `data-leakage-sql-maxdb` | 951210 |
| `data-leakage-sql-mssql` | 951220 |
| `data-leakage-sql-mysql` | 951230 |
| `data-leakage-sql-postgres` | 951240 |
| `data-leakage-sql-sqlite` | 951250 |
| `data-leakage-sql-sybase` | 951260 |

## `data-leakage-java` (CRS 952xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `data-leakage-java-error` | 952110 |

## `data-leakage-php` (CRS 953xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `data-leakage-php-info` | 953100, 953101 |
| `data-leakage-php-source` | 953110, 953120 |

## `data-leakage-iis` (CRS 954xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `data-leakage-iis-install-location` | 954100, 954101 |
| `data-leakage-iis-availability` | 954110 |
| `data-leakage-iis-info` | 954120, 954130 |

## `web-shell` (CRS 955xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `web-shell-detection` | 955100, 955110, 955120, 955130, 955140, 955150, 955160, 955170, 955180, 955190, 955200, 955210, 955220, 955230, 955240, 955250, 955260, 955270, 955280, 955290, 955300, 955310, 955320, 955330, 955340, 955350, 955400 |

## `data-leakage-ruby` (CRS 956xxx)

| Sub-protection | CRS rule IDs |
|---|---|
| `data-leakage-ruby` | 956100, 956110 |

---

## Coverage audit

Every rule ID appearing as a `SecRule`/`SecAction` `id:` attribute in the in-scope files below is accounted for. Extraction uses `grep -E '^SecRule|^SecAction' FILE` with backslash-continuation lines joined.

### Per-file totals

| File | Total rule IDs | Sub-protection rules | Orchestration rules |
|---|---:|---:|---:|
| `REQUEST-913-SCANNER-DETECTION.conf` | 9 | 1 | 8 |
| `REQUEST-920-PROTOCOL-ENFORCEMENT.conf` | 68 | 60 | 8 |
| `REQUEST-921-PROTOCOL-ATTACK.conf` | 26 | 18 | 8 |
| `REQUEST-922-MULTIPART-ATTACK.conf` | 6 | 6 | 0 |
| `REQUEST-930-APPLICATION-ATTACK-LFI.conf` | 14 | 6 | 8 |
| `REQUEST-931-APPLICATION-ATTACK-RFI.conf` | 13 | 5 | 8 |
| `REQUEST-932-APPLICATION-ATTACK-RCE.conf` | 55 | 47 | 8 |
| `REQUEST-933-APPLICATION-ATTACK-PHP.conf` | 29 | 21 | 8 |
| `REQUEST-934-APPLICATION-ATTACK-GENERIC.conf` | 19 | 11 | 8 |
| `REQUEST-941-APPLICATION-ATTACK-XSS.conf` | 42 | 33 | 9 |
| `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` | 68 | 60 | 8 |
| `REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf` | 11 | 3 | 8 |
| `REQUEST-944-APPLICATION-ATTACK-JAVA.conf` | 22 | 14 | 8 |
| `RESPONSE-950-DATA-LEAKAGES.conf` | 14 | 4 | 10 |
| `RESPONSE-951-DATA-LEAKAGES-SQL.conf` | 26 | 16 | 10 |
| `RESPONSE-952-DATA-LEAKAGES-JAVA.conf` | 10 | 1 | 9 |
| `RESPONSE-953-DATA-LEAKAGES-PHP.conf` | 13 | 4 | 9 |
| `RESPONSE-954-DATA-LEAKAGES-IIS.conf` | 14 | 5 | 9 |
| `RESPONSE-955-WEB-SHELLS.conf` | 36 | 27 | 9 |
| `RESPONSE-956-DATA-LEAKAGES-RUBY.conf` | 11 | 2 | 9 |
| **Total** | **506** | **344** | **162** |

### Notes on overlaps and duplications

- **920660** (`Obsolete Request-Range header detected`) is conceptually both a range-header check and a restricted-header check. It is mapped to `protocol-enforcement-range` — its primary semantic — and nowhere else.
- **922140** and **922150** are `pass` setvar helpers that feed 922110's detection. They are grouped under `multipart-attack-content-type` because disabling that sub-protection must also disable its state setup, otherwise the TX variables are populated for no consumer.
- **921170** is analogous: a parameter-counter setvar helper for 921180/210/220, grouped under `protocol-attack-parameter-pollution`.
- **944300** detects base64-encoded suspicious keywords that could be deserialisation indicators. It is filed under `java-base64-keyword` rather than `java-deserialization` to preserve its distinct detection model (base64 pattern vs. raw magic bytes); disabling either is independent.
- **951100** is a `pass` macro that runs `@pmFromFile sql-errors.data` against the response body and `skipAfter:END-SQL-ERROR-MATCH-PL1` when no match is found. It is orchestration for 951110–951260; disabling the `data-leakage-sql` category disables the gate and its guarded rules together.
- **Paranoia-level markers** (`NNN011`–`NNN018` in every attack file, `NNN010` / `NNN021` in response files) are orchestration. They are not mapped to sub-protections. See the "Always-enabled orchestration rules" section above.

### Audit completeness

For each in-scope file, the union of rule IDs listed under that file's sub-protections plus the rule IDs in the "Always-enabled orchestration rules" section equals the file's full rule-ID set, with no duplicates. This invariant is enforced in the Go registry tests (see `internal/protections/crs/registry_test.go` TODO, WBS A2c).
