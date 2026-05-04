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

## Per-leaf rule mapping

Per-leaf CRS rule IDs are no longer maintained as a static table here.
The catalog (`internal/protections/catalog.go` plus the
`catalog_data_*.go` files) carries each leaf's `RuleIDs` list as the
single source of truth, and `internal/protections/crs/mapping.go` builds
the rule-ID → leaf-ID map at package init time by walking
`protections.Catalog` and skipping curated IDs (which live in
`internal/protections/crs/curated`).

To inspect the mapping:

- For a human-readable, per-leaf view including CWE and rationale, run
  `barbacana --catalog` (or `barbacana --catalog-leaf <leaf-id>`).
- For the raw rule-ID → leaf-ID map, read `mapping.go` or its derived
  output via `crs.RuleIDToSubProtection(id int)`.

The cross-reference test `TestCatalogCRSMappingCrossReference` in
`internal/protections/crs` enforces four invariants over these sources:
every catalog leaf's RuleIDs resolve, every curated entry has a catalog
home, every `ruleMapping` entry has a catalog home, and curated and
ruleMapping never overlap on the same rule ID.

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
