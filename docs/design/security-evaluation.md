# Security evaluation

> **When to read**: adding or tuning a rule, bumping CRS, reviewing nightly security artifacts, or changing the curated PL2/PL3 set. **Not needed for**: routine protection work (use `testing.md` + `protections.md`).

Barbacana runs CRS at paranoia level 1 with an anomaly threshold of 5. Neither is user-configurable. On top of that baseline Barbacana force-enables a curated set of PL2/PL3 rules whose patterns have distinctive attack indicators (CRLF prefixes, quoted SQL fragments, specific Node.js/Perl syntax) with no legitimate-HTTP overlap. This document describes how we measure the resulting true-positive / true-negative balance continuously, and how the curated set is maintained across CRS bumps.

## Curated rule mechanism

The curated set is the single source of truth at `internal/protections/crs/curated/curated.go` (`Rules`), each entry pairing a CRS rule ID with the canonical Barbacana sub-protection name. The list is consumed by both the extraction tool and the runtime so ID → protection mapping cannot drift between the two.

At `make rules` time, `cmd/tools/rules` downloads (or reuses a cached) pinned CRS tarball, installs rule files into `internal/protections/crs/rules/`, and regenerates `curated-rules.conf` by splicing each curated rule's full `SecRule` block out of the installed CRS source. The tool makes one mechanical rewrite to the extracted text: `tx.inbound_anomaly_score_pl2` and `tx.inbound_anomaly_score_pl3` are replaced with `tx.inbound_anomaly_score_pl1`. This is a direct consequence of the security decision to promote the rule to always-on — if the rule is safe enough to run unconditionally, its score counts at PL1. The rewrite is required because at `BLOCKING_PARANOIA_LEVEL=1` only rule 949060 runs, and it folds just `pl1` into `tx.blocking_inbound_anomaly_score`; pl2/pl3 accumulators would be written but never aggregated, and rule 949110 would never deny. Regex, targets, transforms, actions, and tags are left untouched.

At engine construction (`crs.NewEngine`), `SecRuleRemoveById` strips the CRS originals of the curated IDs and then `curated-rules.conf` is loaded in place. Crucially this insertion is ordered: `curated-rules.conf` loads *between* the attack rule files (… REQUEST-944-APPLICATION-ATTACK-SESSION-FIXATION.conf) and `REQUEST-949-BLOCKING-EVALUATION.conf`. Loading later (e.g., after REQUEST-999) would let 949060–949110 aggregate and evaluate the blocking score *before* any curated rule fired in phase 2, and blocking would not trigger even though matches would appear in the audit log.

Drift protection: `internal/protections/crs/curated_test.go` asserts (a) every ID in `curated.Rules` resolves via `RuleIDToSubProtection`, (b) the generated file contains exactly the same IDs, and (c) no `inbound_anomaly_score_pl2/3/…` accumulator survived the rewrite. Additionally, `TestCuratedRuleFiresSMTPInjection` is the end-to-end proof: a payload matching rule 932300 must produce a blocking decision, catching any future regression in loading order, score rewrite, or paranoia-level handling.

A CRS bump that renames or removes a curated rule fails `cmd/tools/rules` with an error naming the missing ID, before the Go tests run.

Changing the curated set: edit `internal/protections/crs/curated/curated.go` (Rules), run `make rules` to regenerate `curated-rules.conf`, and commit the regenerated file alongside the code change.

### Rules considered and excluded

**942200 (`sql-injection-comment`, PL2)** — excluded. The rule's regex includes a branch `,[^\)]*?["'` (...) `]["'` (...) `]` that matches a comma followed by any quoted string. Under organic JSON traffic, `{"a": 1, "b": 2}` contains `, "b":` and is flagged. The rule was initially curated because its *comment-detection* branches (`select…from`, `;`, `--`, `/*`) are high-signal, but CRS folds the noisy branch into the same rule ID. Before the PL1 blocking fix this rule was dormant so the false positive never surfaced in tests. A future revisit could promote only the tight branches by writing a Barbacana-authored rule, but copying CRS's 942200 verbatim is unsafe for PL1.

**932236 (`rce-unix-command`, PL2)** — excluded. Fires on natural English containing common-word unix commands (`echo`, `curl`, `exec`, `bash`, `nc`, `java`) followed by any space-separated token. In the gotestwaf false-positive `texts` corpus this rule alone accounted for 14 of 15 new blocks, collapsing TN from 90.78% to 80.14% when added. 932220 and 932231 in the same family use tighter patterns (shell-metacharacter prefixes, backtick/parenthesis context) and are kept.

**942521 (`sql-injection-auth-bypass`, PL3)** — excluded. Matches an apostrophe-or-digit shorthand (`D'or 1st`) that appears in product names and loanword English. Single FP × three placeholders (URL param, HTML form, multipart) in gotestwaf's clean corpus.

## Two evaluation suites

Nightly `security-scan` workflow (`.github/workflows/security.yml`) runs both:

| Suite | What it measures | Artifact |
|---|---|---|
| **go-ftw** (CRS regression) | Whether CRS rules still fire on the exact payloads CRS intends — per-rule-ID coverage | `ftw-report.txt` + `ftw-summary.txt` |
| **gotestwaf** (attack simulation) | True-positive block rate and true-negative pass rate across OWASP categories | `default.{pdf,json}` |

Neither gates PRs. They exist to produce a report; regressions are reviewed in the artifact, not enforced by CI.

## Running locally

```bash
make rules                # fetches CRS rules + FTW test corpus + regenerates curated-rules.conf
make tools-security       # installs pinned go-ftw and gotestwaf into ./bin/
make test-ftw             # ~8 s;  report → tests/ftw/reports/
make test-gotestwaf       # ~2 min; reports → tests/gotestwaf/reports/
```

Scanner versions are pinned in `versions.mk` (`GO_FTW_VERSION`, `GOTESTWAF_VERSION`). Configs used by each suite live under `tests/ftw/` and `tests/gotestwaf/`.

## The FTW suite

`go-ftw` is CRS's own regression harness. It replays every CRS test YAML against a target WAF and asserts that the expected rules trigger. Barbacana runs it in **cloud mode** (`--cloud`): pass/fail is determined by HTTP status only, because Barbacana's audit log is not a SecAuditLog drop-in (it intentionally wraps CRS rule IDs in the canonical-protection-name vocabulary — see `protections.md`).

A handful of tests expect behaviors Barbacana's normalization intentionally rewrites (e.g. `920100-4/5/8` around URI encoding). These show as fails in the report but do not indicate a CRS regression — they reflect the design choice in `docs/design/architecture.md` around request normalization.

## The gotestwaf run

`gotestwaf` fires ~800 attack payloads and ~140 benign payloads across OWASP categories (SQLi, XSS, RCE, SSTI, XXE, LDAP injection, NoSQL, SSRF, path traversal, etc.) plus API surfaces (REST, SOAP, GraphQL, gRPC). The output is two percentages:

- **True-positive** (attack-block): fraction of attacks blocked.
- **True-negative** (clean-pass): fraction of benign payloads allowed through.

Because paranoia level and anomaly threshold are no longer user-configurable, gotestwaf runs once against `tests/gotestwaf/config-default.yaml`. The report lands as `tests/gotestwaf/reports/default.pdf` and `default.json`.

### How to read the report

Open `default.pdf` for the category breakdown. For an at-a-glance view:

```bash
jq '{overall: .score, tp: .summary.true_positive_tests.score, tn: .summary.true_negative_tests.score}' \
  tests/gotestwaf/reports/default.json
```

When tuning the curated PL2/PL3 set:
- **Adding** a rule from `curatedRuleIDs` should lift `true_positive` without dropping `true_negative` more than ~1 percentage point. If TN drops further, the rule's pattern is too broad for organic traffic — remove it.
- **API-sec** coverage saturates at ~100% — the curated rules target App-sec gaps.

### Known soft spots

At the time of the pinned CRS version, gotestwaf consistently reports low true-positive rates in these categories regardless of PL:

- **SSTI (server-side template injection)** — CRS does not yet carry broad template-engine-specific payload coverage. Community-maintained rule packs exist but are out of scope for the default ruleset.
- **XSS (reflected, in specific contexts)** — libinjection-based rules at PL1 are biased toward precision. Raising PL picks up some, not all.

These are CRS corpus gaps, not Barbacana integration gaps. They are worth watching across CRS bumps — if a CRS release closes a category, our sweep will show the lift.

## Where the reports live

- **CI:** GitHub Actions run → "Artifacts" section at the bottom of the run page. Retention: 30 days. See `.github/workflows/security.yml`.
- **Local:** `tests/ftw/reports/` and `tests/gotestwaf/reports/` (gitignored). Delete with `rm -rf tests/{ftw,gotestwaf}/reports/` — they regenerate on next run.

## What we do NOT measure

- **Performance / latency** — not in scope here. Load testing is a separate operator concern (`testing.md`).
- **Real-world traffic** — gotestwaf payloads are synthetic. False-positive behavior against production traffic is only discovered by deploying in detect-only mode (`mode: detect_only` per route) and reviewing audit logs.
- **Bypass research** — FTW and gotestwaf both use known, public payloads. They do not replace targeted pen-testing.

## When to update this doc

Update when any of:

- A new suite is added to `security.yml` (nuclei, Juice Shop, etc.).
- The PL/threshold pairing changes in `tests/gotestwaf/config-pl*.yaml`.
- CRS is bumped and the "Known soft spots" section needs to be reverified against the new corpus.
- Pinned scanner versions (`GO_FTW_VERSION`, `GOTESTWAF_VERSION`) change in a way that affects what the suites report.
