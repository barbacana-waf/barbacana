# Security evaluation

> **When to read**: adding or tuning a rule category, bumping CRS, reviewing nightly security artifacts, or debating defaults for `inspection.sensitivity` / `inspection.anomaly_threshold`. **Not needed for**: routine protection work (use `testing.md` + `protections.md`).

Barbacana exposes a declarative knob — `inspection.sensitivity` (1–4) — that maps to CRS paranoia level (PL). A paired knob, `inspection.anomaly_threshold`, sets how many anomaly score points accumulate before a request is blocked. The two are not independent: raising sensitivity without raising the threshold produces a WAF that blocks legitimate traffic. This document describes how we measure that tradeoff continuously.

## Two evaluation suites

Nightly `security-scan` workflow (`.github/workflows/security.yml`) runs both:

| Suite | What it measures | Artifact |
|---|---|---|
| **go-ftw** (CRS regression) | Whether CRS rules still fire on the exact payloads CRS intends — per-rule-ID coverage | `ftw-report.txt` + `ftw-summary.txt` |
| **gotestwaf** (attack simulation) | True-positive block rate and true-negative pass rate across OWASP categories | `pl{1..4}.{pdf,json,csv}` + `summary.md` |

Neither gates PRs. They exist to produce a report; regressions are reviewed in the artifact, not enforced by CI.

## Running locally

```bash
make rules                # fetches CRS rules + FTW test corpus
make tools-security       # installs pinned go-ftw and gotestwaf into ./bin/
make test-ftw             # ~8 s;  report → tests/ftw/reports/
make test-gotestwaf       # ~7 min; reports → tests/gotestwaf/reports/
```

Scanner versions are pinned in `versions.mk` (`GO_FTW_VERSION`, `GOTESTWAF_VERSION`). Configs used by each suite live under `tests/ftw/` and `tests/gotestwaf/`.

To run a single PL (faster dev loop):

```bash
GOTESTWAF_VERSION=$(awk -F= '/^GOTESTWAF_VERSION=/{print $2}' versions.mk) \
  PATH=$PWD/bin:$PATH \
  go test -tags=gotestwaf -run=TestGotestWAF/PL2 ./tests/gotestwaf/ -v -count=1
```

## The FTW suite

`go-ftw` is CRS's own regression harness. It replays every CRS test YAML against a target WAF and asserts that the expected rules trigger. Barbacana runs it in **cloud mode** (`--cloud`): pass/fail is determined by HTTP status only, because Barbacana's audit log is not a SecAuditLog drop-in (it intentionally wraps CRS rule IDs in the canonical-protection-name vocabulary — see `protections.md`).

A handful of tests expect behaviors Barbacana's normalization intentionally rewrites (e.g. `920100-4/5/8` around URI encoding). These show as fails in the report but do not indicate a CRS regression — they reflect the design choice in `docs/design/architecture.md` around request normalization.

## The gotestwaf sweep

`gotestwaf` fires ~800 attack payloads and ~140 benign payloads across OWASP categories (SQLi, XSS, RCE, SSTI, XXE, LDAP injection, NoSQL, SSRF, path traversal, etc.) plus API surfaces (REST, SOAP, GraphQL, gRPC). The output is two percentages:

- **True-positive** (attack-block): fraction of attacks blocked.
- **True-negative** (clean-pass): fraction of benign payloads allowed through.

These move in opposite directions as sensitivity rises. A single run at the default sensitivity gives you one point; the sweep runs PL1 through PL4 so the full tradeoff curve is visible.

### PL / threshold pairing

`anomaly_threshold` defaults to `5` in the config schema because that is CRS v4's distributed default. It is only correct at PL1. Each higher PL fires strictly more rules; with the threshold fixed, rule triggers accumulate faster than the threshold can absorb, collapsing the true-negative rate. The sweep therefore pairs each PL with a threshold that matches established CRS tuning guidance:

| PL | `anomaly_threshold` | Rationale |
|---|---|---|
| 1 | 5  | CRS default. Safest starting point. |
| 2 | 7  | Covers the additional PL2 rules' typical score contribution. |
| 3 | 9  | Further accommodation for PL3's broader regex rules. |
| 4 | 12 | Needed for PL4 text/structure rules not to self-trigger on benign input. |

A quick verification from a local run: PL4 with `threshold=5` produced **TN=0%** (every benign request blocked). PL4 with `threshold=12` produced **TN≈56%**. The schema-level pairing is not free; if a user raises sensitivity without raising the threshold, they will see this collapse.

### How to read the summary

Each nightly run produces `tests/gotestwaf/reports/summary.md`, like:

```
| PL  | Anomaly threshold | Overall | Attack-block % | Clean-pass % | App-sec block % | API-sec block % |
|-----|------------------:|--------:|---------------:|-------------:|----------------:|----------------:|
| PL1 | 5                 |   86.20 |          54.83 |        90.78 |           54.01 |          100.00 |
| PL2 | 7                 |   85.54 |          55.72 |        87.23 |           54.92 |          100.00 |
| PL3 | 9                 |   85.26 |          56.02 |        85.82 |           55.22 |          100.00 |
| PL4 | 12                |   78.91 |          60.33 |        56.03 |           59.61 |          100.00 |
```

Interpretation:

- **Overall** is gotestwaf's own weighted score; it heavily favors true-negative. PL1 tends to win "Overall" even when higher PLs catch more attacks.
- **API-sec block %** is almost always 100% — REST/SOAP coverage in CRS is mature and saturates at PL1. No tuning lift there.
- **App-sec block %** is where the tuning conversation lives. Typical PL1→PL4 lift with matched thresholds is ~5–10 points, not ~30. The bulk of the `TP` column movement comes from SSTI, XSS, and NoSQL categories — the per-category breakdown is in the individual PDFs.

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
