---
name: barbacana
description: "Routing and reference for working on the Barbacana codebase (Caddy + Coraza + OWASP CRS v4 WAF, in Go). Use before touching protections, the catalog, config schema/parsing, the request pipeline, metrics, tests, build/CI/release, or docs: it says which docs/design/ files to read for the task, which design surfaces must be kept in sync, and where things live in the repo. Project-wide principles and non-negotiable rules are in CLAUDE.md."
---

# Barbacana

Open-source WAF and API security gateway. Built on Caddy + Coraza + OWASP CRS v4. Written in Go. Ships as a single container image with all rules embedded.

The principles that always apply live in `CLAUDE.md`; their full rationale is in `docs/design/principles.md`.

## Reference routing

| Task | Load these docs |
|------|----------------|
| Adding or modifying a protection | `internal/protections/catalog.go` + `docs/design/protections-crs-mapping.md` + `docs/design/conventions.md` |
| Changing config schema or parsing | `docs/design/config-schema.md` + `docs/design/conventions.md` |
| Working on the request pipeline | `docs/design/architecture.md` |
| Writing or modifying tests | `docs/design/testing.md` + `docs/design/architecture.md` |
| Build, Docker, CI, release changes | `docs/design/build.md` |
| Adding a metric | `docs/design/conventions.md` + `docs/design/architecture.md` |
| New feature design or scope question | `docs/design/features.md` + `docs/design/principles.md` |
| Understanding what protections exist (user-facing) | `barbacana --catalog` (or read `internal/protections/catalog_data_*.go`) |
| Mapping protections to CRS rule IDs (implementation) | `internal/protections/catalog.go` (each leaf's `RuleIDs`) + `docs/design/protections-crs-mapping.md` |
| Adding or modifying black-box tests | `docs/design/blackbox-tests.md` + `barbacana --catalog` |
| Working on nightly security scans (go-ftw, gotestwaf) or PL sweep | `docs/design/security-evaluation.md` |
| Documentation site structure, content, or tooling | `docs/design/documentation.md` |
| Release, packaging, versioning | `docs/design/deliverables.md` |

**Docs marked as TODO are not yet written. Write them before implementing that area.**

## Keep the canonical design surfaces in sync

The single source of truth for Barbacana's public contract is the catalog
in code plus three design docs. They are consumed by the end-user
documentation site and by every downstream task (validation, tests, metrics
labels, audit log fields). Any code change that touches the pipeline,
config schema, protection catalog, or CRS mapping **must** update the
corresponding surface in the same PR — never defer it. Drift here silently
poisons the docs site and every future session that routes through the
reference table above.

- **`internal/protections/catalog.go` + `catalog_data_*.go`** — canonical
  for protections. Edit here when a leaf is added, renamed, removed, or
  has its CWE / Rule IDs / Default / Status / WhatItDoes /
  WhyDisable / WhyEnable changed. The user-facing reference is rendered
  on demand by `barbacana --catalog`; there is no separate
  `protections.md` to keep in sync. `TestCatalogIntegrity` and
  `TestCatalogCRSMappingCrossReference` enforce structural invariants;
  `TestNativeLeavesHaveCode` and `TestCRSLeavesHaveRules` fail when a
  leaf has nothing behind it (known gaps go in `knownGaps` in
  `catalog_backing_test.go`, with a matching label in `WhatItDoes`). See
  `docs/design/testing.md` §"Docs and catalog sync tests".
- **`docs/design/architecture.md`** — update when the request pipeline
  order, middleware chain, module boundaries, metrics, audit log fields,
  reload semantics, or error-response behaviour changes.
- **`docs/design/config-schema.md`** — update when any YAML key, default
  value, validation rule, deployment mode, or route/global field is added,
  renamed, removed, or changed. Include the Go struct snippet and the
  field-reference table rows.
- **`docs/design/protections-crs-mapping.md`** — update when the CRS
  pinned version in `versions.mk` changes or when the curated PL2/PL3 set
  changes. Per-leaf rule mappings live in the catalog; this doc covers
  the orchestration / curated / coverage-audit surface.

When finishing a task that touches any of these areas, explicitly check
each of these four surfaces against the change before declaring the task
complete.

## Repo structure

```
barbacana/
├── main.go                  # Single root Go file, entry point only
├── go.mod
├── go.sum
├── Makefile
├── versions.mk              # Pinned versions (CRS, ko, cosign, etc.)
├── LICENSE
├── README.md
├── CLAUDE.md
├── .ko.yaml                 # ko build configuration
├── .claude/
│   ├── agents/              # Project subagents (code-reviewer, security-reviewer, e2e-test-writer)
│   └── skills/
│       └── barbacana/
│           └── SKILL.md     # This file
├── .planning/
│   └── wbs.md               # Work breakdown structure (delete when MVP complete)
├── .github/
│   ├── workflows/           # CI, release, and security workflows
│   └── actions/             # Composite actions (e.g. load-versions)
├── docs/
│   ├── DEVELOPER.md         # Developer onboarding / local workflow
│   ├── RELEASING.md         # Release process
│   └── design/              # Design docs
│       ├── principles.md
│       ├── features.md
│       ├── protections-crs-mapping.md # Internal: orchestration rules, curated PL2/PL3, coverage audit
│       ├── deliverables.md
│       ├── architecture.md
│       ├── conventions.md
│       ├── config-schema.md
│       ├── testing.md
│       ├── blackbox-tests.md
│       ├── documentation.md           # Documentation site strategy
│       └── build.md
├── internal/                 # All Go packages (not importable by external code)
│   ├── config/              # YAML parsing, validation, defaults
│   ├── pipeline/            # Request processing pipeline orchestration
│   ├── protections/         # One package per protection category
│   │   ├── protection.go   # Protection interface (shared by all categories)
│   │   ├── registry.go     # Protection registry (explicit registration from main.go)
│   │   ├── catalog.go      # Canonical name catalog / hierarchy
│   │   ├── response.go     # Shared response types
│   │   ├── crs/            # Coraza/CRS integration + embedded rules
│   │   ├── protocol/       # Protocol hardening (smuggling, CRLF, null byte, etc.)
│   │   ├── headers/        # Security header injection and stripping
│   │   ├── openapi/        # OpenAPI spec validation
│   │   └── request/        # Request validation (size limits, methods, body parsing, file uploads)
│   ├── metrics/             # Prometheus metric registration and collection
│   ├── audit/               # Structured audit log emission
│   ├── health/              # Health and readiness endpoints
│   └── version/             # Build-time version info (ldflags target)
├── cmd/                      # Flag-driven CLI entry (--config, --validate, --render-config, --version)
├── scripts/                  # Miscellaneous helper scripts
├── cmd/tools/rules/          # Go tool: CRS fetch + curated-rules.conf regeneration
├── rules/                    # CRS rules fetched at build time (.gitignored except CRS_SHA256)
├── configs/                  # Example configurations (example.yaml)
├── tests/
│   ├── blackbox/            # Hurl-based functional test suite
│   │   ├── runner_test.go
│   │   ├── upstream/
│   │   └── scenarios/
│   └── e2e/                 # Container-based end-to-end tests (compose.yaml + hurl)
└── deploy/
    └── helm/                # Helm chart
```

## Key conventions (quick reference)

- **Error handling**: wrap with `fmt.Errorf("context: %w", err)`. No sentinel errors.
- **Logging**: `log/slog` only. Structured JSON. No other logging libraries.
- **Context**: pass `context.Context` as first argument everywhere.
- **Protection registration**: every protection implements the `Protection` interface and self-registers.
- **Protection hierarchy**: catalog is a three-level tree (L1 family → L2 bucket → leaf). All three IDs are valid in `disable` and `enable`; resolution uses more-specific-wins, route beats global on ties.
- **Metrics**: use `prometheus/client_golang`. Register in `internal/metrics/`. Labels match canonical protection names (sub-protection level).
- **Tests**: table-driven, in `_test.go` files alongside code. Integration tests in `internal/pipeline/integration_test.go`.
- **No `init()` functions** — explicit registration in `main.go`.
- **Build**: ko-based, no Dockerfile, no xcaddy. See `docs/design/build.md`.
- **Deprecation**: `Since` and `Deprecated` annotations in source code. Deprecated features log a warning at startup and work for at least one major version.