---
name: barbacana
description: "Root skill for the Barbacana project — an open-source WAF and API security gateway built on Caddy + Coraza + OWASP CRS v4, written in Go. Load this skill for any task involving the barbacana codebase. It contains compressed principles, repo structure, coding conventions, and a routing table pointing to detailed design docs in docs/design/."
---

# Barbacana

Open-source WAF and API security gateway. Built on Caddy + Coraza + OWASP CRS v4. Written in Go. Ships as a single container image with all rules embedded.

## Principles (always apply)

1. **Secure by default, explicit opt-out** — every protection is ON. Teams disable what they need via a flat `disable` list.
2. **Stateless** — no Redis, no database, no shared state. Each request evaluated independently.
3. **Path-first config** — the route is the unit of ownership. All controls for a path live in one block.
4. **Flat exception model** — protections have canonical names used in config, metrics, and logs. No nested booleans.
5. **Caddy is wrapped** — users never see Caddyfile or Caddy JSON. YAML compiles to Caddy internals.
6. **CRS is wrapped** — users never see rule IDs or SecLang in config. Human-readable protection names are the interface. Rule IDs appear in audit logs for SIEM correlation.
7. **Five-minute deploy** — pull image, point at upstream, done. No build steps, no rule downloads.
8. **IaC-first** — declarative YAML, Git-friendly, Gateway API integration planned.
9. **Team autonomy** — per-route config from separate files (`routes.d/`). One team, one file, one PR.
10. **Observability from day one** — Prometheus metrics + structured JSON audit logs, always on.
11. **Blocking by default** — the default mode blocks attacks. Detect-only is an opt-in escape hatch per route for tuning.
12. **No latency surprises** — protocol hardening is free. Response inspection is opt-in.
13. **Honest scope** — no IP blocking, no rate limiting, no CAPTCHA, no TLS fingerprinting. Only features that reliably work.
14. **Semver on the public API** — protection names, config keys, metric names, CLI commands.
15. **Gateway API future** — config schema must not conflict with future HTTPRoute + SecurityPolicy CRD mapping.
16. **Single binary, single concern** — reverse proxy with security. Not an IdP, not a UI, not a DDoS appliance.
17. **Go only** — Caddy is Go, Coraza is Go, the project is Go.
18. **Security → UX → DX** — when principles conflict, security wins unconditionally, then user experience, then developer experience.
19. **No breaking changes without deprecation** — deprecated in N, works in N+1, removed earliest in N+2. Always debated first.
20. **Documentation layered from simple to expert** — quickstart works without security expertise. Depth is progressive, never required.

## Reference routing

| Task | Load these docs |
|------|----------------|
| Adding or modifying a protection | `docs/design/protections.md` + `docs/design/protections-crs-mapping.md` + `docs/design/conventions.md` |
| Changing config schema or parsing | `docs/design/config-schema.md` + `docs/design/conventions.md` |
| Working on the request pipeline | `docs/design/architecture.md` |
| Writing or modifying tests | `docs/design/testing.md` + `docs/design/architecture.md` |
| Build, Docker, CI, release changes | `docs/design/build.md` |
| Adding a metric | `docs/design/conventions.md` + `docs/design/architecture.md` |
| New feature design or scope question | `docs/design/features.md` + `docs/design/principles.md` |
| Understanding what protections exist (user-facing) | `docs/design/protections.md` |
| Mapping protections to CRS rule IDs (implementation) | `docs/design/protections-crs-mapping.md` |
| Adding or modifying black-box tests | `docs/design/blackbox-tests.md` + `docs/design/protections.md` |
| Documentation site structure, content, or tooling | `docs/design/documentation.md` |
| Release, packaging, versioning | `docs/design/deliverables.md` |

**Docs marked as TODO are not yet written. Write them before implementing that area.**

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
├── .ai/
│   └── barbacana/
│       └── SKILL.md         # This file
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
│       ├── protections.md             # Public API: canonical names, hierarchy
│       ├── protections-crs-mapping.md # Internal: canonical names → CRS rule IDs
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
├── cmd/                      # CLI subcommands (serve, validate, defaults, debug, version)
├── scripts/                  # Build scripts (fetch-crs.sh, etc.)
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
- **Protection hierarchy**: categories (e.g. `sql-injection`) are shorthand that disable all sub-protections (e.g. `sql-injection-union`, `sql-injection-blind`). Both levels work in the `disable` list.
- **Metrics**: use `prometheus/client_golang`. Register in `internal/metrics/`. Labels match canonical protection names (sub-protection level).
- **Tests**: table-driven, in `_test.go` files alongside code. Integration tests in `internal/pipeline/integration_test.go`.
- **No `init()` functions** — explicit registration in `main.go`.
- **Build**: ko-based, no Dockerfile, no xcaddy. See `docs/design/build.md`.
- **Deprecation**: `Since` and `Deprecated` annotations in source code. Deprecated features log a warning at startup and work for at least one major version.