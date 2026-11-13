# CLAUDE.md

Barbacana is an open-source WAF and API security gateway built on
Caddy + Coraza + OWASP CRS v4. Written in Go.

## Language

Everything in this repository is in English: code, comments, identifiers,
commit messages, PR titles and descriptions, docs, issues, and error and log
messages. The project is open source and meant for outside contributors. When
you reply to a maintainer in another language, keep anything that lands in the
repo in English.

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

Full rationale: `docs/design/principles.md`.

## Before working on an area

Load the `barbacana` skill (`.claude/skills/barbacana/SKILL.md`). It maps each
kind of task to the design docs you must read first and lists the design
surfaces that must be updated in the same PR.

## Non-negotiable rules

- All code is Go. No exceptions.
- Use `log/slog` for logging. No other logging libraries.
- No `init()` functions. Explicit registration in `main.go`.
- Every protection implements the `Protection` interface.
- Protection canonical names in config, metrics, and logs must match 
  the leaf IDs in `internal/protections/catalog.go` exactly. Run 
  `barbacana --catalog` for the rendered reference.
- Never expose Caddy config, Caddyfile syntax, or CRS rule IDs in 
  user-facing interfaces (config, CLI output, error messages, logs).
- Run `go vet ./...` and `go test ./...` before considering a task done.

## Key paths

- `docs/design/` — all design documents
- `internal/` — all Go packages
- `configs/` — example configurations
- `rules/` — embedded CRS rules (go:embed source)
