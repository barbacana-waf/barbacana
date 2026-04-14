# CLAUDE.md

Barbacana is an open-source WAF and API security gateway built on
Caddy + Coraza + OWASP CRS v4. Written in Go.

## Before starting any task

Read `.ai/SKILL.md` — it contains principles, repo structure, 
conventions, and a routing table that tells you which design docs 
to load for each type of task.

## Non-negotiable rules

- All code is Go. No exceptions.
- Use `log/slog` for logging. No other logging libraries.
- No `init()` functions. Explicit registration in `main.go`.
- Every protection implements the `Protection` interface.
- Protection canonical names in config, metrics, and logs must match 
  exactly as listed in `docs/design/protections.md`.
- Never expose Caddy config, Caddyfile syntax, or CRS rule IDs in 
  user-facing interfaces (config, CLI output, error messages, logs).
- Run `go vet ./...` and `go test ./...` before considering a task done.

## Key paths

- `.ai/SKILL.md` — detailed reference and routing table
- `docs/design/` — all design documents
- `internal/` — all Go packages
- `configs/` — example configurations
- `rules/` — embedded CRS rules (go:embed source)