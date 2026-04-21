# Documentation

> **When to read**: planning documentation work, adding a new section to the docs site, changing the docs tooling, deciding what content goes where, or syncing docs with a new release. **Not needed for**: writing Go code (use `conventions.md`), understanding the pipeline (use `architecture.md`).

## Two-repo model

| Repo | Purpose | Audience |
|---|---|---|
| `barbacana-waf/barbacana` | Source code + design docs. Source of truth. | AI assistants, contributors, maintainers |
| `barbacana-waf/barbacana-docs` | User-facing documentation site. Derived from the source repo. | Users: developers, hobbyists, operators, security experts |

The source repo's `docs/design/` directory contains implementation decisions, architectural guidelines, and internal references. These are written for contributors and AI assistants — they reflect what is implemented and must be followed while coding.

The docs repo contains user-facing content — quickstart guides, configuration tutorials, reference pages, and security assessments. This content is written for people who use Barbacana but never read the source code.

The docs repo is **not** a copy of the design docs. It is a separate body of writing that references the source repo as authority. When the config schema changes in the source repo, the docs repo must be updated to match.

## Sync process

Manual sync. No cross-repo CI triggers, no git submodules.

Before each release, the maintainer reviews changes to public API surfaces in the source repo (config keys, protection names, CLI commands, metrics, audit log fields) and updates the docs repo accordingly. The release checklist in `build.md` includes a step for this.

Some reference pages are generated from source repo data (see below). These are regenerated as part of the release process.

## Generated vs hand-written content

| Content | Source | Method |
|---|---|---|
| Config schema reference | `docs/design/config-schema.md` + Go types in `internal/config/types.go` | Generated — script reads the types and defaults, produces a reference page |
| Protection catalog | `docs/design/protections.md` + `internal/protections/catalog.go` | Generated — script reads the catalog, produces a reference page with CWE, Since version |
| CLI reference | `cmd/*.go` | Generated — script reads the flag set help text, produces a reference page. TODO: the generator assumes subcommands; update it to parse the new flag-driven surface (`--validate`, `--render-config`, `--version`, `--config`) and regenerate the page. |
| Everything else | Written by hand in the docs repo | Quickstart, tutorials, concepts, security deep-dives, operations guides |

The generated pages use the `Since` and `Deprecated` annotations from the source code to render version badges automatically.

## Version metadata

Version lifecycle metadata lives in the source repo, not the docs repo:

```go
// In catalog.go
reg.Add(Protection{
    Name:     "sql-injection-auth",
    Category: "sql-injection",
    CWE:      "CWE-89",
    Since:    "v0.1.0",
})
```

```go
// In types.go — deprecation example
type InspectionCfg struct {
    Sensitivity int `yaml:"sensitivity"` // Since: v0.1.0
}
```

When a feature is deprecated:
1. The source code annotation is updated with `Deprecated: vX.Y.Z` and a pointer to the replacement.
2. The runtime logs a warning at startup if the deprecated feature is used.
3. The deprecated feature continues to function for at least one major version (principle 19).
4. The generated docs page shows a deprecation badge with the version and replacement.
5. The feature is removed no earlier than the next major version, with a note in the CHANGELOG.

## Versioned documentation

**For v0.x**: latest only. One version of the docs site, always matching the latest release. Users on older versions check the CHANGELOG.

**Starting at v1.0.0**: one set of docs per major version. When v2.0.0 ships, v1.x docs remain accessible. MkDocs Material supports this via `mike`.

## Tooling

**MkDocs Material** for the docs site. Deployed to `barbacana.dev`.

Reasons:
- Best mobile experience of the major docs generators
- Built-in search, admonitions (warning boxes for deprecated features), content tabs
- Version selector via `mike` when versioned docs are needed
- Simple Markdown authoring — no React, no Hugo templating
- Aligns with principle 18 (UX over DX): the reader experience matters more than the authoring framework

## Audiences

Four audiences, each with different needs. The information architecture ensures each audience finds what they need without wading through content meant for others.

| Audience | Needs | Does not need |
|---|---|---|
| Web app / API developer | Quickstart, config examples, "how do I disable this false positive" | CRS internals, CWE mappings, anomaly scoring theory |
| Homelab hobbyist | Docker run command, simple config, "just make it work" | OpenAPI validation, sensitivity tuning, SIEM integration |
| Cluster operator | Helm values, health/metrics endpoints, resource requirements, upgrade path | Protection details, config syntax |
| Security expert | Protection catalog with CWE/ASVS, detection coverage, audit log format, sensitivity levels, what's NOT covered | "What is a WAF" explanations |

## Information architecture

Content is organized by task, not by audience. The structure is ordered from simple to deep — a user reads top-to-bottom and stops when they have enough.

```
Getting Started
  ├── What is Barbacana
  ├── Quickstart (3-line config → running WAF)
  └── Installation (binary, container, Helm)

Configuration
  ├── Routes and matching
  ├── Accept and content types
  ├── Path rewrites
  ├── Disabling protections
  ├── Detect-only mode
  ├── OpenAPI validation
  ├── CORS
  ├── Security headers
  └── File uploads

Reference (generated)
  ├── Config schema — every field, type, default, since version
  ├── Protection catalog — every protection, CWE, since version
  ├── CLI commands
  ├── Metrics
  └── Audit log format

Security
  ├── Detection coverage and limitations
  ├── Protection details and CWE mappings
  ├── Sensitivity levels explained
  ├── What Barbacana does NOT protect against
  └── OWASP Top 10 mapping

Operations
  ├── Deployment patterns (standalone, behind LB, Kubernetes)
  ├── Auto-TLS with Let's Encrypt
  ├── Health and readiness
  ├── Monitoring and alerting
  ├── Upgrading
  └── Troubleshooting
```

### Design principles for content

- **Getting Started** assumes zero security knowledge. A developer who has never heard of CRS, WAF, or OWASP can follow it end-to-end.
- **Configuration** explains what each field does and why you'd change it. Examples show real scenarios (API gateway, file upload service, legacy app with exceptions). No reference to CRS internals.
- **Reference** is generated and exhaustive. Every config key, every protection, every metric. Version badges show when things were introduced or deprecated. This section is for looking things up, not for reading cover-to-cover.
- **Security** is for assessment. A security team evaluating Barbacana reads this section to understand what's covered, what's not, and how to map protections to their compliance requirements. CWE identifiers, ASVS references, and detection limitations are documented here.
- **Operations** is for the person running Barbacana in production. Deployment patterns, monitoring setup, upgrade procedures, and troubleshooting.

## Content guidelines

- Lead with the answer, not the context. "Add `disable: [sql-injection-auth]` to your route" before explaining why.
- Show the config, then explain it. Code first, prose second.
- One concept per page. If a page covers routes, rewrites, and CORS, split it.
- Use admonitions for important callouts: `!!! warning` for deprecated features, `!!! danger` for security implications, `!!! tip` for shortcuts.
- Never reference CRS rule IDs, SecLang syntax, or Caddy JSON in user-facing pages. The Security section may reference CRS rule groups by name (e.g., "REQUEST-942 SQL Injection rules") but never by rule ID.
- Every config example must be valid YAML that Barbacana accepts. Test examples as part of the release process.