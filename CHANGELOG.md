# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-04-23

### Breaking changes

- Merge overlapping sub-protections; split ssrf into cloud-metadata / url-scheme
- Remove access in API to paranoia level (PL) from CSR rules
  - Remove inspection.sensitivity / anomaly_threshold from API
  - CRS PL locked to PL1 + threshold 5
  - Allows adding curated PL2/PL3 rules
  - Collapse gotestwaf PL1-PL4 configs into one; add per-curated-rule blackbox suite

### Added

- New curated rules
  - complement PL1 baseline with CRS PL2/PL3, focus on minimal false positives
  - stored under internal/protections/crs/curated as source of truth for PL2/PL3 promotions
  - fire via SecRuleRemoveById + re-add past skip gates
  - add tests to blackbox suite to verify the new curated rules are effective against real attack payloads
- Replace scripts/fetch-crs.sh with cmd/tools/rules (Go stdlib, offline-resilient)

## [0.1.0] - 2026-04-21

### Breaking changes

The CLI has been collapsed from five subcommands to a single flag-driven entry point that matches the conventions of ko-built images and nginx-style daemons. Bare invocation starts the WAF server; auxiliary modes are selected with mutually exclusive flags.

Migration:

| Old | New |
|---|---|
| `barbacana serve [--config <cfg>]` | `barbacana [--config <cfg>]` |
| `barbacana validate <cfg>` | `barbacana --config <cfg> --validate` |
| `barbacana debug render-config <cfg>` | `barbacana --config <cfg> --render-config` |
| `barbacana version` | `barbacana --version` |
| `barbacana defaults` | Removed. The protection catalog is published on the documentation site (generated directly from `internal/protections/catalog.go`). |

Notes:

- `--config` defaults to `/etc/barbacana/waf.yaml` and is shared by every mode.
- `--validate`, `--render-config`, and `--version` are mutually exclusive. Supplying more than one exits 2 with an error.
- Container images no longer need a `command: ["serve", ...]` override — the default ENTRYPOINT starts the server.

[Unreleased]: https://github.com/barbacana-waf/barbacana/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/barbacana-waf/barbacana/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/barbacana-waf/barbacana/releases/tag/v0.1.0
