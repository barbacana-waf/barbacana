# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


This release focuses on making Barbacana a more transparent proxy. The upstream now receives requests much closer to what the client actually sent, and a few false positives have been removed.

The new 70 integration tests verify that the proxy preserves HTTP request features, and raised a few bugs that went unnoticed before. This is the main source of the breaking change, but they also make Barbacana more compatible with real-world applications and frameworks.


### Breaking changes

- **Duplicate query-parameter detection is no longer a separate knob.** Barbacana used to ship its own HTTP Parameter Pollution check alongside the equivalent rules in the bundled rule set, and the two could disagree. The built-in check has been removed; detection of the same attacks continues unchanged through the rule set.

  Migration: if your config has a `parameter_pollution:` entry, delete it. Barbacana will otherwise refuse to start.

### Added

- **Proxy-conformance test suite** — 69 new integration tests covering the HTTP behaviours a reverse proxy must preserve: every standard method (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD), common content types (JSON, form-urlencoded, multipart, XML, plain text), 19 status codes from 200 to 503, header round-trips, query-parameter preservation, path handling, chunked transfer encoding, gzip negotiation, and request-body integrity. Each test checks that the upstream receives the exact request the client sent, unmodified. The suite surfaced most of the fixes below.

### Fixed

- **PUT, PATCH, and DELETE were silently blocked.** Barbacana never told its rule engine which HTTP methods the route accepted, so the engine fell back to its own default of GET/HEAD/POST/OPTIONS and rejected every other verb with a 403. Any REST API using standard HTTP methods was broken. The rule engine now receives the route's `accept.methods` list.
- **The proxy stopped silently asking the upstream for gzip-compressed responses.** Go's HTTP client was adding `Accept-Encoding: gzip` to every proxied request regardless of what the client sent, so upstreams that honour compression could return gzipped bodies the client never asked for — and couldn't always decode. The proxy now forwards the client's encoding preferences unchanged.
- **Trailing slashes and other path characters were rewritten on the way to the upstream.** Normalization was changing `/api/users/` to `/api/users`, collapsing `//` to `/`, and turning `\` into `/` before the request was forwarded. Frameworks that distinguish those paths (Django, Rails, strict REST routers) routed to the wrong handler. Normalization now applies only to rule-engine inspection — the original path bytes reach the upstream unchanged. Null-byte and CRLF attacks are still blocked outright.
- **`text/plain` POST bodies (and other uncommon-but-legitimate content types) were blocked unnecessarily.** A content-type rule in the bundled rule set rejected these on routes that didn't explicitly list allowed content types — even when Barbacana's own `accept.content_types` setting was deliberately left open. The duplicate check has been turned off; content-type policy is owned solely by `accept.content_types` per route.

### Notes

- The third-party `gotestwaf` benchmark's `rce-urlparam` score moves from 67% to 33%. This is the loss of an accidental detection, not real coverage: the previous block fired because path normalization was mutating the URL in place and the mutated form coincidentally matched an unrelated regex. With the path-transparency fix above, the bundled rule set's actual (weak) coverage for ASP/VBScript payload families is now what the score reflects. Overall gotestwaf score is essentially unchanged (86.35 → 86.24).


## [0.2.0] - 2026-04-23

### Security

- Bump `github.com/jackc/pgx/v5` v5.9.0 → v5.9.2 (indirect, via caddy → smallstep/nosql) to address GHSA-j88v-2chj-qfwx
- Replace GitHub Release SBOM attachment with a cosign keyless attestation bound to the image digest. Consumers retrieve the SBOM from the registry (`cosign download attestation` or `trivy image --sbom-sources oci`) instead of the Release page. This security mechanism is used to cryptographically prove the identity and integrity of the container image. 
- Replace SBOM from SPDX to CycloneDX format, this format better describes runtime dependencies and is more widely supported by security tools. The attested SBOM allows users to verify the contents of the image and check for known vulnerabilities (CVEs).

### Breaking changes

- Merge overlapping sub-protections; split ssrf into cloud-metadata / url-scheme
- Manage CRS rules independently of paranoia level (PL) — no more wholesale PL1-PL4 enablement
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
