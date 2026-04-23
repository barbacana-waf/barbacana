# Verifying a release

Every Barbacana release ships a multi-arch image, a cosign keyless signature
over that image, and a CycloneDX SBOM attested to the same image digest. All
three are stored in `ghcr.io` — there is no Release-page download to fetch.

This page covers the consumer side: signature verification, attestation
verification, SBOM retrieval, CVE scanning, and continuous monitoring. For
the producer side (what CI emits, why it does it that way) see
[docs/RELEASING.md](RELEASING.md) and [docs/design/build.md](design/build.md).

Edge builds at `ghcr.io/barbacana-waf/barbacana-edge` are **not** signed and
**not** attested. Do not run them in production; do not apply the procedures
below to them — they will fail.

## Prerequisites

| Tool | Used for | Install |
|---|---|---|
| [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) ≥ 3.0 | Signature + attestation verification, SBOM download | `brew install cosign` |
| [jq](https://jqlang.org/) | SBOM extraction | `brew install jq` |
| [trivy](https://trivy.dev/) ≥ 0.50 | CVE scanning | `brew install trivy` |
| [grype](https://github.com/anchore/grype) (optional) | Alternative CVE scanner | `brew install grype` |

A clone of the Barbacana repo is **not** required. The Makefile targets
referenced below (`make verify`, `make verify-attestation`) are convenience
wrappers; the underlying `cosign` invocations are documented inline so a
consumer without the repo can copy-paste them.

## 1. Verify the image signature

The signature proves the image at the given reference was produced by the
Barbacana release workflow on a tagged commit. It does not say anything about
what is *inside* the image — that is what the SBOM attestation is for.

From a checkout of [barbacana-waf/barbacana](https://github.com/barbacana-waf/barbacana):

```
make verify IMG=ghcr.io/barbacana-waf/barbacana:vX.Y.Z
```

Without a checkout, the equivalent raw command:

```
cosign verify \
  --certificate-identity-regexp='https://github.com/barbacana-waf/barbacana/\.github/workflows/.+@refs/tags/v.*' \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/barbacana-waf/barbacana:vX.Y.Z
```

The certificate identity regex pins the signature to a workflow file in the
`barbacana-waf/barbacana` repository, fired on a `v*` tag push. The OIDC
issuer pins it to GitHub Actions' token endpoint. Together they prevent a
signature produced by any other repo, workflow, or trigger from passing.

A successful run prints a JSON array of verified signatures and exits 0.

A failure means one of the following:

- The image at that reference is unsigned, or signed by an identity that does
  not match the regex (i.e. not produced by this repo's release workflow).
- The transparency log entry for the signature has been tampered with or
  removed.
- The image reference points to a different digest than the one that was
  signed (e.g. a tag was force-pushed).

In all three cases, treat the image as untrusted.

## 2. Verify the SBOM attestation

The attestation is a cosign-signed in-toto statement carrying a CycloneDX
SBOM as its predicate. Verifying it proves the SBOM came from the same
release workflow that signed the image and is bound to that image's digest.

```
make verify-attestation IMG=ghcr.io/barbacana-waf/barbacana:vX.Y.Z
```

Raw command:

```
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp='https://github.com/barbacana-waf/barbacana/\.github/workflows/.+@refs/tags/v.*' \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/barbacana-waf/barbacana:vX.Y.Z
```

A success prints the verified in-toto envelope to stdout and exits 0. Pipe it
through `jq` if you want to inspect it:

```
make verify-attestation IMG=ghcr.io/barbacana-waf/barbacana:vX.Y.Z 2>/dev/null \
  | jq -r '.payload' | base64 -d | jq '.predicateType,.subject'
```

Failure modes:

- `none of the attestations matched the predicate type: cyclonedx` — the
  image has no CycloneDX SBOM attached. Either the reference is wrong, the
  image was not produced by a release tag, or the attestation has been
  stripped from the registry.
- The certificate-identity check fails — same meaning as in step 1: the
  SBOM was attested by something other than this repo's release workflow.

Both verification steps should pass before you trust the SBOM in the next
step.

## 3. Retrieve the SBOM

For tooling that consumes the SBOM file directly (Dependency-Track, GUAC,
custom scanners), download and extract the CycloneDX predicate:

```
cosign download attestation \
  --predicate-type https://cyclonedx.org/bom \
  ghcr.io/barbacana-waf/barbacana:vX.Y.Z \
  | jq -r '.dsseEnvelope.payload' | base64 -d | jq '.predicate' \
  > barbacana.cdx.json
```

What each stage does:

- `cosign download attestation` fetches the signed in-toto bundle for the
  CycloneDX predicate type from the registry. No network call to Rekor is
  made — this is a registry read.
- `jq -r '.dsseEnvelope.payload'` extracts the base64-encoded DSSE payload
  (the in-toto statement).
- `base64 -d | jq '.predicate'` decodes the statement and unwraps the
  CycloneDX document.

The result is a standalone CycloneDX 1.x JSON document at `barbacana.cdx.json`.

`cosign download attestation` does **not** verify the signature — it only
fetches. Always run step 2 first; only trust an SBOM whose attestation you
have already verified.

## 4. Scan for CVEs

Two equivalent ways. Pick one based on workflow.

**Direct (no manual download)** — trivy fetches the attestation from the
registry itself:

```
trivy image \
  --sbom-sources oci \
  --scanners vuln \
  --severity CRITICAL,HIGH \
  ghcr.io/barbacana-waf/barbacana:vX.Y.Z
```

Best for operators who just want a vuln report against a deployed image.
`--sbom-sources oci` tells trivy to prefer the registry-attached SBOM over
re-deriving one from the image layers, which is faster and produces results
that match exactly what was attested.

**From a downloaded SBOM** — useful for air-gapped scanning or when the same
SBOM is fed into multiple tools:

```
trivy sbom barbacana.cdx.json
```

Or with grype:

```
grype sbom:./barbacana.cdx.json
```

Both scanners auto-detect CycloneDX format. Severity, output format, and
ignore-policy flags are scanner-specific — see the respective documentation.

A clean scan today does not mean the image is clean tomorrow; new CVEs are
disclosed against existing components continuously. See the next section.

## 5. Continuously monitor a deployed image

The SBOM is immutable — it lists the components present at build time. The
vulnerability database is not. A CVE disclosed this week against a Go module
pinned at release time will show up only if you re-scan.

For a deployed image, schedule a re-scan against the live tag (the tag,
not a stored SBOM, so the scanner always uses the latest CVE database):

```
trivy image \
  --sbom-sources oci \
  --scanners vuln \
  --severity CRITICAL,HIGH \
  --exit-code 1 \
  ghcr.io/barbacana-waf/barbacana:vX.Y.Z
```

`--exit-code 1` makes the command fail the surrounding job on any matching
finding, which is the hook to wire into a CI cron, an alerting pipeline, or
a Kubernetes admission/operator policy.

For longer-lived inventories, feed the attested SBOM into a service that
tracks components over time — Dependency-Track and GUAC both ingest
CycloneDX and re-evaluate against their CVE feeds on a schedule. They can
fetch the attestation directly from `ghcr.io` using cosign or oras; no
manual download step is required.

The Barbacana project itself runs a daily trivy scan of the published
`:latest` tag and surfaces findings in the GitHub Security tab — see
[docs/design/build.md](design/build.md) for the workflow definition.
That is upstream visibility, not a substitute for monitoring your own
deployed pin.

## Why not a Release-page attachment

Consumers coming from other projects sometimes expect to find an SBOM
attached to the GitHub Release. Barbacana does not publish one there.
Three reasons:

- **Cryptographic binding.** The attested SBOM is signed against the image
  digest. A Release attachment is only as trustworthy as the
  `contents: write` token that uploaded it — there is no link between the
  uploaded file and the image.
- **Portability.** Attestations travel with the image. Mirrors, private
  registries, and air-gapped environments carry the SBOM along with the
  image automatically; nothing has to scrape the GitHub Releases API.
- **Tooling.** trivy, grype, GUAC, and Dependency-Track all fetch
  attestations natively. There is no consumer workflow that requires the
  SBOM to be a Release asset.

The attested copy in the registry is the authoritative SBOM. The Makefile
`make sbom` target produces an identical CycloneDX file from a checkout for
local debugging, but is not a distribution channel.

## Reference

- [docs/RELEASING.md](RELEASING.md) — how releases are produced and what
  artifacts they consist of.
- [docs/design/build.md](design/build.md) — signing flow, identity policy,
  and CI workflow definitions.
- [Sigstore docs](https://docs.sigstore.dev/) — background on cosign,
  Fulcio, Rekor, and the in-toto attestation format.
