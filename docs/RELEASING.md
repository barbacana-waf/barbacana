# How releases work

A Barbacana release is four artifacts, all bound to the same commit:

1. A `master` commit bumping `BARBACANA_VERSION` in [versions.mk](../versions.mk).
2. An annotated git tag `vX.Y.Z` on that commit.
3. A multi-arch image at `ghcr.io/barbacana-waf/barbacana:vX.Y.Z` (and `:latest`), cosign-keyless-signed, built from the same commit.
4. A CycloneDX SBOM attested to the image digest via cosign (stored as an OCI 1.1 referrer alongside the image in `ghcr.io`). The same file is also published as a workflow artifact for internal debugging.

If any of the four is missing or doesn't line up, there is no release. The pipeline is the only path that produces a signed image.

Master-commit dev builds publish to the separate `ghcr.io/barbacana-waf/barbacana-edge` package so the main package page stays clean (only release tags + `latest` + the signature entry).

## Ownership

- [release.yml](../.github/workflows/release.yml) — bumps `versions.mk`, commits to `master`, creates the tag, pushes. Owns steps 1 and 2.
- [ci.yml](../.github/workflows/ci.yml) `image` job, tag path only — ko builds, cosign signs the image, generates the CycloneDX SBOM, attests it to the image digest. Owns steps 3 and 4.

The handoff is the tag push.

## Cutting a release

1. GitHub → **Actions** → **release** → **Run workflow** → pick `patch` / `minor` / `major`.
2. Wait for `ci.yml` to go green on the new tag. On success, the image is signed and the SBOM is attested in `ghcr.io` — there is no race with a GitHub Release, because the SBOM does not live on the Release page.
3. Create a GitHub Release on the tag and write the notes (optional; consumers verify and fetch the SBOM from the registry, not from the Release page).

Helm chart ships separately, from the chart repo — see [design/deliverables.md](design/deliverables.md).

## Verifying a release

Consumers verifying a release — signature, SBOM attestation, SBOM retrieval, CVE scanning, and continuous monitoring — should follow [docs/VERIFYING.md](VERIFYING.md). The short version:

```
make verify IMG=ghcr.io/barbacana-waf/barbacana:vX.Y.Z
make verify-attestation IMG=ghcr.io/barbacana-waf/barbacana:vX.Y.Z
trivy image --sbom-sources oci --scanners vuln --severity CRITICAL,HIGH ghcr.io/barbacana-waf/barbacana:vX.Y.Z
```

Both verification commands must pass — a failure means the image or its SBOM isn't what it claims and should be treated as untrusted. The trivy scan is advisory (reports CVEs present in pinned Go dependencies at build time).

## Two things that will bite you

- **`RELEASE_TOKEN` (a PAT) is load-bearing.** `release.yml` uses it instead of `GITHUB_TOKEN` for two reasons: the release commit goes to a protected `master`, and pushes authored by `GITHUB_TOKEN` do not trigger downstream workflows — so a `GITHUB_TOKEN`-pushed tag would never wake `ci.yml`, and no image would ever be built. If the PAT expires, step 1 fails silently-ish.
- **Only tag pushes sign.** PR builds and master-commit dev images are unsigned on purpose — they're for developer smoke-testing, not distribution. Never hand a consumer a tag without verifying it with the commands above first.
