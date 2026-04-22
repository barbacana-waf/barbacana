# How releases work

A Barbacana release is four artifacts, all bound to the same commit:

1. A `master` commit bumping `BARBACANA_VERSION` in [versions.mk](../versions.mk).
2. An annotated git tag `vX.Y.Z` on that commit.
3. A multi-arch image at `ghcr.io/barbacana-waf/barbacana:vX.Y.Z` (and `:latest`), cosign-keyless-signed, built from the same commit.
4. A CycloneDX SBOM (`barbacana-vX.Y.Z.cdx.json`) attached to the GitHub Release on the same tag.

If any of the four is missing or doesn't line up, there is no release. The pipeline is the only path that produces a signed image.

Master-commit dev builds publish to the separate `ghcr.io/barbacana-waf/barbacana-edge` package so the main package page stays clean (only release tags + `latest` + the signature entry).

## Ownership

- [release.yml](../.github/workflows/release.yml) — bumps `versions.mk`, commits to `master`, creates the tag, pushes. Owns steps 1 and 2.
- [ci.yml](../.github/workflows/ci.yml) `image` job, tag path only — ko builds, cosign signs the image, generates the CycloneDX SBOM, attaches it to the GitHub Release. Owns steps 3 and 4.

The handoff is the tag push.

## Cutting a release

1. GitHub → **Actions** → **release** → **Run workflow** → pick `patch` / `minor` / `major`.
2. Wait for `ci.yml` to go green on the new tag.
3. Create a GitHub Release on the tag and write the notes. The SBOM gets uploaded automatically by CI; do this step after CI to avoid a race where the release doesn't exist yet when `gh release upload` runs — or create it first and CI will `--clobber` the SBOM onto it.

Helm chart ships separately, from the chart repo — see [design/deliverables.md](design/deliverables.md).

## Verifying a release

Verify the image signature:

```
make verify IMG=ghcr.io/barbacana-waf/barbacana:vX.Y.Z
```

Scan the SBOM for CVEs (downloads from the GitHub Release):

```
gh release download vX.Y.Z --pattern 'barbacana-*.cdx.json'
trivy sbom barbacana-vX.Y.Z.cdx.json
```

The signature check must pass — a failure means the image isn't what it claims and should be treated as untrusted. The SBOM scan is advisory (reports CVEs present in pinned Go dependencies at build time).

## Two things that will bite you

- **`RELEASE_TOKEN` (a PAT) is load-bearing.** `release.yml` uses it instead of `GITHUB_TOKEN` for two reasons: the release commit goes to a protected `master`, and pushes authored by `GITHUB_TOKEN` do not trigger downstream workflows — so a `GITHUB_TOKEN`-pushed tag would never wake `ci.yml`, and no image would ever be built. If the PAT expires, step 1 fails silently-ish.
- **Only tag pushes sign.** PR builds and master-commit dev images are unsigned on purpose — they're for developer smoke-testing, not distribution. Never hand a consumer a tag without verifying it with the commands above first.
