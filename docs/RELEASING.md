# How releases work

A Barbacana release is three artifacts, all bound to the same commit:

1. A `master` commit bumping `BARBACANA_VERSION` in [versions.mk](../versions.mk).
2. An annotated git tag `vX.Y.Z` on that commit.
3. A multi-arch image at `ghcr.io/barbacana-waf/barbacana:vX.Y.Z` (and `:latest`), cosign-keyless-signed and SPDX SBOM-attested, built from the same commit.

If any of the three is missing or doesn't line up, there is no release. The pipeline is the only path that produces a signed image.

## Ownership

- [release.yml](../.github/workflows/release.yml) — bumps `versions.mk`, commits to `master`, creates the tag, pushes. Owns steps 1 and 2.
- [ci.yml](../.github/workflows/ci.yml) `image` job, tag path only — ko builds, cosign signs, cosign attests the SBOM. Owns step 3.

The handoff is the tag push.

## Cutting a release

1. GitHub → **Actions** → **release** → **Run workflow** → pick `patch` / `minor` / `major`.
2. Wait for `ci.yml` to go green on the new tag.
3. Create a GitHub Release on the tag and write the notes.

Helm chart ships separately, from the chart repo — see [design/deliverables.md](design/deliverables.md).

## Verifying a release

```
cosign verify \
  --certificate-identity-regexp "^https://github.com/barbacana-waf/barbacana/.github/workflows/ci.yml@refs/tags/v" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/barbacana-waf/barbacana:vX.Y.Z

cosign verify-attestation \
  --certificate-identity-regexp "^https://github.com/barbacana-waf/barbacana/.github/workflows/ci.yml@refs/tags/v" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --type spdxjson \
  ghcr.io/barbacana-waf/barbacana:vX.Y.Z
```

Both must pass. Either one failing means the image isn't what it claims — treat as untrusted.

## Two things that will bite you

- **`RELEASE_TOKEN` (a PAT) is load-bearing.** `release.yml` uses it instead of `GITHUB_TOKEN` for two reasons: the release commit goes to a protected `master`, and pushes authored by `GITHUB_TOKEN` do not trigger downstream workflows — so a `GITHUB_TOKEN`-pushed tag would never wake `ci.yml`, and no image would ever be built. If the PAT expires, step 1 fails silently-ish.
- **Only tag pushes sign.** PR builds and master-commit dev images are unsigned on purpose — they're for developer smoke-testing, not distribution. Never hand a consumer a tag without verifying it with the commands above first.
