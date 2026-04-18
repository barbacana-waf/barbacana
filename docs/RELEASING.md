# How releases work

A reference for future-me. Not a setup guide — the pipeline already exists. This explains how the pieces fit together so the behaviour isn't a mystery in a year.

## The shape of a release

A Barbacana release is three artifacts that all reference the same git commit:

1. A commit on `master` that bumps `BARBACANA_VERSION` in [versions.mk](../versions.mk).
2. An annotated git tag `vX.Y.Z` pointing at that commit.
3. A multi-arch OCI image at `ghcr.io/barbacana-waf/barbacana:vX.Y.Z` (and `:latest`), cosign-keyless-signed and SBOM-attested, matching the same commit SHA.

Nothing else counts. If any of those three is missing or doesn't line up, there is no release.

## Who produces what

| Artifact | Produced by | Why it looks like that |
|---|---|---|
| Version bump commit + git tag | [.github/workflows/release.yml](../.github/workflows/release.yml) | Humans don't edit `BARBACANA_VERSION` and don't create tags by hand. A single workflow owns both so they can't drift. |
| Multi-arch image, signature, SBOM attestation | [.github/workflows/ci.yml](../.github/workflows/ci.yml) `image` job (on `refs/tags/v*`) | The tag push triggers `ci.yml`. ko builds, cosign signs and attests against the OIDC identity of that workflow run. |

Two workflows, one thing they each own. The handoff is the tag push.

## Why `RELEASE_TOKEN` (a PAT) exists

`release.yml` authenticates git pushes with `secrets.RELEASE_TOKEN`, not the default `GITHUB_TOKEN`. Two reasons, both load-bearing:

- **Branch protection.** The release commit goes to `master`, which has protection rules. `GITHUB_TOKEN` can't bypass them; a PAT with `contents: write` can.
- **Downstream triggers.** GitHub deliberately suppresses workflow triggers for events authored by `GITHUB_TOKEN`, to prevent recursion. That means a tag pushed by `GITHUB_TOKEN` would **not** wake `ci.yml`, so no image would ever be built. A PAT-authored push does trigger downstream workflows.

Remove or expire the PAT and the release pipeline stops working at step one.

## What gates an image being published

The `image` job in `ci.yml` decides what to push based on the trigger (see `Compute tag` step):

| Trigger | `push` | Result |
|---|---|---|
| `pull_request` | `false` | `ko build --local` — nothing published, image just verified buildable |
| Push to `master` (normal commit) | `true` | Published as `:v{VERSION}-master-<sha7>` — dev image |
| Push to `master` (commit starts `release: v`) | *job skipped* | The tag run will handle it; see the job-level `if:` in `ci.yml` |
| Push of tag `v*` | `true` | Published as `:vX.Y.Z` and `:latest`, **signed and SBOM-attested** |

Only the tag path signs. Master dev images are unsigned on purpose — they're for developer convenience, not distribution.

## What "signed" actually means here

The cosign keyless signature binds the image digest to the GitHub OIDC identity of the workflow run that produced it. Concretely, verifying succeeds only if:

- The image was pushed during a run of `.github/workflows/ci.yml` in this repo,
- on a ref matching `refs/tags/v*`,
- and the signature is logged in Sigstore's Rekor transparency log.

Any of those not being true → verification fails. That is the entire supply-chain guarantee consumers rely on.

The SBOM is attached twice:

- **Via ko** (`--sbom=cyclonedx`) — as OCI `.sbom` tags alongside the image, pullable with `cosign download sbom`.
- **Via `cosign attest`** — as an in-toto DSSE envelope, signed by the same workflow identity, verifiable with `cosign verify-attestation --type cyclonedx`.

The ko copy is convenient; the cosign attestation is the strong one.

## How to actually cut a release

Given all the above is set up, the operator action is:

1. GitHub → **Actions** → **release** → **Run workflow** → pick `patch` / `minor` / `major`.
2. Wait for `ci.yml` to go green on the new tag.
3. Create a GitHub Release on the tag and write the notes.

Helm chart release is separate (lives in the chart repo, see [design/deliverables.md](design/deliverables.md)).

## Sanity check

After the tag CI is green, confirm the release is signed end-to-end:

```
cosign verify \
  --certificate-identity-regexp "^https://github.com/barbacana-waf/barbacana/.github/workflows/ci.yml@refs/tags/v" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/barbacana-waf/barbacana:vX.Y.Z
```

A clean three-bullet "claims validated / Rekor entry present / cert chain verified" output means:

- The image at that tag was signed by our `ci.yml` on `refs/tags/vX.Y.Z`,
- the signature is publicly logged and tamper-evident,
- and the short-lived Fulcio certificate is intact.

If verification fails, something reached that tag that didn't come from this repo's CI. Treat the image as unpublished until it's investigated.

To also confirm the SBOM attestation (available from the first release that includes the ko-SBOM-path fix onward):

```
cosign verify-attestation \
  --certificate-identity-regexp "^https://github.com/barbacana-waf/barbacana/.github/workflows/ci.yml@refs/tags/v" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --type cyclonedx \
  ghcr.io/barbacana-waf/barbacana:vX.Y.Z
```
