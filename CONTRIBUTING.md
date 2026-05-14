# Contributing to Barbacana

Thanks for your interest in contributing. Barbacana is a Web Application Firewall — a security-critical piece of software. Several of the rules below are stricter than typical Go open source projects, specifically to reduce the risk of supply-chain attacks against the project and the people who deploy it. Most of the rest is normal Go practice.

## Reporting a security vulnerability

**Please do not open a public GitHub issue for security bugs.**

Use a private channel instead:

- GitHub [Private Vulnerability Reporting](https://github.com/barbacana-waf/barbacana/security/advisories/new) (preferred)
- The contact listed in [SECURITY.md](./SECURITY.md)

You will get an acknowledgement within a few days, and we will coordinate a fix and disclosure timeline with you.

## Ways to contribute

- **Bug reports** — open a [GitHub issue](https://github.com/barbacana-waf/barbacana/issues) for non-security bugs. Include the version, what you did, what you expected, and what actually happened.
- **Feature requests** — open an issue first to discuss the idea before writing code. This avoids work that may not be accepted.
- **Code changes** — see below.

Documentation lives in a separate repository and is maintained by the project maintainers. If your code change affects user-facing behaviour, describe the required documentation update in your PR description (see the checklist below) — the maintainers will mirror it.

Look for issues labelled `good first issue` or `help wanted` if you want a starting point.

## Development setup

### Prerequisites

- Go (the minimum version is in `go.mod`)
- `make`
- `git`

### Build and test

```bash
git clone https://github.com/barbacana-waf/barbacana.git
cd barbacana
make simulate-ci
```

`make simulate-ci` runs the same checks the CI pipeline runs on every PR (build, lint, tests, `go.mod` tidiness, etc.). It's not strictly one-to-one — CodeQL static analysis runs only on GitHub — but if `make simulate-ci` passes locally, your PR is very likely to pass CI.

## Making changes

### 1. Fork and branch

This is a public project, so contributions go through forks:

1. Fork the repository on GitHub.
2. Clone your fork locally.
3. Create a branch from `master`:
   ```bash
   git checkout -b my-change master
   ```

### 2. Sign your commits

Every commit on this project carries two things: a **DCO sign-off** (a text line stating you have the right to contribute the code) and a **cryptographic signature** (proof the commit really came from you). They are independent mechanisms — both are required.

For background on how commit signing works in git and GitHub, see GitHub's [signing commits guide](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification). The walkthrough below is the fastest path; the guide covers alternatives.

Setup is one-time and takes a few minutes.

#### One-time setup (SSH signing, the simplest path)

If you already use SSH to push to GitHub, you can reuse the same key for signing.

1. Configure your git identity if you haven't already:

   ```bash
   git config --global user.name "Your Name"
   git config --global user.email "you@example.com"
   ```

2. Tell git to sign commits with your SSH key:

   ```bash
   git config --global gpg.format ssh
   git config --global user.signingkey ~/.ssh/id_ed25519.pub
   git config --global commit.gpgsign true
   ```

   Replace `id_ed25519.pub` with the filename of your SSH public key if different.

3. Register the same key as a **signing key** on GitHub. This is separate from the authentication key, even when the file is the same:

   - GitHub → Settings → SSH and GPG keys → **New SSH key**
   - Set **Key type** to **Signing Key**
   - Paste the contents of `~/.ssh/id_ed25519.pub`
   - The same key registered twice (once for auth, once for signing) is normal and expected.

Other signing methods (GPG, Sigstore/gitsign) are also accepted — see the GitHub guide linked above for setup instructions.

#### Making a commit

With the setup above, signing happens automatically. Add the DCO sign-off with `-s`:

```bash
git commit -s -m "fix(parser): handle empty Content-Length header"
```

This single command produces a commit that is both DCO-signed-off and cryptographically signed.

#### Verify it worked

Push to a branch and open the commit on GitHub. You should see:

- A green **Verified** badge next to the commit hash.
- A `Signed-off-by: Your Name <you@example.com>` line at the bottom of the commit message.

If either is missing, fix it before opening a Pull Request. CI rejects unsigned or un-signed-off commits.

### 3. Use Conventional Commit messages

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): short summary

Optional longer description explaining the why.

Signed-off-by: Your Name <you@example.com>
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, `build`.

The type also drives the next release version (see [Versioning](#versioning) below):

- `fix:` → patch bump
- `feat:` → minor bump
- `!` after the type, or a `BREAKING CHANGE:` footer → major bump

Examples:

- `feat(rules): add SQL injection detector`
- `fix(parser): handle empty Content-Length header`
- `feat(api)!: rename Detect() to Evaluate()` (breaking)

### 4. One change per Pull Request

Keep Pull Requests small and focused on one thing. Don't bundle a bug fix with a refactor — open two PRs instead. This matters even more for security fixes, which need to be small enough to review carefully and easy to back-port.

## Pull Request checklist

CI runs the same checks as `make simulate-ci`, plus CodeQL and dependency review. The PR cannot be merged until every required check passes — you don't need to repeat them in your PR description.

Before opening a PR, please confirm:

- [ ] All commits are signed-off (`-s`) and cryptographically signed (Verified badge on GitHub)
- [ ] The PR addresses one thing — no bundled refactors or unrelated fixes
- [ ] **All changes have tests** (new behaviour, bug fixes, refactors that change observable behaviour — all of them)
- [ ] If your change affects user-facing behaviour, the PR description spells out what needs to change in the docs repository (the maintainers will mirror it)
- [ ] The branch is rebased onto the latest `master` with no conflicts
- [ ] The PR description explains *what* the change does and *why*
- [ ] If you touched a high-sensitivity area, you have read that section below

## How review works

This project currently has a single maintainer, so reviews depend on availability:

- Expect an initial response within roughly a week.
- Larger or security-sensitive changes may take longer.
- You may be asked to rework the PR. This is normal, not personal.

PRs are merged using **squash-and-merge** by default — your branch's commits collapse into a single signed commit on `master`, so choose a clean PR title (it becomes the squash commit message). If your PR is structured as multiple independently-meaningful commits, the maintainer may opt to preserve them via rebase-merge instead, but squash is the default.

Branches must be rebased onto the latest `master` with no conflicts before merge. If conflicts appear during review, expect to be asked to rebase.

## High-sensitivity areas

Changes in the following areas receive extra scrutiny and may take longer to review:

- Detection rules and the protections catalog
- Request parsing
- The request-handling pipeline

If you are adding or modifying a protection rule, follow the protections-catalog convention. See [CLAUDE.md](./CLAUDE.md) for the format.

## CI / workflow / build policy

**Don't touch these files.** CI/CD configuration is one of the highest-impact attack surfaces in any project, and Barbacana publishes signed binaries — a mistake here can compromise every user.

The following files are maintainer-only:

- `.github/workflows/`, `.github/dependabot.yml`, `.github/CODEOWNERS`
- `Makefile`, `Dockerfile`, `goreleaser` config
- Anything else that influences how the project is built, tested, or released

PRs touching these will be closed without review unless the change was discussed and explicitly agreed in an issue first.

## Versioning

Barbacana follows [Semantic Versioning](https://semver.org/). Strict semver rules apply from `v1.0.0` onwards; the project is currently in `v0.x`, where breaking changes may land in any release but are flagged in commit messages and release notes.

## Releasing

Releases are cut by maintainers via the manual `release` workflow. Contributors do not need to do anything special for a release — your changes ship in the next release after merge.

## Questions?

- Bug reports → GitHub Issues
- Security reports → see the top of this file
- Anything else → open a draft issue and tag it `question`

Thanks again for contributing to Barbacana.