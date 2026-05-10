# Workflows

Trigger map across all workflows in this folder:

| Workflow | PR | Cron | Dispatch | Other |
|---|---|---|---|---|
| `ci.yml` | yes | | | `workflow_call` from `release.yml` |
| `dependency-review.yml` | yes | | | |
| `release.yml` | | | yes (`bump` input) | |
| `security.yml` | | daily 06:00 UTC | yes | |
| `weekly-codeql.yml` | yes | weekly Fri 06:00 UTC | | |
| `weekly-fuzz.yml` | | weekly Fri 06:00 UTC | yes | |
| `weekly-scorecard.yml` | | weekly Fri 06:00 UTC | yes | `branch_protection_rule` |


## What each workflow does

- **`ci.yml`** — lint, vuln-scan (govulncheck + Trivy fs), test, integration, blackbox. Runs on every PR; also called as a reusable workflow by `release.yml` as the pre-flight gate. All jobs invoke `make` targets so CI mirrors `make simulate-ci` exactly.

- **`release.yml`** — manual single-button release. See the operator-facing header at the top of the file for the full failure semantics, cosign-verification caveat, and SLSA-provenance verification command. The `tag-publish` job is the only one that writes to origin, so failures before it are non-destructive.

- **`dependency-review.yml`** — GitHub's dependency-review action on PRs; flags vulnerable / disallowed-license dependencies introduced by the PR.

- **`weekly-codeql.yml`** — CodeQL static analysis. PRs + weekly cron.

- **`weekly-scorecard.yml`** — OpenSSF Scorecard. Weekly cron + `branch_protection_rule` change events + manual dispatch.

- **`security.yml`** — daily security scan (govulncheck, Trivy, etc.).

- **`weekly-fuzz.yml`** — Go fuzz corpus runs. **Note:** these two files have identical triggers and look like an unintended duplicate; one should likely be removed.

## Repo-level security settings

These GitHub-side settings are turned on. They sit alongside the workflows above — they don't change what the workflows do, but they shape what's allowed to run and what gets blocked at push time.

- **Push protection for secrets.** GitHub scans every push for things that look like API keys or credentials, and *blocks the push* if it finds one. If it ever false-positives, there's a one-click override in the UI.
- **Dependabot security updates.** Whenever one of the Go or GitHub Actions dependencies has a known security bug, Dependabot opens a PR with the fix. The PR runs through `ci.yml` like any other PR — nothing lands without going green.
- **Allowlist for third-party Actions.** Only Actions from GitHub itself, from GitHub-verified publishers, and from an explicit short list (currently `softprops/action-gh-release` and `imjasonh/setup-crane`) can run. Adding a new third-party Action means extending the allowlist.
