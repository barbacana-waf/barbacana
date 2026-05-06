# Workflows

Trigger map across all workflows in this folder:

| Workflow | PR | Cron | Dispatch | Other |
|---|---|---|---|---|
| `ci.yml` | yes | | | `workflow_call` from `release.yml` |
| `dependency-review.yml` | yes | | | |
| `fuzz-weekly.yml` | | weekly Fri 06:00 UTC | yes | |
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
