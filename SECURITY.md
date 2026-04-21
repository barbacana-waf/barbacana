# Security Policy

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report privately via GitHub's [Security Advisories](https://github.com/barbacana-waf/barbacana/security/advisories/new).
If you can't use that, email <your-email> (optionally PGP: <fingerprint>).

Please include:
- A description of the issue and its impact
- Steps to reproduce, or a proof-of-concept
- The affected version/commit
- Any suggested mitigation, if you have one

## What to Expect

Barbacana is maintained by a single person in their spare time. I aim to:
- Acknowledge your report within **7 days**
- Provide an initial assessment within **30 days**
- Work with you on a coordinated disclosure timeline

I may be slower during busy periods. If you haven't heard back in two weeks,
feel free to send a polite nudge.

## Disclosure

I follow coordinated disclosure. Once a fix is available, I'll publish a
GitHub Security Advisory crediting you (unless you prefer to remain anonymous).
I'm comfortable with a **90-day** disclosure deadline from initial report,
which is standard industry practice.

## Scope

In scope:
- The barbacana codebase in this repository
- Default configurations and example rulesets

Out of scope:
- Vulnerabilities in upstream dependencies (report those to the upstream project)
- Issues requiring a misconfigured or already-compromised host
- Denial of service via resource exhaustion with no amplification

## Supported Versions

Only the `master` branch and the latest tagged release receive security fixes.