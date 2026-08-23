# Security Policy

## Supported versions

Only the latest tagged release of LADING is supported for security fixes until
additional stable branches are announced.

## Reporting a vulnerability

Do **not** open a public GitHub issue for security reports.

Email **security@lading.dev** (or the repository owner contact in GitHub profile
if that address is not yet live) with:

- a clear description of the issue
- steps to reproduce (deterministic, preferably with a small fixture)
- impact assessment (what a wrong `not_affected` or forged evidence would mean)

**Acknowledgement:** within 7 days.

**Coordinated disclosure:** **90-day** default timeline from acknowledgement unless
we agree otherwise. We will not publish your identity without permission.

## Scope notes

LADING is a compliance evidence tool. Reports that demonstrate:

- emission of `not_affected` without a re-derivable evidence bundle
- non-deterministic decision outcomes for identical inputs
- evidence-bundle forgery or verification bypass

are in scope and treated as critical.

## Out of scope

- Disputes about whether your regulatory filing is sufficient (see [DISCLAIMER.md](DISCLAIMER.md))
- Feature requests (use GitHub Discussions per [SUPPORT.md](SUPPORT.md))
