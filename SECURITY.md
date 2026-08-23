# Security Policy

## Supported versions

Only the latest tagged release of LADING is supported for security fixes until
additional stable branches are announced.

## Reporting a vulnerability

Do **not** open a public GitHub issue for security reports.

Email security concerns to the maintainer at the address listed in
`git log` / repository owner contact, with:

- a clear description of the issue
- steps to reproduce (deterministic, preferably with a small fixture)
- impact assessment (what a wrong `not_affected` or forged evidence would mean)

You should receive an acknowledgement within 7 days. Coordinated disclosure
timelines will be agreed case by case.

## Scope notes

LADING is a compliance evidence tool. Reports that demonstrate:

- emission of `not_affected` without a re-derivable evidence bundle
- non-deterministic decision outcomes for identical inputs
- evidence-bundle forgery or verification bypass

are in scope and treated as critical.
