# Support boundaries (CP-0)

LADING is maintained by an individual. **No SLA.** Best effort, stated plainly.

## Channels

| Channel | Use |
|---------|-----|
| **GitHub Issues** | Bugs, incorrect verdicts with reproduction |
| **GitHub Discussions** | Feature requests (batch-reviewed monthly) |
| **Security email** | Vulnerabilities only — see [SECURITY.md](../SECURITY.md) |

**Not supported:** Discord, Slack, email support, DMs, or “quick questions” outside
Issues. This keeps expectations honest and preserves maintainer time for Manifest
curation.

## Before opening an issue

1. Read [README.md](../README.md), [DISCLAIMER.md](../DISCLAIMER.md), [docs/LIMITS.md](LIMITS.md).
2. Search existing issues.
3. Use the correct template below.

## Bug reports (reproducible artifact required)

Issues **without** a minimal reproduction get the bug template and are closed if
the reporter cannot attach:

- fixture binary or image digest, and
- scanner input (SBOM + CVE list or grype JSON), and
- expected vs actual verdict / bundle ID.

No reproduction → no investigation thread.

## Feature requests

Open a **GitHub Discussion**, not an Issue. Feature requests are answered in a
**monthly batch** (first week). Do not expect roadmap commitments.

## Manifest entry disputes

Wrong symbol↔CVE mapping damages credibility. Manifest disputes use the dedicated
template and receive a **5 business-day** first response commitment.

Maintainer may promote, correct, or reject entries per [docs/MANIFEST.md](MANIFEST.md).
Disputes about **your** regulatory conclusions are out of scope — see DISCLAIMER.

## What is never support

- Legal advice or “will this satisfy CRA / my technical file” opinions
- Requests to soften kill tests or emit prove-a-negative VEX justifications
- Guarantees of completeness for any scanner CVE list
- Custom consulting via Issues (see [launch/revenue/CP-14-GATE.md](../launch/revenue/CP-14-GATE.md) when inbound exists)

## Security

See [SECURITY.md](../SECURITY.md). **Do not** file public issues for vulnerabilities.
