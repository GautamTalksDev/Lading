# CRA Annex I — factual mapping (not legal advice)

This document describes **what LADING output contains**, for teams mapping
artifacts into EU Cyber Resilience Act (CRA) technical documentation workflows.

**This is not legal advice.** The manufacturer remains solely responsible for
their technical file. See [DISCLAIMER.md](../DISCLAIMER.md).

## Scope boundary

LADING addresses **evidence for vulnerability exploitability statements** about
binary artifacts — not entire Annex I compliance (secure-by-design lifecycle,
CE marking process, incident reporting timelines, etc.).

## Annex I mapping (illustrative)

| Annex I theme | LADING artifact | What it demonstrates |
|---------------|-----------------|----------------------|
| Identification of vulnerabilities in the product | Scanner findings input + `lading scan` report | Which CVEs were in scope for triage |
| Documentation of security testing / analysis | Evidence bundle per CVE (`statements/`) | Re-derivable record of symbols consulted, manifest version, binary hashes |
| Known-exploited or relevant CVE disposition | VEX outputs (`vex.openvex.json`, `vex.cdx.json`, `vex.csaf.json`) | Machine-readable status with digest-pinned product identity |
| Traceability of security claims | `MANIFEST.sha`, `BUNDLE.id`, cosign signatures (`lading sign`) | Tamper-evident linkage from claim → inputs |
| Limits of analysis | `refusals.json`, D03 reason codes, [LIMITS.md](LIMITS.md) | Explicit record of what was **not** decided |

## What to file vs what to withhold

**File** when your process accepts the evidence:

- `NOT_AFFECTED` / `AFFECTED` rows with matching evidence bundle and VEX
- `lading verify` exit 0 transcript (air-gapped re-derivation)
- `lading explain <cve> --bundle …` printout for auditor readability

**Do not file as “cleared”**:

- `UNDER_INVESTIGATION` / refused rows — these are explicit non-claims
- Any statement whose bundle fails `lading verify`

## Forbidden claims reminder

LADING will never produce VEX justifications that claim code is not in the
execute path, cannot be controlled by an adversary, or is mitigated inline.
If your CRA narrative requires those arguments, they must come from a separate
process outside LADING — with separate evidence and separate liability.

## Related docs

- [EVIDENCE.md](EVIDENCE.md) — verdicts and rules
- [VERIFY.md](../VERIFY.md) — independent verification without trusting the operator
- [LIMITS.md](LIMITS.md) — coverage boundaries
