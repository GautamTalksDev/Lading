# Research and authority (Part VII)

CP-11 corpus output is the research byproduct. Four tracks, ranked by durability.

## 7.1 The spec (highest ceiling)

[SPEC-EVIDENCE.md](../SPEC-EVIDENCE.md) — versioned **`evidence-v1`**, licensed **CC-BY-4.0**,
zero LADING-specific structures required to implement.

**Goal:** own the definitional gap — what evidence is sufficient for each admissible
`not_affected` justification — not just one Go implementation.

**Test:** can someone implement from the spec alone without reading our code?

## 7.2 Standards bodies (~2 hrs/month)

| Body | Entry |
|------|-------|
| CycloneDX (OWASP / ECMA-424) | Working group minutes — listen from CP-4 |
| CSAF (OASIS) | Same |
| OpenSSF | SBOM / security tooling WGs |

**Play:** find the unowned backlog item your implementation already addresses;
contribute **implementation + CP-11 data**, not product pitches.

Evidence-sufficiency guidance is in scope for all three and matches SPEC-EVIDENCE.

## 7.3 Workshop paper (lagging asset)

Draft: [launch/paper/workshop-draft.md](../launch/paper/workshop-draft.md)

- Supply-chain / SBOM **workshop**, not top-tier chase
- Reports CP-11 pre-registered result (negative results publishable)
- Corpus + ground truth + code released with paper
- **Independent** of launch timing

## 7.4 Disclosure record (byproduct)

`lading audit-vex` findings on inert public VEX → coordinated disclosure per
[launch/vendor-notifications/](../launch/vendor-notifications/):

- **14 days** private notice minimum
- Severity context **with** the name, never name alone
- Right of reply — publish unedited when provided
- Frame as ecosystem problems where honest; say plainly when not

**Not a marketing channel.** Report whether or not it helps you.

## 7.5 What NOT to do

- Distort LADING to chase a publication
- Top-tier security conference as first submission
- Publish corpus findings before maintainer pre-notification

See [DISTRIBUTION.md](DISTRIBUTION.md) for outreach sequencing.
