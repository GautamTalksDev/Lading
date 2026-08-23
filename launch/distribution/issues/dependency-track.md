# GitHub issue draft — Dependency-Track integration

**Repo:** Dependency-Track/dependency-track  
**Title:** Extension point: attach external evidence bundle reference to finding analysis

## Problem

Scanners populate DT with CVE rows. Compliance workflows need **evidence** (VEX + re-derivable bundle) or explicit **refusal** — not analyst free-text alone.

## Proposal

Optional webhook or API field on `FindingAnalysis`:

- `evidenceBundleDigest` (sha256 of tarball/dir)
- `evidenceTool` (`lading/evidence-v1`)
- `verdict` (`NOT_AFFECTED` | `AFFECTED` | `UNDER_INVESTIGATION`)

LADING produces `scan-summary.json` + `evidence-bundle/` locally; CI uploads bundle to object storage and PATCHes DT.

## Non-goals

- Replace DT vulnerability intel
- Auto-clear without bundle hash

## Repro

https://github.com/gautamtalksdev/lading — `RESULTS.md`, `action/action.yml`
