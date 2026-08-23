# GitHub issue draft — OSS Review Toolkit advisor

**Repo:** oss-review-toolkit/ort  
**Title:** Community advisor: LADING refusal-first triage after scanner

## Context

ORT advisors encode policy on scan results. **LADING** adds binary-grounded triage after grype/Trivy JSON exists.

## Proposal

External advisor module (initially out-of-tree):

1. Input: path to LADING `scan-summary.json` + optional `evidence-bundle/`
2. Output: ORT `Issue` list for each `refused` finding above severity threshold
3. Treat `NOT_AFFECTED` as resolved **only** with bundle digest present

## Fixtures

CC-BY corpus scan outputs: `corpus/results/*/scan-summary.json`

## Ask

Which advisor interface version (ORT 30+) should we target first?
