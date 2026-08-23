# Refusal-First Vulnerability Triage on Shipped Binaries: Corpus Results and VEX Identity Audits

**Gautam Khosla**  
Draft for SBOM/VEX/supply-chain workshop (4–6 pages + references)

## Abstract

Compliance teams must justify scanner-reported CVEs against shipped firmware and container images. We present an open, deterministic pipeline that inventories binaries, matches curated manifest entries, and emits evidence bundles with OpenVEX/CycloneDX/CSAF — or an explicit `under_investigation` refusal. On a 41-artifact public corpus (10,088 grype CVE rows), **zero** findings reached an evidence-decided verdict at v1 integration (100% refused at PURL insufficiency). A pre-registered 100-statement hand-verified benchmark found **zero** false `not_affected` claims (KT-2 pass). We separately describe **`audit-vex`**, which flags VEX statements that are **inert** or **overbroad** relative to CycloneDX SBOM PURL match quality. Negative KT-1 is a first-class result: scanner volume alone does not support binary-grounded clearance.

## 1. Introduction

CRA and customer security questionnaires push organizations to clear CVE lists faster than manual review allows. Tools emit VEX with `vulnerable_code_not_present` without binary proof. We ask: **what fraction of scanner output admits re-derivable symbol evidence?**

## 2. Threat model and guarantees

- **No LLM, no network in decision path** (CP-0).
- **Two allowed `not_affected` justifications only:** `component_not_present`, `vulnerable_code_not_present`.
- **Forbidden VEX justifications** (prove-a-negative) blocked in CI.
- **Refusal default:** insufficient manifest, probable-only symbols, stripped static binaries, weak PURL match.

## 3. Method

### 3.1 Corpus

41 publicly downloadable artifacts (`corpus/ARTIFACTS.yaml`): OCI base/app, OpenWrt rootfs, static release binaries, RTOS SDK archives, firmware-class substitutes where vendor URLs 404. CC-BY dataset.

### 3.2 Pipeline

grype JSON → sandboxed unpack → multi-format inventory → `decide` rules (D01–D04) → optional evidence bundle + VEX emit.

### 3.3 Manifest

25 native components, one definitive CVE entry each, manually reviewed (`manifest/VERSION` 0.2.0, CC0).

### 3.4 Kill tests (pre-registered)

- **KT-1:** ≥30% scanner CVEs decided with evidence on corpus → **FAIL (0%)**
- **KT-2:** zero false `not_affected` in 100 hand-verified statements → **PASS**

## 4. Results

| Metric | Value |
|--------|------:|
| CVEs in | 10,088 |
| Decided | 0 |
| Refused | 10,088 |
| Refusal reason (corpus) | 100% PURL insufficient |

Ground truth engine agreement: 100/100 on controlled statements (64 expected `NOT_AFFECTED`).

## 5. VEX identity audit

Given CycloneDX SBOM + OpenVEX, grade PURL match quality per statement. Document **inert** (Grype-class) and **overbroad** (Trivy-class) fixtures with deterministic reproduction (`lading audit-vex`).

## 6. Discussion

Scanner CVE counts measure **package metadata exposure**, not shipped vulnerable code. Without PURL harmonization and manifest depth, binary-grounded clearance scales to **zero decided** — not because CVEs are false, but because evidence chains are incomplete. Stripped ELF dominance in container layers reinforces limits.

## 7. Related work

NTIA SBOM minimum elements; OpenVEX; CSAF 2.0; firmware scanners (EMBA, cve-bin-tool); ORT/Dependency-Track policy layers.

## 8. Conclusion

Publish negative KT-1 alongside sound KT-2. Ship `audit-vex` in CI before VEX reaches regulators. Future work: PURL normalization (v2 spec), flash filesystem extraction, corpus-driven manifest expansion — without refitting v1 thresholds.

## References

[To be completed: OpenVEX spec, CycloneDX, grype, CRA Article 10 vulnerability handling, BSI TR-03183 if applicable]

## Artifact availability

https://github.com/gautamtalksdev/lading — `RESULTS.md`, `corpus/`, `corpus/groundtruth/statements.yaml`
