---
title: "Your VEX documents are silently doing nothing"
date: 2026-09-13
site: gautamkhosla.com
status: draft — publish ≥7 days after post 1 AND after VEX vendor notices (see launch/vendor-notifications/LOG.md)
---

# Your VEX documents are silently doing nothing

Organizations ship **VEX** (Vulnerability Exploitability eXchange) documents to say “this CVE does not apply to our product.” Regulators and customers treat them as evidence.

We built a deterministic auditor that asks a narrower question: **given your SBOM, does each VEX statement actually attach to a component identity your tooling would match — or is it inert?**

Two failure modes show up repeatedly. Both are silent: CI goes green, audits fail later.

## Failure mode A — inert (Grype-class)

**Symptom:** VEX names `pkg:generic/commons-lang3@3.12.0`. Your CycloneDX SBOM lists the same name and version — but only at **`name_version_only`** match quality, not `exact` or `type_normalized`.

**Effect:** The VEX statement **never binds** to the SBOM component your scanner uses. You think you suppressed CVE-2022-99999; your pipeline never applied the statement.

Reproduction (fixture in repo):

```bash
lading audit-vex \
  testdata/auditvex/grype_inert/sbom.cdx.json \
  testdata/auditvex/grype_inert/vex.openvex.json
# STATUS inert — best match name_version_only
```

This is not hypothetical JSON. It is the **minimal shape** we see when product PURLs in VEX do not carry the same type/ecosystem normalization as SBOM generators.

## Failure mode B — overbroad (Trivy-class)

**Symptom:** VEX suppresses CVE-2023-88888 on `pkg:generic/openssl@3.0.2` with an **`exact`** match — but the hit is on a **subcomponent**, not the root product.

**Effect:** You may suppress a CVE for a dependency identity while believing you cleared the **shipping root**. Cross-product false confidence.

```bash
lading audit-vex \
  testdata/auditvex/trivy_overbroad/sbom.cdx.json \
  testdata/auditvex/trivy_overbroad/vex.openvex.json
# STATUS overbroad — exact match on subcomponent only
```

## Why this matters for CRA and PSIRT

CRA technical files and customer security questionnaires assume VEX is **machine-actionable**. If match quality is wrong:

- **Inert** statements create a false sense of clearance (nothing was suppressed).
- **Overbroad** statements create a false sense of product-level clearance (dependency-level only).

Both are worse than no VEX: they generate **paperwork that does not connect to the SBOM your scanner consumed.**

## Method

`lading audit-vex <sbom> <vex...>`:

1. Load CycloneDX SBOM components (root vs. subcomponent flagged).
2. Parse OpenVEX (CycloneDX / CSAF paths supported in CLI).
3. For each statement, grade PURL match quality (`exact`, `type_normalized`, `name_version_only`, …).
4. Flag **inert** (no exact/type-normalized hit) or **overbroad** (exact hit on subcomponent only).

No LLM. No heuristics. Exit code 1 if any failure — suitable for CI.

We are **not** claiming every public VEX file in the wild matches these fixtures. We **are** claiming these shapes appear when SBOM and VEX are produced by different toolchain chains (Grype vs. Trivy vs. hand-authored OpenVEX) without a shared PURL contract.

### Auditing your own documents

```bash
# Your SBOM + your VEX
lading audit-vex sbom.cdx.json vex.openvex.json
```

If you maintain public VEX for a product line, run this before publication.

## What we told vendors first

Anchore (Grype) and Aqua (Trivy) maintainers received private notice **≥14 days** before this post (see our notification log). We describe **failure modes**, not malice. Both ecosystems are essential; the gap is **integration**, not incompetence.

If you publish VEX and want us to run `audit-vex` on a public document before citing it, contact us — we will report privately first.

## Relation to the firmware corpus study

Last week’s post: [41 shipped artifacts, 10,088 scanner CVEs, 0 decided with symbol evidence at v1](/). VEX silence is the **downstream** failure: even when teams try to document clearance, identity mismatch means the documentation never attaches.

Fix order:

1. Align SBOM ↔ VEX PURLs (audit-vex in CI).
2. Only then argue symbol-level `vulnerable_code_not_present` with binary evidence.

---

## Tool (last)

**LADING** — `lading audit-vex`, `lading scan`, evidence bundles. Open source.

Repo: [github.com/gautamtalksdev/lading](https://github.com/gautamtalksdev/lading)

We do not ask for stars. We ask you to run the auditor on your own VEX before the regulator does.
