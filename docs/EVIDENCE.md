# What LADING cannot do

LADING is a **deterministic evidence tool**, not a lawyer, not a scanner, and not a
complete picture of your security posture.

- **It cannot prove legal compliance.** Output is factual evidence for *your* technical
  file. See [DISCLAIMER.md](../DISCLAIMER.md).
- **It cannot clear CVEs without re-derivable proof.** When evidence is insufficient,
  the answer is **refused** (`under_investigation`), not a guess.
- **It never emits these three VEX prove-a-negative justifications:**
  1. `vulnerable_code_not_in_execute_path`
  2. `vulnerable_code_cannot_be_controlled_by_adversary`
  3. `inline_mitigations_already_exist`
- **It cannot see what symbols hide in stripped static binaries**, renamed vendored
  code without identity match, or components with no manifest entry.
- **It does not replace Grype, Trivy, or your SBOM pipeline.** It consumes their
  findings and adds evidence — or refuses.

If you need a tool that clears everything your scanner reports, LADING is the wrong
tool. That honesty is the product.

---

# Evidence model (`evidence-v1`)

Normative spec: [SPEC-EVIDENCE.md](../SPEC-EVIDENCE.md). User guide: this file.

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `NOT_AFFECTED` | Decided with re-derivable bundle; one of two justifications below |
| `AFFECTED` | Vulnerable symbol observed in scanned binaries |
| `UNDER_INVESTIGATION` | **Refused** — insufficient evidence; reason code on every row |

## Rules (precedence)

1. **D03** — any refusal gate fires first (fail closed)
2. **D04** — definitive vulnerable symbol present → affected
3. **D02** — component identified, definitive symbols absent → not affected
4. **D01** — component not identified → not affected (`component_not_present`)

## The two justifications LADING emits

| Justification | Rule | Plain language |
|---------------|------|----------------|
| `component_not_present` | D01 | SBOM names a package; scanned binaries do not match manifest identity |
| `vulnerable_code_not_present` | D02 | Manifest ties CVE to upstream symbols; those symbols are not in your binaries |

Nothing else. No execute-path arguments. No “attacker can’t reach it.” No “we already mitigated inline.”

## Evidence bundle

Each decided statement produces a content-addressed bundle:

```
evidence-bundle/
  BUNDLE.id
  MANIFEST.sha
  statements/<id>/
    statement.json
    inputs.json
    observations.json
    manifest-slice.json    ← embedded manifest; verify needs no manifest/ tree
    versions.json
```

Verification: [VERIFY.md](../VERIFY.md) and `lading verify`.

## Explain command

Compliance reviewers should live here:

```bash
lading explain CVE-2023-0286 --bundle ./evidence-bundle
```

Prints rule ID, symbols checked, manifest provenance URLs, and what LADING refused to claim.
