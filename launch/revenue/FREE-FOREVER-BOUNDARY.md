# Free forever boundary (CP-12 → ∞)

**Draw the line here. Never cross it.**

Paid tier (**LADING Evidence**) may only **add** org infrastructure. It must not
**remove**, **degrade**, or **license-gate** anything below.

---

## Free and fully featured (forever)

| Capability | CP-12 artifact |
|------------|----------------|
| `lading scan` | CLI |
| `lading explain` | CLI |
| `lading verify` | CLI + air-gap bundle re-derivation |
| `lading sign` | CLI (cosign on reviewed VEX) |
| `lading manifest derive` | Operator tool |
| `lading manifest propose` | Contributor path |
| `lading manifest promote` | Maintainer path (public tree) |
| `lading manifest coverage` | Coverage reports |
| Public Manifest (`manifest/components/`, CC0) | Data |
| Manifest contribution flywheel (CP-13) | DATA-only extension |
| Corpus methodology + CC-BY corpus | Research reproducibility |
| GitHub Action (self-hosted workflow) | `.github/workflows/lading-action-smoke.yml` pattern |
| Evidence bundle format + `MANIFEST.sha` / `BUNDLE.id` | Open format |
| VEX output + refusal semantics | No prove-a-negative |
| Homebrew / Scoop / .deb packaging | Distribution |
| All documentation (EVIDENCE, MANIFEST, CRA mapping, LIMITS, VERIFY) | Docs |

---

## Explicitly not moving to paid

- Removing symbol coverage from free CLI when Manifest entry exists
- Network calls required for `lading verify`
- Rate limits on local scan
- “Enterprise edition” fork of the CLI
- Private-only fixes to public CVE logic

---

## What paid tier may add (new infrastructure only)

Examples (build only after CP-14 step 3):

- Hosted retention for evidence bundles (10-year class)
- Org-scoped private Manifest entries (not in public CC0 tree)
- Central CI audit log across pipelines (self-hosted Action stays free)
- CRA technical file **export assembly** from stored evidence

Customers who never pay get the same CP-12 tool chain indefinitely.

---

## Enforcement

- Product decisions: check against this file before any commercial roadmap item
- Code review: reject PRs that introduce license gates on items in the first table
- KT-3: if no inbound by month 8, none of the paid tier is built — free OSS remains

See [CP-14-GATE.md](CP-14-GATE.md).
