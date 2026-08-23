# LADING Evidence Specification — `evidence-v1`

> **License:** [Creative Commons Attribution 4.0 International (CC-BY-4.0)](https://creativecommons.org/licenses/by/4.0/).
> You may implement this specification without reading the LADING Go source. Attribute:
> **LADING evidence-v1 spec** with a link to this repository.

This document is the normative specification for the LADING deterministic
decision engine. An engineer may implement `internal/decide` from this
document alone without reading the Go source.

**Version:** `evidence-v1`  
**Scope:** Convert `(artifact inventories, SBOM component claim, vulnerability
finding, Manifest)` into a single **verdict** per evaluation. No LLM calls,
embeddings, probabilities, or network I/O.

---

## 1. Purpose

Given factual inputs only, decide whether a reported CVE against an SBOM
component is:

| Verdict | VEX-style justification (when applicable) |
|---------|-------------------------------------------|
| `NOT_AFFECTED` | `component_not_present` or `vulnerable_code_not_present` |
| `AFFECTED` | _(none — positive finding)_ |
| `UNDER_INVESTIGATION` | _(machine-readable reason code — not a VEX prove-a-negative)_ |

When evidence is insufficient for a sound `NOT_AFFECTED`, the answer is always
`UNDER_INVESTIGATION` (fail closed).

---

## 2. Inputs

### 2.1 Artifact inventories

Zero or more **Inventory** records (see `internal/inventory`), one per binary
in the artifact under analysis. Each inventory is authoritative for:

- `format`, `stripped`, `static_linked`
- `dyn_syms`, `symtab` (symbol tables)
- `ro_strings` (read-only data strings)
- parse outcome (`format != Unknown` means parse succeeded)

### 2.2 SBOM / finding

One **Finding**:

| Field | Meaning |
|-------|---------|
| `cve` | CVE identifier (case-insensitive) |
| `component_purl` | PURL string claiming the vulnerable component |

The finding’s PURL is matched against Manifest component PURLs using graded
**MatchQuality** (`internal/purl`): `none < name_only < name_version_only <
type_normalized < exact`.

### 2.3 Manifest

Loaded Lading Manifest (`manifest.Load`). Provides:

- Component identity: `identity_symbols`, `identity_strings`
- Per-CVE entries with `vulnerable_symbols[]` and `confidence`

Only `confidence: definitive` symbols may support `NOT_AFFECTED` via D02.
`confidence: probable` symbols are reporting-only (see D03).

---

## 3. Output

Every evaluation emits one **Result**:

```yaml
verdict: NOT_AFFECTED | AFFECTED | UNDER_INVESTIGATION
justification: component_not_present | vulnerable_code_not_present | ""
rule_id: D01 | D02 | D03 | D04
reason_code: ""            # non-empty only for UNDER_INVESTIGATION / D03
manifest_version: "<semver+hash from Manifest.Version()>"
tool_version: "evidence-v1"
inputs_used:
  cve: CVE-YYYY-NNNNN
  component_purl: "<canonical or raw finding PURL>"
  manifest_component: "<name or empty>"
  purl_match_quality: exact | type_normalized | name_version_only | name_only | none
  inventories: ["<path or id>", ...]
  definitive_symbols_checked: ["sym", ...]
  symbols_observed: ["sym", ...]
  component_inventories: ["<inv id where component identified>", ...]
```

**Hard requirements:**

- Every result **must** cite `rule_id`.
- `NOT_AFFECTED` **must** include a non-empty `justification` (`component_not_present`
  or `vulnerable_code_not_present`).
- `UNDER_INVESTIGATION` **must** include a non-empty `reason_code`.
- `AFFECTED` **must** leave `justification` and `reason_code` empty.

---

## 4. Derived facts

Implementations **must** compute these deterministically before applying rules.

### 4.1 PURL match

For the finding PURL `F` and each Manifest component `C`, compute
`Equivalent(F, C.purls[i])` and take the **maximum** MatchQuality across all
PURLs. The winning component is `manifest_component`. If no component reaches
at least `name_version_only`, `manifest_component` is empty.

Record `purl_match_quality`.

### 4.2 Usable symbol table

Inventory `I` has a **usable symbol table** iff:

1. `I.format != Unknown` (parse succeeded), and
2. NOT (`I.stripped AND I.static_linked`), and
3. `len(I.dyn_syms) > 0` OR (`NOT I.stripped` AND `len(I.symtab) > 0`).

If **no** inventory has a usable symbol table → D03 `symbol_table_unusable`.

### 4.3 Component identified

Component `C` is **identified in inventory `I`** iff any of:

- A normalized/raw symbol in `I.dyn_syms ∪ I.symtab` equals an entry in
  `C.identity_symbols`, or
- An `I.ro_strings` entry matches any `C.identity_strings` regex.

**Artifact-level:** `C` is identified in the artifact if identified in **any**
inventory.

Record `component_inventories`: sorted list of inventory IDs/paths where `C`
is identified.

### 4.4 Observable symbols

For inventory `I`, the **observable symbol set** is all `normalized` and `raw`
names from `I.dyn_syms` and `I.symtab` (imports and exports both count).

Union across inventories for artifact-level checks.

### 4.5 Manifest CVE entry

Look up `cve` in Manifest. Select the entry whose `component_name` equals
`manifest_component`. If none → no entry.

Collect **definitive symbols**: vulnerable symbols with `confidence: definitive`.
Collect **probable-only** flag: entry exists but zero definitive symbols.

### 4.6 Symbol presence

A definitive symbol `S` is **present** in the artifact if `S` (normalized) is
in the observable symbol set of **any** inventory.

**Important:** Undefined dynamic imports (`defined: false` in `dyn_syms`) **do**
count as present. A vulnerable function visible only as an import is **not**
`vulnerable_code_not_present`.

### 4.7 Stripped / static gate (D02 and D03)

For each inventory where `C` is identified:

| Condition | Effect |
|-----------|--------|
| `stripped AND static_linked` | D03 `stripped_static_binary` |
| `stripped AND NOT static_linked` AND `len(dyn_syms)==0` | D03 `stripped_insufficient_dynsym` |
| otherwise | eligible for D02 absence claim on that inventory |

D02 requires **every** component-carrying inventory to pass this gate.

---

## 5. Rules

Evaluate in **two phases**: Phase A (D03 refusals), Phase B (decisive rules).
**D03 always beats D01/D02/D04.**

### D03 — REFUSAL: insufficient evidence

If **any** condition holds, emit `UNDER_INVESTIGATION` with the listed
`reason_code` and stop. Evaluate top-to-bottom; first match wins.

| ID | Condition | `reason_code` |
|----|-----------|---------------|
| D03a | `purl_match_quality` is `none` or `name_only` | `purl_match_insufficient` |
| D03b | No Manifest CVE entry for `(cve, manifest_component)` | `manifest_no_entry` |
| D03c | Entry exists but has zero definitive symbols (probable-only or empty) | `manifest_probable_only` |
| D03d | No inventory has a usable symbol table | `symbol_table_unusable` |
| D03e | Any component-carrying inventory is `stripped AND static_linked` | `stripped_static_binary` |
| D03f | Any component-carrying inventory is `stripped`, not static, and `len(dyn_syms)==0` | `stripped_insufficient_dynsym` |
| D03g | `purl_match_quality == name_version_only`, `manifest_component` resolved, **no** inventory identifies `C`, and entry exists | `identity_unverified` |

**Rationale (D03g):** SBOM/manifest agree on component identity at name/version,
but binary identity markers are absent. A vendored or renamed build cannot be
distinguished from true absence without stronger evidence → refuse (never
`component_not_present`).

**Default:** If Phase B would apply but ambiguity remains, emit D03 with
`reason_code: default_insufficient`.

### D04 — AFFECTED

After D03 passes:

- `manifest_component` is identified in the artifact, **and**
- At least one definitive vulnerable symbol is **present**.

→ `AFFECTED`, `rule_id: D04`.

### D02 — NOT_AFFECTED / vulnerable_code_not_present

After D03 passes, D04 does not apply:

- `manifest_component` identified in the artifact, **and**
- Manifest entry has ≥1 definitive symbol, **and**
- **None** of those definitive symbols are present in the artifact, **and**
- Every component-carrying inventory passes the stripped/static gate (§4.7).

→ `NOT_AFFECTED`, `justification: vulnerable_code_not_present`, `rule_id: D02`.

### D01 — NOT_AFFECTED / component_not_present

After D03 passes, D04/D02 do not apply:

- `manifest_component` is **not** identified in any inventory, **and**
- At least one inventory has a usable symbol table, **and**
- `purl_match_quality >= type_normalized`.

→ `NOT_AFFECTED`, `justification: component_not_present`, `rule_id: D01`.

### D05 — Forbidden justifications (non-rule)

The following VEX prove-a-negative justifications **must not exist** in any
emitter or decision code path:

1. `vulnerable_code_not_in_execute_path`
2. `vulnerable_code_cannot_be_controlled_by_adversary`
3. `inline_mitigations_already_exist`

There is **no** rule, constant, or branch that emits them. Verify with a static
test grepping `internal/decide`, `internal/vexout`, `internal/evidence`, and
`cmd/lading` sources.

---

## 6. Precedence summary

```
Phase A: D03 (any refusal) → UNDER_INVESTIGATION
Phase B:
  D04 (vuln symbol present) → AFFECTED
  D02 (component present, vuln symbols absent, gates pass) → NOT_AFFECTED / vulnerable_code_not_present
  D01 (component absent, usable inventory, strong PURL) → NOT_AFFECTED / component_not_present
  else → UNDER_INVESTIGATION / default_insufficient
```

**When in doubt, refuse.**

---

## 7. Near-miss reference outcomes

These scenarios **must** resolve conservatively in conformance tests:

| Scenario | Expected |
|----------|----------|
| Component absent in binary A, present in binary B with vuln symbol | `AFFECTED` (D04) |
| Vulnerable symbol present as undefined import | `AFFECTED` (D04) — not `vulnerable_code_not_present` |
| Vulnerable symbol absent but carrying binary is stripped+static | `UNDER_INVESTIGATION` (D03e) |
| Vendored/renamed component (PURL match, identity absent) | `UNDER_INVESTIGATION` (D03g) — never D01 |

---

## 8. Conformance fixtures

Minimum **8 fixtures per rule** (D01–D04) under `testdata/decide/`. Each
fixture is a complete tuple:

`(inventories, finding, manifest slice, expected result)`

Include deliberate near-misses from §7. **≥40 fixtures** must pass.

D05 is validated by the forbidden-string grep test, not fixture count.

---

## 9. Non-goals (evidence-v1)

- Version-range matching (Manifest uses exact versions only in v1).
- Path/exploitability analysis (forbidden justifications in §5 D05).
- Auto-promotion of Manifest `probable` symbols.
- Cross-artifact correlation beyond supplied inventories.

---

## 10. Versioning

| Field | Value |
|-------|-------|
| Spec ID | `evidence-v1` |
| Tool constant | `evidence-v1` (recorded in every result’s `tool_version`) |

Future incompatible rule changes require a new spec ID (e.g. `evidence-v2`).
