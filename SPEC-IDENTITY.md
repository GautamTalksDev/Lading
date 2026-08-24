# LADING Identity Resolution Specification — `identity-v1`

> **License:** [Creative Commons Attribution 4.0 International (CC-BY-4.0)](https://creativecommons.org/licenses/by/4.0/).
> You may implement this specification without reading the LADING Go source. Attribute:
> **LADING identity-v1 spec** with a link to this repository.

**Version:** `identity-v1`  
**Scope:** Resolve scanner-reported **distro package identities** to **upstream
component identities** so the evidence engine (`evidence-v1`) can evaluate real
findings. No LLM calls, embeddings, probabilities, or network I/O at evaluation
time.

**Status:** Specification only. No implementation ships under this document ID.

**Normative dependencies:** [SPEC-EVIDENCE.md](SPEC-EVIDENCE.md) (`evidence-v1`),
[SPEC-MANIFEST.md](SPEC-MANIFEST.md), CP-3 PURL equivalence rules
(`internal/purl` behavior as specified in evidence-v1 §4.1).

---

## Problem statement

Scanners report findings against **distro package identities**, for example:

- `pkg:deb/debian/zlib1g@1:1.2.11.dfsg-2`
- `pkg:apk/alpine/openssl-libs@3.1.4-r5`
- `pkg:rpm/rocky/openssl@1:1.1.1k-7.el8_6`

The Manifest carries **upstream component identities**, for example:

- `pkg:generic/zlib@1.2.11`
- `pkg:generic/openssl@3.0.7`

Without a resolution layer, CP-3 cross-type PURL equivalence caps at
`name_version_only`. The evidence engine correctly refuses: distro and generic
types disagree, so match quality never reaches `type_normalized`, D03 fires, and
symbol rules never run.

That is what produced **0 / 10,088** decided findings in the CP-11 corpus run
(`corpus/results/aggregate.json`: 10,088 CVE rows in, 10,088 refused, 100%
`purl-insufficient` in scan summaries). This is an **instrument gap**, not a
measure of firmware reachability.

`identity-v1` defines the curated mapping layer that closes this gap **without**
weakening the clearance bar that KT-2 depends on.

---

## 1. The mapping record

### 1.1 Layout

```
identity/
  VERSION                          # semver of this Identity release
  schema/
    mapping.schema.json            # normative JSON Schema
  mappings/
    <distro>/
      <distro_package>.yaml        # one file per binary-package mapping
```

Each file describes **one binary package name on one distro family** mapping to
**one upstream component PURL** (`pkg:generic/...` in v1).

### 1.2 Record shape

```yaml
distro: debian                    # debian | ubuntu | alpine | rhel | rocky | suse | ...
distro_package: libssl3           # binary package name as scanners emit it
source_package: openssl           # distro source package name (from control/APKBUILD/spec)
upstream_purl: pkg:generic/openssl
version_relationship: debian_upstream_from_version
confidence: definitive            # definitive | probable — see §4 for promotion
provenance:                       # schema in §4.2; definitive requires full block
  artifact_sha256: "<64-hex of extracted package binary>"
  distro: debian
  package_name: libssl3
  package_version: "3.0.17-1~deb12u2"
  verified_at: "2026-08-24"
  binary_path: "usr/lib/x86_64-linux-gnu/libssl.so.3"
  identity_symbols_verified: ["SSL_CTX_new"]
  extraction_method: dpkg-deb-extract
  reviewed_by: your-handle
  url: https://sources.debian.org/src/openssl/   # locator only — not evidence (§4.1)
notes: >
  Optional free text (e.g. "libssl3 is the OpenSSL 3.x userspace ABI package on Debian 12+").
identity_version: "1.0.0"
```

### 1.3 Required fields

| Field | Required | Meaning |
|-------|----------|---------|
| `distro` | yes | Distro family key. Must match the namespace segment scanners use in distro PURLs (`debian`, `alpine`, `rocky`, …). |
| `distro_package` | yes | Binary package name exactly as it appears in grype/Trivy/SBOM PURLs. |
| `source_package` | yes | Distro source package providing the upstream tarball (from `debian/control` `Source:`, APKBUILD `pkgname` source, RPM `Source0` lineage, etc.). |
| `upstream_purl` | yes | Canonical upstream identity **without version** (`pkg:generic/<name>`) or with a pinned template version when the mapping is version-specific (see §2). |
| `version_relationship` | yes | Algorithm ID for deriving upstream version from distro version (§2). |
| `confidence` | yes | `definitive` or `probable` (§4). |
| `provenance` | yes (object) | Provenance block (§4.2). Probable may be partial; definitive MUST be complete. |
| `identity_version` | yes | Semver of the identity release when the record was written. |

**Definitive provenance fields** (required only when `confidence: definitive` — full table in §4.2):
`artifact_sha256`, `distro`, `package_name`, `package_version`, `verified_at`,
`binary_path`, `identity_symbols_verified`, `extraction_method`, `reviewed_by`.

### 1.4 Validation rules (same spirit as Manifest)

1. **Definitive without complete provenance → schema invalid.** Loader refuses the entry (§4.3).
2. **Nothing automated may write `confidence: definitive`.** CI MUST reject PRs where
   `reviewed_by` is a bot account or `extraction_method` is denylisted (§4.2).
3. **Probable records are loadable** but MUST NOT enable clearance (§4.4).
4. `debian/control`, changelogs, and `upstream=` are **not** promotion evidence (§4.1).
5. `Identity.Version()` returns `semver+contentHash` over `VERSION` and all mapping files.
6. Duplicate `(distro, distro_package)` keys across files → load error.
### 1.5 Lookup key

Given finding PURL `F`:

1. Parse `F` with CP-3 canonicalization.
2. If `F.Type ∉ {deb, apk, rpm}` → identity layer **does not apply**; pass `F` through unchanged.
3. Otherwise lookup `(F.Namespace_or_distro_family, F.Name)` in the identity store.
   - For `pkg:deb/debian/libssl3@…`, key = `(debian, libssl3)`.
   - For `pkg:rpm/rocky/openssl@…`, key = `(rocky, openssl)`.

---

## 2. Version relationship semantics

Distro versions are not upstream versions. Implementations MUST NOT treat raw
equality of version strings across types as evidence.

### 2.1 Relationship algorithms (`version_relationship`)

| ID | Applies to | Rule |
|----|------------|------|
| `exact_upstream_in_qualifier` | deb/rpm when grype emits `upstream=` qualifier | Use qualifier value verbatim after normalization (strip `.src.rpm`, epoch prefix). If qualifier absent → **underivable** (§2.3). |
| `debian_upstream_from_version` | Debian/Ubuntu `.deb` | Parse binary version per Debian policy: strip epoch (`1:`), take upstream portion before first `-` ( Debian revision ), then apply upstream-specific normalization table (§2.2). Example: `3.0.17-1~deb12u2` → `3.0.17`. |
| `alpine_upstream_frompkgver` | Alpine APK | From `pkgver` in APKBUILD lineage: strip `-r<N>` revision suffix. Example: `3.1.4-r5` → `3.1.4`. |
| `rpm_upstream_from_nvr` | RPM | Split NVR: remove distro release tag (`-7.el8_6`), remove epoch prefix if present. Example: `1:3.0.7-25.el9` → `3.0.7`. |
| `pinned_mapping` | Any | Mapping record fixes upstream version literally in `upstream_purl` (`pkg:generic/foo@2.4.7`). Finding version MUST match after distro parse or → underivable. Used for split/ABI packages where binary version does not track upstream. |

### 2.2 Upstream normalization table (deterministic)

After distro parsing, apply **in order**:

1. URL-decode percent escapes.
2. Strip Debian `dfsg`, `really`, `ubuntu` cosmetic suffixes from upstream segment only when attached with `+` or `.` (regex: `(?i)(?:[+.]?(?:dfsg|really|ubuntu)[^.-]*)$`).
3. Collapse duplicate separators; trim trailing `.`.
4. Compare to Manifest `affected_versions` entries by **exact string match only** (evidence-v1 rule — no ranges).

### 2.3 Underivable version

`version_underivable` when **any** holds:

- Required qualifier (`upstream=`) missing and algorithm is `exact_upstream_in_qualifier`.
- Parsed version contains `%` or unbalanced parentheses after decode (corrupt input).
- Multiple conflicting upstream candidates (e.g. Debian version with two `:` epochs).
- `pinned_mapping` and parsed upstream ≠ pinned version.
- Algorithm ID unknown to loader.

**Behavior:** Emit D03 `version_underivable` (§7). Do **not** guess a version.

### 2.4 Resolved upstream PURL

When derivation succeeds, construct:

```
resolved_purl = upstream_purl + "@" + derived_upstream_version
```

(with canonical formatting). All subsequent Manifest matching uses `resolved_purl`
as the **effective finding identity**, while preserving `finding_purl` (raw scanner
input) in the result and bundle.

---

## 3. The backport problem

Distros routinely **backport security fixes** without changing the upstream
version segment visible in the package version.

**Example:** Debian ships `1.2.11-1+deb11u2` for zlib. The upstream version
derived by §2.1 is still **`1.2.11`**. The Manifest lists `1.2.11` as affected
for CVE-2018-25032. The distro package may already contain the backported fix.

### 3.1 What LADING does (conservative default)

`identity-v1` **does not** infer backport status from distro revision tags (`deb11u2`,
`el9_4`, Alpine `-r5`). Revision metadata is not modeled as upstream version
change.

Therefore:

- If derived upstream version matches a Manifest `affected_versions` entry and
  vulnerable symbols are **absent**, engine may emit `NOT_AFFECTED` (D02) — same as today.
- If derived upstream version matches affected and vulnerable symbols **are present**,
  engine emits `AFFECTED` (D04) — even when a backport may have removed the bug
  without changing symbol layout.

### 3.2 Risk direction

A missed backport annotation causes **over-reporting** (`AFFECTED` or continued
investigation), **not** a false `not_affected`. That is the safe direction for
KT-2.

### 3.3 What evidence would be needed to clear a backported-fixed package

Any `NOT_AFFECTED` claim when distro revision suggests a security upload MUST
rely on **symbol-level evidence** (D02: definitive vulnerable symbols absent) or
**component absence** (D01), never on "the distro fixed it" alone.

Future spec (not identity-v1) could add **explicit backport records** under
`identity/backports/` with:

- `(distro, distro_package, exact_debian_version)` → `fixes_cve: [CVE-…]`
- provenance URL to Debian `DSA-*` / Red Hat errata / Alpine secfixes
- `confidence: definitive` + human review

Until such a record exists, backport status is **unknown** and symbol rules apply
to the derived upstream version only.

---

## 4. Promoting an alias from `probable` to `definitive`

This section is the **promotion standard**. Another engineer MUST be able to
apply it without inventing rules to suit a particular dataset. CP-15b MUST NOT
land until this section is satisfied in both the written schema and the loader
validation tests.

### 4.1 Requirement (apply in order; all five are mandatory)

To set `status: definitive` (or YAML `confidence: definitive`) on an identity
alias, **all** of the following MUST be true:

1. **Real distro package binary.** A real binary MUST be extracted from the
   **actual distro package** named by the mapping (the `.deb` / `.apk` / `.rpm`
   / equivalent that scanners name). A container layer export, a source tree,
   an upstream tarball, or a hand-built object is **not** acceptable.
2. **Symbol verification.** Every entry in the mapping's
   `identity_symbols` / `identity_symbols_verified` list MUST be verified
   present in that binary's symbol table (`.dynsym` and/or `.symtab`, as
   observed by LADING inventory — not by reading package metadata).
3. **Recorded provenance.** The alias entry's `provenance` block MUST record
   the artifact `sha256`, the distro, the package name, the package version,
   and the verification date (`verified_at`, ISO `YYYY-MM-DD`).
4. **Metadata is not evidence.** A `debian/control` file, a changelog, a
   copyright file, an APKBUILD/`Source0` line, or **any third-party assertion**
   (advisory text, SBOM property, wiki page, mailing-list claim) is
   **explicitly NOT sufficient** to promote. Those documents may help a
   reviewer *locate* the right package; they never substitute for steps 1–3.
5. **`upstream=` is never evidence.** The grype-supplied `upstream=` PURL
   qualifier is a **third-party assertion**. It MAY only narrow which Manifest
   component to consult when choosing a candidate mapping. It is **never**
   evidence that the mapping is correct and **MUST NOT** appear as the sole
   or decisive basis for `definitive`.

If any of (1)–(5) cannot be met, the alias remains `probable` (or is refused
as a candidate). There is no partial-definitive status.

### 4.2 Provenance block schema

Every identity alias record carries a `provenance` object. **Probable**
aliases MAY leave verification fields empty. **Definitive** aliases MUST
populate every required field below; the loader fails closed otherwise.

```yaml
provenance:
  # Required for status: definitive (all of these):
  artifact_sha256: "<64-hex SHA-256 of the extracted binary file>"
  distro: debian                    # distro family key (debian|ubuntu|alpine|rhel|…)
  package_name: libexpat1           # binary package name as scanners emit it
  package_version: "2.5.0-1+deb12u1"
  verified_at: "2026-08-24"         # ISO date YYYY-MM-DD of the binary verification
  binary_path: "usr/lib/x86_64-linux-gnu/libexpat.so.1.8.10"
  identity_symbols_verified:        # non-empty; each present in that binary's symbol table
    - XML_ParserCreate
  extraction_method: dpkg-deb-extract   # see allowlist below
  reviewed_by: your-handle

  # Optional (never sufficient alone):
  url: https://sources.debian.org/src/expat/   # locator only — not evidence
  notes: "optional free text"
```

**JSON field names** (loader / `identity-aliases.json`):

| Field | Type | Definitive required |
|-------|------|---------------------|
| `artifact_sha256` | string, 64 lowercase hex | yes |
| `distro` | non-empty string | yes |
| `package_name` | non-empty string | yes |
| `package_version` | non-empty string | yes |
| `verified_at` | `YYYY-MM-DD` | yes |
| `binary_path` | non-empty path relative to package root | yes |
| `identity_symbols_verified` | non-empty string array | yes |
| `extraction_method` | allowlisted string (below) | yes |
| `reviewed_by` | non-empty string | yes |
| `url` | optional `http(s)` locator | no |
| `notes` | optional string | no |

**`extraction_method` allowlist** (definitive only):

| Value | Meaning |
|-------|---------|
| `dpkg-deb-extract` | Binary taken from a `.deb` via `dpkg-deb -x` (or equivalent unpack of that `.deb`) |
| `apk-extract` | Binary taken from an Alpine `.apk` package archive |
| `rpm2cpio-extract` | Binary taken from an `.rpm` via `rpm2cpio` / `rpm -qp --filesbypkg` unpack |
| `pacman-extract` | Binary taken from an Arch `.pkg.tar.*` package |

**`extraction_method` denylist** (always invalid for `definitive`):

| Value / pattern | Why |
|-----------------|-----|
| `debian-control`, `control-file`, `changelog`, `copyright` | Package metadata — not a binary |
| `apkbuild`, `rpm-spec`, `source-tree` | Build recipe / source — not the shipped binary |
| `container-layer`, `oci-export`, `docker-save` | Container layer — not the named distro package |
| `grype-upstream`, `upstream-qualifier`, `sbom-assertion`, `third-party` | Third-party assertion — never evidence |
| `automated-scrape` | Automation MUST NOT write definitive |

Unknown methods → load error (fail closed). Extend the allowlist only by
spec amendment, never by silent loader tolerance.

### 4.3 Loader validation (fail closed)

1. `status` / `confidence` MUST be `definitive` or `probable`.
2. If `probable`: provenance may be partial; missing verification fields are OK.
3. If `definitive`: **every** required provenance field in §4.2 MUST be present
   and well-formed; `extraction_method` MUST be allowlisted; denylisted methods
   MUST reject. Incomplete provenance → **schema invalid** (loader refuses the
   file / entry).
4. Nothing automated may write `status: definitive`. CI MUST reject PRs where
   `reviewed_by` is a bot account or `extraction_method` is denylisted.
5. `provenance.url` alone NEVER upgrades probable → definitive.

### 4.4 What definitive enables (clearance safety)

> Can a distro-mapped identity reach a `NOT_AFFECTED` verdict (D01 or D02) on
> weaker evidence than a direct PURL match?

**No.** A distro-mapped identity may feed D01/D02 **only** when:

1. The mapping record has `status: definitive` (and therefore satisfied §4.1–§4.3), **and**
2. Upstream version derivation succeeded (not `version_underivable`), **and**
3. All existing evidence-v1 gates still pass (Manifest entry, definitive symbols,
   stripped/static gates, D03g identity verification).

`status: probable` mappings **must never** enable D01, D02, or D04. They may
only replace a coarse refusal with a **more specific refusal reason**
(`mapping_probable_only`) for reporting clarity.

Direct PURL match at `type_normalized` or `exact` without a mapping hop is
unchanged. A mapping hop MUST NOT produce a **stronger** match quality than
`identity_mapped` (§5).

### 4.5 Reasoning

KT-2 proves the engine does not emit false `not_affected` when given **controlled
fixtures with explicit PURLs**. The dominant failure mode of a loose identity
layer is **false clearance**: mapping `libssl3` to the wrong upstream, mapping a
compat package to the wrong major, or accepting scraped metadata as definitive —
each turns D01/D02 into a guess.

Probable mappings are useful for prioritizing curator work ("this refusal is
likely openssl, not truly unknown") but must not shorten the evidence path to
clearance. Promotion without a verified package binary would recreate that
failure mode under a different name.

### 4.6 False-negative risk (plain language)

**False negative** here means: a CVE is actually exploitable in the shipped
binary, but LADING emits `NOT_AFFECTED`.

Under this spec, the false-negative risk from identity mapping is:

- **Low for wrong-package mapping leading to clearance:** blocked — definitive
  requires human-reviewed binary+symbol provenance (§4.1); wrong mapping is a
  curator error, not automation.
- **Non-zero for correct-package mapping:** if upstream version is derived as
  `3.0.7`, Manifest lists that version affected, but the **distro backport removed
  the bug while symbols unchanged**, D02 could still clear on absent symbols
  (existing evidence-v1 behavior). identity-v1 does not add new clearance paths;
  it only opens the door to **asking** the symbol question.
- **Higher if probable mappings were allowed to clear:** **rejected by this spec.**
  That would let "likely openssl" become `component_not_present` without proving
  component absence — the primary KT-2 failure mode.
- **Higher if metadata/`upstream=` could promote:** **rejected by §4.1 items 4–5.**

**Net:** identity-v1 trades "refuse everything" for "ask symbol questions on
curated, binary-verified mappings." It does **not** trade clearance rigor for coverage.

---

## 5. New MatchQuality semantics

CP-3 defines:

```
none < name_only < name_version_only < type_normalized < exact
```

`identity-v1` adds **`identity_mapped`** without collapsing it into `exact` or
`type_normalized`:

```
none < name_only < name_version_only < type_normalized < identity_mapped < exact
```

### 5.1 Definition

`identity_mapped` applies when **all** hold:

1. Raw finding PURL `F` is distro-scoped (`deb` / `apk` / `rpm`).
2. A mapping record `(distro, F.Name)` with `confidence: definitive` produced
   `resolved_purl` `R`.
3. `Equivalent(R, C.purls[i])` for some Manifest component `C` is
   `type_normalized` or `exact`.
4. No digest conflict between `F` and `R`.

`identity_mapped` is **not** `exact`: the scanner did not claim `pkg:generic/…`
directly. Auditors MUST see the mapping hop.

### 5.2 Gate behavior

| Gate | Rule |
|------|------|
| D01 requires `purl_match_quality >= type_normalized` | `identity_mapped` satisfies (`.AtLeast(type_normalized)` is true). |
| D03a (`purl_match_insufficient`) | Fires when quality is `none` or `name_only` **before** resolution; after failed resolution use §7 codes. |
| Evidence bundle | MUST record both `finding_purl`, `resolved_purl`, and `purl_match_quality: identity_mapped`. |

### 5.3 API requirement

Implementations MUST expose `identity_mapped` as its own string in JSON results
and bundles — never report it as `type_normalized` or `exact`.

---

## 6. Evidence bundle impact

### 6.1 New file: `identity-slice.json`

Verdicts that used identity resolution MUST embed **`identity-slice.json`** in
the statement directory (alongside existing `manifest-slice.json`):

```
evidence-bundle/statements/<id>/
  statement.json
  inputs.json
  observations.json
  manifest-slice.json
  identity-slice.json          # NEW — required when purl_match_quality is identity_mapped
  versions.json
```

**Why not only manifest-slice.json:** Manifest slices describe CVE↔symbol
knowledge. Identity slices describe **distro↔upstream** knowledge. Mixing them
blurs audit boundaries and complicates Manifest CC0 / identity licensing.

### 6.2 `identity-slice.json` shape

```json
{
  "identity_version": "1.0.0+abc123…",
  "finding_purl": "pkg:deb/debian/libssl3@3.0.17-1~deb12u2",
  "resolved_purl": "pkg:generic/openssl@3.0.17",
  "mapping": {
    "distro": "debian",
    "distro_package": "libssl3",
    "source_package": "openssl",
    "upstream_purl": "pkg:generic/openssl",
    "version_relationship": "debian_upstream_from_version",
    "derived_upstream_version": "3.0.17",
    "confidence": "definitive",
    "provenance": {
      "artifact_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "distro": "debian",
      "package_name": "libssl3",
      "package_version": "3.0.17-1~deb12u2",
      "verified_at": "2026-08-23",
      "binary_path": "usr/lib/x86_64-linux-gnu/libssl.so.3",
      "identity_symbols_verified": ["SSL_CTX_new"],
      "extraction_method": "dpkg-deb-extract",
      "reviewed_by": "…",
      "url": "https://sources.debian.org/src/openssl/3.0.17-1~deb12u2/"
    }
  },
  "purl_match_quality": "identity_mapped"
}
```

### 6.3 `lading verify` offline re-derivation

`lading verify` MUST:

1. Read `identity-slice.json` from the bundle (not from repo `identity/`).
2. Re-parse `finding_purl`, re-apply mapping record from slice, re-derive version.
3. Confirm `resolved_purl` matches slice.
4. Re-run evidence-v1 decision using embedded `manifest-slice.json`.

Verification succeeds **without** the repo `identity/` tree installed — same
air-gap guarantee as Manifest slices ([VERIFY.md](VERIFY.md)).

### 6.4 `inputs.json` additions

Add optional fields (non-breaking):

```json
{
  "finding_purl_raw": "pkg:deb/debian/libssl3@…",
  "resolved_purl": "pkg:generic/openssl@3.0.17",
  "identity_mapping_id": "debian/libssl3"
}
```

---

## 7. D03 reason code changes

### 7.1 New reason codes

| Code | Meaning |
|------|---------|
| `no_identity_mapping` | Finding is distro-scoped; no mapping record for `(distro, package)`. |
| `mapping_probable_only` | Mapping exists but `confidence: probable`; clearance forbidden. |
| `version_underivable` | Definitive mapping exists; upstream version derivation failed (§2.3). |

Existing codes unchanged, including `purl_match_insufficient` (spec) / `purl-insufficient` (scan summary alias).

### 7.2 Resolution phase (before evidence-v1 Phase A)

Insert **Phase 0 — Identity resolution**:

```
Phase 0:
  If F is not deb/apk/rpm → resolved_purl = F; skip to evidence-v1.
  Else lookup mapping:
    no record        → UNDER_INVESTIGATION / no_identity_mapping
    probable only    → UNDER_INVESTIGATION / mapping_probable_only
    definitive:
      derive version → fail → UNDER_INVESTIGATION / version_underivable
      success        → resolved_purl = R; continue

Phase A (evidence-v1 D03): unchanged, but PURL match uses resolved_purl
Phase B: unchanged
```

### 7.3 Precedence (first match wins)

When multiple conditions could apply, evaluate **top to bottom**:

| Order | Condition | `reason_code` |
|-------|-----------|---------------|
| 1 | Distro finding, no mapping | `no_identity_mapping` |
| 2 | Mapping `probable` only | `mapping_probable_only` |
| 3 | Definitive mapping, version underivable | `version_underivable` |
| 4 | `purl_match_quality` is `none` or `name_only` (after resolution) | `purl_match_insufficient` |
| 5 | No Manifest CVE entry | `manifest_no_entry` |
| 6 | Manifest probable-only symbols | `manifest_probable_only` |
| 7 | No usable symbol table | `symbol_table_unusable` |
| 8 | Stripped static binary gate | `stripped_static_binary` |
| 9 | Stripped insufficient dynsym | `stripped_insufficient_dynsym` |
| 10 | Identity unverified (D03g) | `identity_unverified` |
| 11 | Default | `default_insufficient` |

**Note:** For distro findings **without** definitive mapping, stop at order 1 — do
not fall through to `purl_match_insufficient`. That replaces the CP-11 blanket
`purl-insufficient` with a precise "mapping missing" signal.

---

## 8. Seeding plan

Counts derived from **`corpus/results/*/grype.json`** grype match rows (the intake
that produced **`corpus/results/aggregate.json` totals: 10,088 CVE rows in, 0
decided**). Only **`pkg:deb` / `pkg:apk` / `pkg:rpm`** rows are listed. Packages
were ranked among those mappable to **Manifest v1** native components (25 seed
components in `manifest/components/native/`).

Seeding these **10 mapping records first** covers the largest share of
**manifest-addressable** distro findings. They do **not** cover non-distro intake
(e.g. `pkg:golang/stdlib`, 2,265 rows) — out of scope for identity-v1.

| Rank | Distro package (PURL name) | Distro | CVE rows in corpus | Upstream (Manifest v1) |
|------|----------------------------|--------|-------------------:|------------------------|
| 1 | `libexpat1` | debian | 98 | libexpat |
| 2 | `curl` | debian | 94 | curl |
| 3 | `libcurl4` | debian | 94 | curl |
| 4 | `openssl` | debian | 91 | openssl |
| 5 | `libssl3` | debian | 87 | openssl |
| 6 | `libgnutls30` | debian | 57 | gnutls |
| 7 | `openssh-client` | debian | 57 | openssh |
| 8 | `libsqlite3-0` | debian | 49 | sqlite3 |
| 9 | `curl` | alpine | 42 | curl |
| 10 | `libssl3` | alpine | 36 | openssl |

**Subtotal:** 705 / 10,088 corpus CVE rows (**7.0%**) would at minimum pass Phase 0
identity resolution and reach Manifest/symbol gates (actual decide rate depends on
Manifest CVE coverage, symbol tables, and D03g — not guaranteed decided).

**Corpus context (aggregate.json):** 10,088 total CVE rows; 8,522 are deb/rpm/apk;
remaining rows are primarily `pkg:golang`, `pkg:npm`, `pkg:generic`, etc., which
identity-v1 does not resolve.

---

## 9. What identity-v1 explicitly does NOT do

1. **No version range inference.** Derived upstream versions match Manifest
   `affected_versions` by exact string only (evidence-v1 carry-over).
2. **No automated scraping into definitive records.** Scrapers may propose
   `confidence: probable` candidates for human review; they MUST NOT set
   `definitive` or `reviewed_by`.
3. **No cross-distro transitive mapping.** A Debian mapping does not auto-apply
   to Ubuntu, Rocky, or Alpine — each `(distro, distro_package)` requires its
   own record and provenance URL.
4. **No backport/errata inference** (§3). Security revision tags are ignored for
   version derivation.
5. **No golang/npm/pypi identity normalization.** Non-distro PURLs pass through
   unchanged; separate future specs if needed.
6. **No weakening of D03g.** Distro mapping does not bypass vendored/rename checks.
7. **No new VEX prove-a-negative justifications.** evidence-v1 D05 unchanged.

---

## 10. Conformance and KT re-run

### 10.1 Fixtures

Add under `testdata/identity/` (future implementation):

- Version derivation vectors per algorithm (§2.1).
- At least 8 cases per new D03 code (§7).
- Near-miss: probable mapping must not clear; wrong source package must not clear.

### 10.2 CP-11 re-run gate

Launch remains frozen ([launch/DO-NOT-PUBLISH.md](launch/DO-NOT-PUBLISH.md)) until:

1. identity-v1 implementation ships,
2. Seed mappings (§8) exist with `confidence: definitive`,
3. CP-11 corpus scan re-runs against the **unchanged** 30% KT-1 threshold.

KT-2 ground-truth fixtures MUST be re-run unchanged; any new failure blocks release.

---

## 11. Open questions

1. **Ubuntu namespace:** Scanners emit `pkg:deb/ubuntu/…`. Should Ubuntu reuse
   Debian `source_package` mappings automatically with a `distro: ubuntu` alias
   record, or require separate provenance URLs per suite?

2. **RPM naming split:** Rocky/Alma/RHEL share NVR patterns but differ in errata.
   Is `(rocky, openssl)` one record or three with copied provenance?

3. **Multi-upstream source packages:** Debian `ffmpeg` ships dozens of binaries;
   identity-v1 assumes 1:1 binary→upstream for v1 seed. Need a `provides`/`virtual`
   model?

4. **OpenWrt/apk edge cases:** OpenWrt uses `pkg:apk/openwrt/…` with different
   versioning (`rNNNN`). Algorithm catalog needs OpenWrt-specific ID?

5. **Pinned vs derived version conflicts:** When grype `upstream=` qualifier
   disagrees with `debian_upstream_from_version` parse, which wins? (Proposal:
   qualifier wins if present and valid; else derived; conflict → underivable.)

6. **identity-slice licensing:** Manifest is CC0; identity mappings may cite
   distro copyrighted control files. Confirm CC-BY for `identity/` with
   provenance URLs as attribution anchor?

7. **Manifest PURL cleanup:** Several v1 Manifest components already list distro
   PURLs in `component.purls[]` (e.g. `pkg:deb/debian/libssl3`). Should
   evidence-v1 stop matching those directly and require identity layer only, to
   keep a single audit path?

8. **Static binary findings (`pkg:generic` from grype on Go binaries):** 487+
   corpus rows on static-binary artifacts — identity-v1 silent. Is a separate
   `language-ecosystem-v1` spec required for KT-1 to exceed single digits?

---

## 12. Versioning

| Field | Value |
|-------|-------|
| Spec ID | `identity-v1` |
| Tool constant | Record in bundle `versions.json` alongside `evidence-v1` |

Incompatible mapping schema or MatchQuality ordering changes require a new spec ID
(e.g. `identity-v2`).

---

**STOP:** Review this document — especially **§4** — before any implementation.
Section 4 defines the probable→definitive promotion bar (binary + symbols +
recorded provenance; metadata/`upstream=` are not evidence). Without it, CP-15b
has no standard and clearance after mapping cannot stay KT-2-safe.
