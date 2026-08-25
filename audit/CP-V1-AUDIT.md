# CP-V1: Figure Provenance Audit

**Date:** 2026-08-25  
**Mode:** READ-ONLY. No published datasets, metrics, CSVs, decisions, or findings were modified.  
**Scope:** Locate ground truth for A1–A9. Do not reconcile figures.

**Session hygiene note (pre-existing, not introduced by this audit):**
`git status --porcelain` already showed `M launch/issues/trivy-001-comment-on-7850.md`
before any audit write. This audit created only `audit/CP-V1-AUDIT.md`. The DoD
porcelain check will fail until that unrelated dirty path is handled outside this
session. `git stash list` was empty.

---

## A1. Inventory totals

**Status: DISCREPANCY**

### Conflicting values

| Source | binaries | stripped | static_linked |
|--------|--------:|--------:|--------------:|
| `corpus/results/cp11-metrics.json` → `inventory` | **27670** | **22971** | **5194** |
| Sum of every data row in `results/binary-profile.csv` (54 rows) | **27658** | **22955** | **5191** |
| Delta (metrics − CSV) | **+12** | **+16** | **+3** |

### Writers / code paths

- **CSV:** `scripts/profile-corpus.sh` builds `scripts/profile-corpus` (`main.go`), which walks **`corpus/ARTIFACTS.yaml`** and writes `results/binary-profile.csv` (`writeCSV`, lines 532–554) and `PROFILE.md` (`oneSentence`, lines 611–658).
- **`cp11-metrics.json` inventory:** `scripts/compute-cp11-metrics.py` → `inventory_stats()` (lines 329–345) sums `binaries_scanned` / `stripped` / `static_linked` from every parseable `corpus/results/*/scan-summary.json` with size ≥ 2.

**They are not the same traversal.** Profile = catalog entries. Inventory telemetry = scan-result directories.

### Exact set difference (command output)

```text
CSV ids not in parseable scan-summary: ['bench-inventory-elves']
parseable scan-summary ids not in CSV: ['bin-cosign-2.2.4-single', 'bin-restic-0.16.4-single']
intersection mismatch: oci-alpine-3.20  csv=0/0/0  scan-summary=21/18/3
```

Arithmetic that produces the published +12 / +16 / +3:

| Term | binaries | stripped | static |
|------|--------:|--------:|------:|
| `+ oci-alpine-3.20` (scan-summary − CSV) | +21 | +18 | +3 |
| `+ bin-cosign-2.2.4-single` (scan only) | +1 | +0 | +1 |
| `+ bin-restic-0.16.4-single` (scan only) | +1 | +1 | +1 |
| `− bench-inventory-elves` (CSV only) | −11 | −3 | −2 |
| **Net** | **+12** | **+16** | **+3** |

There is **no list of twelve named binary paths**. The “12” is a **net count delta** across different row sets.

### Candidate checks

| Candidate | Ruled |
|-----------|-------|
| `oci-alpine-3.20` CSV prepare failure (0 binaries) | **In.** CSV note: `prepare:no payload in …/oci-alpine-3.20` (`binary-profile.csv` line 2). Downloads tree has empty `image.tar/` directory. Scan-summary still has 21/18/3 (`corpus/results/oci-alpine-3.20/scan-summary.json`). |
| 2 auxiliary rescan dirs (A4) | **In** for inventory, not CSV: `bin-cosign-2.2.4-single`, `bin-restic-0.16.4-single` (+1/+1 binaries). |
| `bench-inventory-elves` | **In** for CSV only (−11 binaries); class `benchmark`; absent from scan-summary set. |
| Double-count profile-rootfs vs inventory | **Not** the +12 mechanism. Intersection matches except alpine. |

### Authoritative value

- **For RESULTS.md / PAPER inventory telemetry (27670 / 22971 / 5194):** `inventory_stats()` over scan-summaries — `cp11-metrics.json` lines 666–669; source function `scripts/compute-cp11-metrics.py:329–345`.
- **For PROFILE.md / binary-profile stratum figures:** `results/binary-profile.csv` (and the profile tool that wrote it).

Published RESULTS inventory **does re-derive** from scan-summaries, **not** from summing `binary-profile.csv`.

---

## A2. D01 artifact count

**Status: DISCREPANCY**

### Conflicting values

- `d01_corpus_absence.artifacts_scanned` = **59** (`cp11-metrics.json` line 685).
- Every other published denominator in the same file / RESULTS: **55** (`kt1.artifacts_scanned`, RESULTS §5 table).
- Both OpenSSL ID arrays: length **22** and **19** (lines 688–733).

### Code path for 59

`d01_corpus_absence()` (`scripts/compute-cp11-metrics.py:295–301`) counts every directory under `corpus/results/` that **has a `scan-summary.json` file**, with **no size / parse filter**:

```295:301:scripts/compute-cp11-metrics.py
    scanned = sum(
        1 for d in RESULTS_DIR.iterdir() if d.is_dir() and (d / "scan-summary.json").is_file()
    )
```

KT-1 / aggregate use the stricter filter (size ≥ 2 + JSON parse) in `scripts/corpus-aggregate.py:41–46` → **55**.

### Which denominator does the D01 absence claim use?

The **substantive** D01 claim (OpenSSL package-match artifacts with/without `.so`) uses:

- selection pool = artifacts with openssl/libssl/libcrypto in `grype.json` → **22** IDs  
- among those, `find` for `libssl.so*` / `libcrypto.so*` → **0** without  

It does **not** use 59 as a rate denominator. The field `artifacts_scanned: 59` is a **directory census**, then RESULTS.md rewrites the prose denominator as **55**.

### The 59 − 55 = 4 extra directories (empty `scan-summary.json`, size 0)

```text
bin-jq-1.7.1-single
openwrt-23.05-x86-64-rootfs-oci-single
subst-httpd-alpine-single
subst-memcached-alpine-single
```

Verified: each has `scan-summary.json` of size 0 (`content=b''`).

### Authoritative value

- **D01 scientific claim:** 22 package-match / 0 without `.so` / 19 decisions-bound — arrays in `cp11-metrics.json` `d01_corpus_absence`.
- **`artifacts_scanned: 59`:** literal empty-file-inclusive census; **not** the same 55 used elsewhere. Do not treat 59 as the kill-test artifact count.

Published RESULTS D01 section uses **55**, which does **not** re-derive from `d01_corpus_absence.artifacts_scanned`.

---

## A3. Stratum grouping for stripped/static figures

**Status: CONFIRMED** (PROFILE grouping) · firmware triple **CONFIRMED**

### PROFILE.md claim

> firmware stripped 75% / static 43% vs containers stripped 97% / static 3%

### Code that defines “containers”

`scripts/profile-corpus/main.go` `oneSentence()` (lines 626–627) and the comment at line 600:

```600:627:scripts/profile-corpus/main.go
	// Container stratum = oci-base + oci-app + substitute-container
	...
	cb, cs, cst := sum("oci-base", "oci-app", "substitute-container")
```

Also prints `firmware vs container(oci+subst)` at lines 605–608.

### Recompute from `results/binary-profile.csv`

| Grouping | binaries | stripped % | static % |
|----------|--------:|----------:|---------:|
| oci-app + oci-base only | 17422 | 97.8% | 1.5% |
| **oci-* + substitute-container (PROFILE)** | **18724** | **96.6% → rounds to 97%** | **2.7% → rounds to 3%** |
| firmware | **4236** | **75.5% → 75%** | **42.9% → 43%** |

`%.0f` formatting in `oneSentence` produces the published integers.

### Authoritative value

PROFILE.md’s “containers” = **oci-base + oci-app + substitute-container**.  
Firmware **4236 / 75.5% / 42.9%** confirmed from CSV; published 75% / 43% are rounding.  
Published PROFILE figures **re-derive** from `binary-profile.csv` via that grouping — **not** from `cp11-metrics.json` inventory.

---

## A4. The `unknown` class

**Status: DISCREPANCY** (denominator composition) · identity of dirs **CONFIRMED**

### The two directories

From `corpus/results/aggregate.json` / `cp11-metrics.json` `by_class.unknown`:

| Directory | class assignment | cves_in | decisions.jsonl |
|-----------|------------------|--------:|-----------------|
| `bin-cosign-2.2.4-single` | `unknown` | **144** | **absent** |
| `bin-restic-0.16.4-single` | `unknown` | **109** | **absent** |
| **Sum** | | **253** | 0 decided |

Assignment path: `scripts/corpus-aggregate.py:48` — `classes.get(aid, "unknown")` because these IDs are **not** in `ARTIFACTS.yaml`.

RESULTS.md line 24: “55 result directories … (includes **2 auxiliary single-binary re-scan dirs**)” — **same two**.

### Are the 253 inside 15641 / 15385 / only scan-summary?

Arithmetic (actual command totals):

```text
sum cves_in over 55 parseable scan-summaries = 15641
sum decisions.jsonl rows                   = 15385
gap                                        = 256
unknown cves (144+109)                     = 253
oci-alpine-3.20 cves (also no decisions)   = 3
253 + 3                                    = 256
```

- **Inside 15641:** **YES** — both unknown dirs’ `cves_in` are summed into KT-1 `cves_in` via aggregate.
- **Inside 15385:** **NO** — no `decisions.jsonl` for either dir; they never enter the stage histogram.
- **scan-summary only:** their CVE counts live in `scan-summary.json` (and are copied into aggregate refused via summary fields).

### KT-1 denominator implication (plain statement)

**Yes: the pre-registered KT-1 coverage denominator 15,641 includes 253 findings from two directories that are not product artifacts in `ARTIFACTS.yaml`.**  
Product catalog claims **53** product artifacts; scanned dirs **55** = 53 + these 2.  
Excluding unknown: 15641 − 253 = **15388** (still not equal to 15385; alpine’s 3 remain).

This is a **corpus-composition limitation**, not rounding.

### Authoritative value

- Identity of the two dirs: aggregate / metrics `by_class.unknown`.
- KT-1 `cves_in=15641` as published **does** include them by construction of `corpus-aggregate.py`.

---

## A5. The 256-row gap

**Status: DISCREPANCY** (RESULTS “10 artifacts” attribution) · gap size **CONFIRMED**

### Conflicting claim vs evidence

RESULTS.md line 185 attributes 15641 − 15385 = **256** to “**10** zero/low-finding artifacts lack `decisions.jsonl`”.

### Actual artifacts lacking `decisions.jsonl` (and their cves_in)

| Artifact | cves_in | Overlap with A4? |
|----------|--------:|------------------|
| `bin-cosign-2.2.4-single` | 144 | **yes** (unknown) |
| `bin-restic-0.16.4-single` | 109 | **yes** (unknown) |
| `oci-alpine-3.20` | 3 | no (product `oci-base`, but no decisions file) |
| **Sum** | **256** | |

**Three** artifacts, not ten. They **do** sum to 256. They **do** overlap A4 for 253 of the 256.

### Where “10” comes from

```text
no decisions.jsonl file:              3  (cves sum 256)
decisions.jsonl exists but 0 rows:    7  (all cves_in=0)
3 + 7 = 10
```

The seven empty decision files (`arm-gnu-toolchain`, `bin-bat-0.24.0`, `bin-fd-10.2.0`, `bin-jq-1.7.1`, `bin-ripgrep-14.1.0`, `oci-amazonlinux-2023`, `zephyr-sdk-0.16.5`) contribute **0** to the 256 gap.

### KT-1 vs stage histogram mixing

| Figure | Denominator | Intent in RESULTS |
|------|-------------|-------------------|
| KT-1 decided rate 5 / 15641 | scan-summary aggregate | intentional |
| Refusal-stage table | decisions.jsonl n=15385 | intentional |
| RESULTS §4 “10 artifacts” prose | conflates 10 empty-decision *artifacts* with 256 *CVE rows* | **incorrect attribution** |

No published rate was found that divides a 15641 numerator into a 15385 histogram cell; the documents keep the two n’s in separate tables. The error is the “10 artifacts” gloss, not a mixed rate.

### Authoritative value

Gap **256** = cves_in of the **three** dirs without `decisions.jsonl`.  
Source: on-disk `scan-summary.json` vs presence of `decisions.jsonl`.

---

## A6. FINDING-001 baseline error (public)

**Status: DISCREPANCY**

### Conflicting arithmetic in publication

| Claim | Numbers |
|-------|---------|
| Discussion / FINDING-001 filing text | SBOM **137**, image **409**, “**278** missed” |
| Arithmetic 409 − 137 | **272** |
| Table Hidden column / 415 − 137 | **278** |
| Severity breakdown cited | 13 CRITICAL / 63 HIGH / 121 MEDIUM / 70 LOW / 11 UNKNOWN (**sum 278**) |

### Cached evidence (pairing-matrix nginx trivy JSON)

Command (Python over cached files; counts verified):

```text
|trivy-image unique| = 409   (.lading/pairing-matrix/nginx-1.25/trivy-image.json)
|trivy-cdx unique|   = 137   (.lading/pairing-matrix/nginx-1.25/trivy-cdx.json)
|image − cdx|        = 278
|cdx − image|        = 6
409 − 137            = 272 = 278 − 6
```

Severity of **(image − cdx)** unique IDs, using image-scan Severity:

```text
CRITICAL: 13
HIGH:     63
MEDIUM:   121
LOW:      70
UNKNOWN:  11
sum:      278
```

### Which set was the severity breakdown computed against?

**Against the set difference `trivy image` − `trivy sbom` (baseline CDX), cardinality 278** — **not** against a numeric subtraction of 409 − 137, and **not** against a “415 baseline”.

The filing text pairs that 278 (and 13/63) with baseline **409**, which is internally inconsistent: the set that has 278 IDs is `image \ cdx`, while `409 − 137 = 272`.

### Correct sentences for each baseline (do not edit the published post)

1. **Direct image baseline:** `trivy image` on the nginx:1.25 tar reports **409** unique CVE IDs.
2. **Baseline SBOM path:** `trivy sbom` on Syft CycloneDX reports **137** unique CVE IDs.
3. **Set difference image − SBOM:** **278** unique CVE IDs (13 CRITICAL / 63 HIGH / 121 MEDIUM / 70 LOW / 11 UNKNOWN). This is **not** equal to 409 − 137.
4. **Numeric gap image − SBOM counts:** 409 − 137 = **272** (= 278 − 6), because 6 SBOM-only IDs are absent from the image set (see A7).
5. **Post-intervention SBOM path:** `trivy sbom` after SrcName injection reports **415** unique CVE IDs; Hidden in the effect-size table is 415 − 137 = **278**, which equals `|image \ cdx|` and also `|post \ cdx|` when post = image ∪ cdx.

### Authoritative value

Severity 13/63/121/70/11: **re-derives from** `.lading/pairing-matrix/nginx-1.25/trivy-image.json` minus IDs in `trivy-cdx.json`.  
The public sentence that says “409 … 278 missed” **does not** re-derive from 409 − 137.

---

## A7. The +6

**Status: CONFIRMED**

### Claim

FINDING-001: copying SrcName “restores the full count exactly.” Direct **409**; post-intervention **415**.

### Evidence

Post-intervention scan of cached `/tmp/lading-trivy-repro/nginx-src.cdx.json` (output written only under `/tmp`, not the repo):

```text
|nginx-src.trivy.json unique| = 415
|src − image| = 6
|image − src| = 0
src == (image ∪ cdx) = True
```

### The 6 CVE IDs in 415 and absent from 409

All reported against package `nginx@1.25.5-1~bookworm` on the SBOM path; **none** appear under any ID in the image scan:

| CVE ID | Severity (CDX path) | Status |
|--------|---------------------|--------|
| CVE-2009-4487 | LOW | affected |
| CVE-2013-0337 | LOW | will_not_fix |
| CVE-2023-44487 | LOW | affected |
| CVE-2026-42533 | HIGH | affected |
| CVE-2026-56434 | MEDIUM | affected |
| CVE-2026-60005 | HIGH | affected |

### Nature

**Genuinely extra unique CVE IDs** relative to `trivy image` — not duplicate rows of the same ID, not an unversioned-ID alias of an image hit. They are nginx-package advisories present on the SBOM ingest path and absent from the direct image result for this tar/DB snapshot.

### Authoritative value

415 = |409 image ∪ 137 CDX| = 409 + 6.  
“Restores … exactly” is **exact vs the post-intervention / union count (415)**, **not** exact vs the direct image count (409).

---

## A8. Unsourced figures

### (a) “7 provenance-verified” in PAPER.md

**Status: CONFIRMED**

Command:

```bash
grep -H 'provenance_status:' manifest/components/native/*.yaml | grep verified
```

**Count: 7** — list:

1. `libexpat`
2. `libwebp`
3. `libxml2`
4. `libxslt`
5. `openssl`
6. `sqlite3`
7. `zlib`

(PAPER.md line 314; schema field `provenance_status: verified`.)

Re-derives from `manifest/components/native/*.yaml`.

### (b) SPDX package count 151 vs 153

**Status: CONFIRMED** (both are real; version-scoped)

| Syft | Cached SPDX | packages with valid PURL |
|------|-------------|-------------------------:|
| **1.51.0** | `.lading/spdx-anomaly/syft-1_51_0/nginx-1.25/nginx-1.25.spdx.json` | **151** |
| **1.22.0** | `.lading/spdx-anomaly/syft-1_22_0/nginx-1.25/nginx-1.25.spdx.json` | **153** |

FINDING-001-PRIOR-ART “~151” matches **current** syft 1.51.0.  
ANALYSIS-spdx session table’s **153** is the **1.22.0** row — not a contradiction if version-labeled.

Exact jq (same as `scripts/spdx-anomaly.sh` `count_sbom` for spdx-json, lines 64–80):

```bash
jq '{
  total: ([.packages[]?] | length),
  with_purl: ([
    .packages[]?
    | select(
        any(.externalRefs[]?;
          .referenceType == "purl"
          or .referenceCategory == "PACKAGE-MANAGER"
        )
      )
    ] | length),
  unique_purl_locators: ([
    .packages[]?
    | .externalRefs[]?
    | select(.referenceType == "purl")
    | .referenceLocator
  ] | unique | length)
}' .lading/spdx-anomaly/syft-1_51_0/nginx-1.25/nginx-1.25.spdx.json
# → total=151, with_purl=151, unique_purl_locators=151
```

Authoritative for “current syft” claim: **151**.

---

## A9. Free hunt

### (a) REFUSAL-STAGES.md empty-`reason_code` paragraph

**Status: DISCREPANCY (stale pre-guard sentence)**

- Lines 94–102: audit table shows **5** findings, all `AFFECTED` / `D04` — matches post-guard `decisions.jsonl`.
- Lines 105–106: “All **40** empty rows are `NOT_AFFECTED` (D02) or `AFFECTED` (D04)” — **stale pre-guard sentence** left in a post-guard document.

Confirmed: pre-guard decided empty-reason rows were 35 NA + 5 affected = 40; post-guard only 5 affected remain empty-reason.

### (b) Other pre-guard figures in post-guard context

| Location | Figure | Labeling |
|----------|--------|----------|
| RESULTS.md pass table §6 (lines 248–249) | **40 / 15,641** | In “Instrument passes” history table; post-guard rate is 5/15641 elsewhere — **historical**, but adjacent to current narrative |
| RESULTS.md / PAPER decision tables | **0.2557%**, **40**, **35** | Generally labeled **pre-guard** / KT-2 snapshot — OK when labeled |
| RELATED-WORK.md line 113 | **0.2557%** | Explicitly “observed pipeline output, not an answer…” — OK |
| REFUSAL-STAGES.md:105–106 | **40** empty rows | **Unlabeled stale** inside post-guard audit section |
| RESULTS.md:185 | **10** artifacts for 256 gap | **Wrong count** (see A5); not a pre-guard fossil but a mis-count |
| PAPER.md:255–256 | **27,670** inventory; firmware **75% / 43%** | 27670 from metrics; 75/43 from PROFILE/CSV rounding — different sources, OK if not claimed as one traversal |
| PAPER.md:314 | **7** provenance-verified | Confirmed (A8) |
| FINDING-001.md:25–26 vs :113/:197 | “restores … exactly” vs 409 baseline | See A6/A7 |
| PAIRING-MATRIX.md | nginx delta **−272** | Consistent with 409−137; **differs** from FINDING-001 Hidden **278** by design of baseline |

### Additional non-rederiving figures (summary)

See final table below.

---

## Summary table — figures that do not currently re-derive from a single published dataset

| Figure as published | Where | Does not re-derive because | Authoritative source |
|-------------------|-------|----------------------------|----------------------|
| Inventory = CSV sum | Implied if reader sums `binary-profile.csv` | Different traversal; delta +12/+16/+3 | Scan-summaries → `inventory_stats()` **or** CSV — pick one |
| D01 `artifacts_scanned` **59** vs RESULTS **55** | `cp11-metrics.json` vs RESULTS §5 | Empty-file census vs parseable summaries | 55 for KT-1; 59 is file-presence count |
| “10 artifacts” → 256 gap | RESULTS.md:185 | Only **3** dirs lack `decisions.jsonl` and sum to 256 | Those 3 scan-summaries |
| KT-1 **15641** as “product corpus” | RESULTS / PAPER | Includes **253** `unknown`-class CVEs | Aggregate includes non-catalog dirs |
| “409 … 278 missed” | FINDING-001.md:197; discussion #11139; vendor LOG | 409−137=272; 278=\|image\cdx\| | Pairing-matrix trivy JSON set difference |
| “restores the full count exactly” vs image 409 | FINDING-001.md:25–26 | Post = **415** = 409 ∪ 6 SBOM-only | `/tmp` nginx-src scan + pairing image JSON |
| REFUSAL-STAGES “All 40 empty rows” | REFUSAL-STAGES.md:105–106 | Post-guard empty count is **5** | Current `decisions.jsonl` / lines 94–102 |
| SPDX **151** vs **153** without syft version | PRIOR-ART vs session table | Both true for 1.51.0 vs 1.22.0 | Version-scoped SPDX caches |

### Figures that *do* re-derive (spot checks)

| Figure | Source |
|--------|--------|
| KT-1 5 / 15641 / 0.032% / CI bounds | `cp11-metrics.json` ← aggregate + Wilson |
| Stage histogram n=15385 | `results/refusal-stages.csv` / decisions.jsonl |
| PROFILE containers 97% / 3%, firmware 75% / 43% | `binary-profile.csv` + `oneSentence` rounding |
| 7 provenance-verified | native YAML `provenance_status` |
| SPDX 151 (syft 1.51.0) | cached spdx-json + jq above |

---

## Section-status tally

| Status | Sections |
|--------|----------|
| CONFIRMED | A3, A7, A8 |
| DISCREPANCY | A1, A2, A4, A5, A6, A9 |
| (none open) | — |

No A1–A9 section was left without a ground-truth determination. Post-intervention 415 was settled by scanning the cached SBOM under `/tmp` (not written into the repo).

---

## Meta: files written this session

- `audit/CP-V1-AUDIT.md` (this file)
- Directory `audit/` created to hold it

No edits to `cp11-metrics.json`, CSVs, `decisions.jsonl`, RESULTS, PAPER, FINDING-00x, or corpus scan outputs.  
Did **not** run `corpus-scan.sh`, `corpus-redecide.sh`, or `rederive-results.sh` (rederive would rewrite frozen metrics/RESULTS).
