# CP-11 Kill Test Results (evidence-v1 / manifest 0.2.0)

**Correction (2026-08-23):** The original v1 reading of **KT-1: FAIL** is **withdrawn**. That label treated an instrument defect (PURL identity resolution never engaged) as a scientific finding about firmware. It is retracted here; the original FAIL record is preserved below as part of the evidence trail.

**KT-1 is NOT EVALUABLE** against the pre-registered 30% bar — the decision engine never evaluated a single real CVE on corpus scanner input.

Date: 2026-08-23 · Tool: `lading` built from this repo (`evidence-v1`, manifest `0.2.0`).

## 1. Method

| Item | Value |
|------|--------|
| **Corpus** | `corpus/ARTIFACTS.yaml` (version `cp11-1`) — 41 product artifacts across OCI base/app, OpenWrt, static binaries, firmware-class substitutes, Yocto-class substitute, RTOS/SDK archives. Provenance and license recorded per row. |
| **Manifest** | `manifest/VERSION` `0.2.0` — 25 native components, each with one manually reviewed definitive CVE entry (`reviewed_by` / `reviewed_at` on every seed). `manifest/COVERAGE.md` generated via `lading manifest coverage`. |
| **Tool** | `bin/lading` from `go build ./cmd/lading`; decision rules `evidence-v1` (D01–D04 unchanged). |
| **Scan procedure** | `bash scripts/corpus-download.sh` then `bash scripts/corpus-scan.sh`: grype JSON → `lading scan` → `corpus/results/<id>/` (grype.json, scan-summary.json, evidence-bundle when applicable). Rollup: `scripts/corpus-aggregate.py` → `corpus/results/aggregate.json`. |
| **Ground truth** | `corpus/groundtruth/statements.yaml` — 100 statements (40 decide fixtures + 60 inventory binaries). Hand verification via `readelf -sW` / `nm -D` on `testdata/inventory/bin/*`. Repro: `go test ./corpus/groundtruth/`. |
| **Thresholds** | From README (unchanged): **KT-1** ≥30% of scanner-reported CVEs decided with evidence; **KT-2** zero false `not_affected` in 100 hand-verified cases. |

**Corpus notes:** Several original vendor/firmware URLs returned HTTP 404 at fetch time; substitutes are documented inline in `ARTIFACTS.yaml` (OpenWrt rootfs OCI tags, Hub images for firmware/Yocto class rows). All 41 catalog IDs produced non-empty `scan-summary.json` after unpack/findings fixes below.

**Correctness fixes during CP-11 (no rule/threshold changes):**

- `OpenArchive` double-wrapped tar streams (empty OCI unpacks).
- Container rootfs tar: absolute and `..` symlink/hardlink targets.
- `LoadFindings` accepts empty grype match lists; `matchesToFindings` returns empty slice instead of error.
- `corpus-scan.sh`: grype `file:` for single binaries; resilient download/scan skips.

---

## 2. KT-1 — Corpus decided coverage

**Aggregate:** 10,088 grype-reported CVEs across 41 scanned artifacts → **0 decided** (0 `not_affected`, 0 `affected`, 10,088 `refused`).

**KT-1: NOT EVALUABLE** — The pre-registered 30% bar cannot be applied to this run. Zero decided coverage does not measure how often vulnerable code is absent from shipped binaries; it measures that identity resolution never engaged.

**Original v1 label (withdrawn):** KT-1 was initially recorded as **FAIL** (0% vs. 30% bar). That reading is retracted in the correction above.

**Why NOT EVALUABLE, not FAIL:**

1. **10,088 grype findings** across **41 corpus artifacts**.
2. **100% refused** with reason code **`purl-insufficient`** (10,088 / 10,088).
3. **Cause:** grype emits **distro PURLs** (`pkg:deb/...`, `pkg:apk/...`, `pkg:rpm/...`) while the Manifest carries **upstream PURLs** (`pkg:generic/...`). Per CP-3, cross-type equivalence caps at `NameVersionOnly`, which D03 correctly refuses — it will not treat a distro package identity as equivalent to an upstream generic identity for symbol-level clearance.
4. **Therefore** the decision engine never evaluated a single real CVE on corpus input. Zero decisions is the signature of an instrument that never fired, not a genuine negative result about firmware reachability. A real negative on this bar would look like 2% or 7% decided — not exactly 0 / 10,088.
5. **KT-1 re-runs unchanged** against the 30% bar once distro-to-upstream identity resolution exists (CP-15).

| Artifact class | Artifacts | CVEs in | Decided | Coverage |
|----------------|-----------|---------|---------|----------|
| oci-app | 12 | 6,498 | 0 | 0% |
| oci-base | 9 | 1,130 | 0 | 0% |
| static-binary | 8 | ~900 | 0 | 0% |
| openwrt | 4 | varies | 0 | 0% |
| rtos-sdk | 3 | varies | 0 | 0% |
| firmware / yocto (substitute OCI) | 4 | varies | 0 | 0% |

The 0% figure is reported as raw instrument output, not as a pass/fail verdict against the 30% threshold.

---

## 3. KT-2 — Ground truth soundness

**100-statement sample:** stratified D01=33, D02=31, D03=20, D04=16; weighted toward `NOT_AFFECTED` (64/100).

Independent binary review + `go test ./corpus/groundtruth/` → **0 false `not_affected`** (no case where engine emitted `NOT_AFFECTED` contradicting hand-verified ground truth).

**KT-2: PASS WITH LIMITATION** — zero false `not_affected` in the 100-statement hand-verified set. That result stands.

**Limitation (explicit):** Because no corpus grype finding reached a decided verdict, **none** of the 100 ground-truth statements came from live scanner-fed corpus input. All 100 are constructed benchmark fixtures (40 from `testdata/decide/`, 60 from hand-verified inventory binaries). Soundness against **real-world scanner input is UNTESTED**. This PASS must not be read as end-to-end validation on grype-fed production triage.

---

## 4. Per-rule precision (ground truth)

On the pre-registered 100-statement set (not corpus grype findings):

| Rule | Statements | Engine agreement |
|------|------------|------------------|
| D01 | 33 | 33/33 |
| D02 | 31 | 31/31 |
| D03 | 20 | 20/20 |
| D04 | 16 | 16/16 |

**Precision:** 100/100 verdicts match ground truth (100%). This measures the decision engine against controlled fixtures, not grype recall on the corpus.

**Coverage limits by artifact class:**

- **OCI / OpenWrt rootfs:** Dynamic ELF with dynsym — symbol rules apply when PURL + manifest entry align; corpus scans did not reach that gate in v1 (identity resolution blocked first).
- **Static release binaries (musl/go):** Often stripped; D03 `symbol_table_unusable` / `stripped_static_binary` dominates when statements reach the engine.
- **Flash/combined images / factory `.bin`:** Not inventoryable as ELF collections without filesystem extraction; substitutes used OCI rootfs scans for CP-11 throughput.
- **RTOS/SDK archives:** Mix of host tools + bare-metal objects; grype noise high, manifest coverage low.

---

## 5. Method defects

This study's end-to-end instrument had a **PURL identity gap** between scanner output and manifest seeds. It is a defect in the pipeline under test, not a finding about shipped firmware.

| Evidence | Value |
|----------|-------|
| Corpus CVE rows in | 10,088 |
| Decided | 0 |
| Refused | 10,088 |
| Refusal reason `purl-insufficient` | **10,088 (100%)** |
| Other refusal reasons on corpus | 0 |

**Mechanism:** grype reports distro-scoped package identities; the v1 Manifest lists upstream `pkg:generic/...` identities. CP-3 cross-type matching stops at `NameVersionOnly`; D03 refuses rather than infer upstream equivalence. The engine behaved correctly — the integration layer never supplied matchable identities.

**Consequence:** KT-1 corpus numbers are **instrument telemetry**, not corpus-scale clearance rates. Publishing them as FAIL implied a scientific negative about firmware CVE reachability; that implication is withdrawn.

---

## 6. What this study does not show

Stated plainly:

- This study does **NOT** show that firmware CVEs are mostly unreachable in shipped binaries.
- This study does **NOT** show that LADING cannot decide real scanner findings when identity resolution aligns.
- This study does **NOT** support any public claim about corpus-scale clearance rates, exoneration rates, or “most scanner CVEs are irrelevant.”
- The 0 / 10,088 decided figure is consistent with a broken identity bridge, not with a measured absence of vulnerable code.

---

## 7. Notable findings

**Over-reported components (corpus):** Grype reports large CVE counts for `oci-node-20` (2,922), `oci-nginx-1.25` (626), `oci-mariadb-11` (582), `oci-rockylinux-9` (607) — none reached manifest PURL alignment sufficient to invoke symbol rules in v1; refusal at the identity gate is expected, not exoneration.

**audit-vex / public VEX shapes (`testdata/auditvex/`):**

- **Grype-class inert:** VEX for `CVE-2022-99999` on `commons-lang3@3.12.0` matches SBOM only at `name_version_only` → **inert** (would silently miss in production VEX).
- **Trivy-class overbroad:** VEX for `CVE-2023-88888` with **exact** match on subcomponent `openssl@3.0.2` → **overbroad** (cross-product suppression risk).

These are deterministic PURL match-quality failures, not scanner CVE truth claims.

---

## 8. Limitations (full)

1. **Manifest v1 is a 25-component seed**, not production-complete NVD coverage; even with identity resolution, most corpus CVEs would lack manifest entries.
2. **Distro-to-upstream PURL harmonization** was not in CP-11 scope; KT-1 is not evaluable until CP-15 provides that layer.
3. **Corpus substitutes** replace unavailable vendor GPL/flash URLs; class labels are preserved but bytes differ from original product intent.
4. **No threshold or rule refitting** was performed; pre-registered bars in README are unchanged.
5. **Scan environment:** rootless podman on WSL2; sandbox unpack uses Debian bookworm-slim helper image.
6. **Grype version** pinned by local install (`0.115.0` at run time); results are not grype-version invariant.
7. **Evidence bundles** were emitted only when manifest slice + decided path existed; corpus runs produced refusals without VEX for all grype findings.
8. **KT-1 and KT-2 measure different things:** KT-2 validates engine soundness on controlled fixtures; KT-1 validates end-to-end usefulness on scanner-fed corpus — v1 KT-1 is **not evaluable**, not failed.

---

## Decision

**Do not launch** on v1 for scanner-driven compliance claims at corpus scale. The engine appears **sound on NOT_AFFECTED** within the 100-statement fixture benchmark (KT-2 pass with limitation) but **did not evaluate real scanner output** on the corpus (KT-1 not evaluable). Next work (v2 spec, not built here): distro-to-upstream PURL normalization (CP-15), manifest expansion from corpus-driven CVE/component pairs, and filesystem extraction for flash images — see `IDEAS.md`.

---

## Reproduce

```bash
go build -o bin/lading ./cmd/lading
bash scripts/corpus-download.sh
bash scripts/corpus-scan.sh
go test ./corpus/groundtruth/ -count=1
python3 scripts/corpus-aggregate.py
cat corpus/results/aggregate.json
```
