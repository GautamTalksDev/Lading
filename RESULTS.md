# CP-11 Kill Test Results (evidence-v1 / manifest 0.2.0)

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

**KT-1: FAIL** — 0% decided coverage is below the 30% bar; most refusals are `purl-insufficient` because grype PURLs (often `pkg:deb/...` / `pkg:apk/...` with version) do not reach `TypeNormalized` against manifest `pkg:generic/...` seeds.

| Artifact class | Artifacts | CVEs in | Decided | Coverage |
|----------------|-----------|---------|---------|------------|
| oci-app | 12 | 6,498 | 0 | 0% |
| oci-base | 9 | 1,130 | 0 | 0% |
| static-binary | 8 | ~900 | 0 | 0% |
| openwrt | 4 | varies | 0 | 0% |
| rtos-sdk | 3 | varies | 0 | 0% |
| firmware / yocto (substitute OCI) | 4 | varies | 0 | 0% |

**Interpretation:** On real shipped Linux artifacts, scanner output volume is high but manifest PURL alignment is insufficient for the v1 manifest to engage symbol rules — the pipeline correctly refuses rather than guessing. Stripped static firmware–class objects remain near-useless for definitive symbol evidence (expected).

---

## 3. KT-2 — Ground truth soundness

**100-statement sample:** stratified D01=33, D02=31, D03=20, D04=16; weighted toward `NOT_AFFECTED` (64/100).

Independent binary review + `go test ./corpus/groundtruth/` → **0 false `not_affected`** (no case where engine emitted `NOT_AFFECTED` contradicting hand-verified ground truth).

**KT-2: PASS** — zero false `not_affected` in the 100-statement hand-verified set.

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

- **OCI / OpenWrt rootfs:** Dynamic ELF with dynsym — symbol rules apply when PURL + manifest entry align; corpus scans rarely reached that gate in v1.
- **Static release binaries (musl/go):** Often stripped; D03 `symbol_table_unusable` / `stripped_static_binary` dominates.
- **Flash/combined images / factory `.bin`:** Not inventoryable as ELF collections without filesystem extraction; substitutes used OCI rootfs scans for CP-11 throughput.
- **RTOS/SDK archives:** Mix of host tools + bare-metal objects; grype noise high, manifest coverage low.

---

## 5. Notable findings

**Over-reported components (corpus):** Grype reports large CVE counts for `oci-node-20` (2,922), `oci-nginx-1.25` (626), `oci-mariadb-11` (582), `oci-rockylinux-9` (607) — none map to manifest v1 PURLs at sufficient quality to decide; refusal is expected, not exoneration.

**audit-vex / public VEX shapes (`testdata/auditvex/`):**

- **Grype-class inert:** VEX for `CVE-2022-99999` on `commons-lang3@3.12.0` matches SBOM only at `name_version_only` → **inert** (would silently miss in production VEX).
- **Trivy-class overbroad:** VEX for `CVE-2023-88888` with **exact** match on subcomponent `openssl@3.0.2` → **overbroad** (cross-product suppression risk).

These are deterministic PURL match-quality failures, not scanner CVE truth claims.

---

## 6. Limitations (full)

1. **Manifest v1 is a 25-component seed**, not production-complete NVD coverage; corpus CVEs overwhelmingly lack entries.
2. **PURL harmonization** between grype (distro-specific PURLs) and manifest (`pkg:generic/...`) was not in CP-11 scope; KT-1 failure is largely a matching-layer gap, not proof that symbol rules work when inputs align (see ground truth).
3. **Corpus substitutes** replace unavailable vendor GPL/flash URLs; class labels are preserved but bytes differ from original product intent.
4. **No threshold or rule refitting** was performed; reporting reflects evidence-v1 honestly.
5. **Scan environment:** rootless podman on WSL2; sandbox unpack uses Debian bookworm-slim helper image.
6. **Grype version** pinned by local install (`0.115.0` at run time); results are not grype-version invariant.
7. **Evidence bundles** were emitted only when manifest slice + decided path existed; corpus runs produced refusals without VEX for most findings.
8. **KT-1 and KT-2 measure different things:** KT-2 validates engine soundness on controlled statements; KT-1 validates end-to-end usefulness on scanner-fed corpus — v1 fails KT-1.

---

## Decision

**Do not launch** on v1 for scanner-driven compliance claims. The engine appears **sound on NOT_AFFECTED** (KT-2 pass) but **cannot decide real scanner output at scale** (KT-1 fail). Next work (v2 spec, not built here): PURL normalization layer, manifest expansion from corpus-driven CVE/component pairs, and filesystem extraction for flash images — see `IDEAS.md`.

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
