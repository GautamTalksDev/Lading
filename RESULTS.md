# CP-11 Kill Test Results (S-15 re-run)

**Date:** 2026-08-24 · **Git:** `97eca4038f5d2e7ff6a4e053c01a1a0841671eb1` · **Engine:** `evidence-v1` · **Manifest:** `0.2.0`

Pre-registered thresholds unchanged: **KT-1** ≥30% scanner CVEs decided with evidence; **KT-2** zero false `not_affected` in 100 hand-labeled real-corpus statements.

**Correction (2026-08-24, CP-A3):** The S-15 reading of **KT-1: FAIL** (0.2557% decided ≪ 30%) is **withdrawn**. That label treated a measured decided rate as an answer to the pre-registered question even though **99.6%** of findings (`decisions.jsonl`) terminated at identity resolution or manifest lookup — before symbol-table evaluation — and **zero** refusals cite a symbol-table cause. The FAIL line is preserved below as part of the evidence trail; the corrected verdict is **NOT EVALUABLE**.

**Correction (2026-08-24, post-FINDING-002 guard):** `bash scripts/corpus-redecide.sh` re-ran decide after `symbol_not_observable`. The **35** unsound D02 `NOT_AFFECTED` rows are now S5b refusals. Current measured decided rate is **5 / 15,641 = 0.032%** (all `AFFECTED`). The pre-guard **40 / 0.2557%** figure remains the snapshot that KT-2 scored (`real-100.yaml` is frozen). KT-1 stays **NOT EVALUABLE**: **99.60%** still terminate at S1/S2; S3/S5 symbol-table refusals remain **0**.

**Correction (2026-08-25, FINDING-003):** Version applicability was never computed. Corpus OpenSSL is seven versions, not 3.0.20. **7 of 40** pre-guard decisions would have terminated at a version gate (CVE-2026-14456 on 3.0.x). Corrected unsound D02 count: **28 of 35**. Corrected KT-2 false `not_affected`: **16 of 20** (real-008, real-031, real-035, real-086 were NA by accident; original labels frozen in `real-100.yaml`). CVE-2026-14456 is QUIC, not DTLS. Scanner PURL on subst-golang-bookworm asserts 3.0.15 against `.so`/dpkg 3.0.20. RabbitMQ D04 evidence is `/opt/openssl` 3.1.8, not the 3.0.13 package. See [FINDING-003.md](FINDING-003.md). `real-100.yaml` was not rescored; the amendment block preserves original `human_label` values.

**Gate decision:** **Stop.** KT-1 **NOT EVALUABLE**. KT-2 **FAIL** — **16** false `not_affected` clearances after FINDING-003 ([FINDING-002.md](FINDING-002.md) mechanism on the 16; corpus-wide **28** of **35** D02 clearances unsound). Original labelled count was **20/20**; four labels were wrong. KT-1 remains the **third consecutive** NOT EVALUABLE on instrument reachability (see §11). No threshold or rule refitting was performed.

Canonical figures: `corpus/results/cp11-metrics.json` · Re-derive: `bash scripts/rederive-results.sh`

---

## 1. Method

| Item | Value |
|------|--------|
| **Corpus catalog** | `corpus/ARTIFACTS.yaml` version **`cp11-3`** — **53** product artifacts (+1 benchmark excluded from kill tests) |
| **Class composition** | firmware **12** · oci-app **12** · oci-base **9** · static-binary **8** · substitute-container **7** · rtos-sdk **3** · openwrt **2** |
| **Hashes verified** | **53/53** product rows `status: present` with non-null `sha256` (`bash scripts/verify-corpus-hashes.sh`; 12 firmware-class rows checked) |
| **Artifacts scanned** | **55** result directories with `scan-summary.json` (includes 2 auxiliary single-binary re-scan dirs) |
| **Manifest** | `manifest/VERSION` **`0.2.0`** — **25** native component YAMLs, one definitive CVE entry each (seed coverage) |
| **Identity aliases** | `manifest/data/identity-aliases.json` — **10** rows (**1** `definitive`: expat; **9** `probable`) |
| **PURL / evidence taxonomy** | CP-3 graded equivalence (`none` … `exact`); SPEC-IDENTITY §2.1 `debian_upstream_from_version` derivation in engine; decision rules **`evidence-v1`** (D01–D04) |
| **Ground truth (KT-2)** | `corpus/groundtruth/real-100.yaml` — seed **20260824**, sampled from `corpus/results/*/decisions.jsonl` |
| **Scan procedure** | `bash scripts/corpus-download.sh` → profile extract (`.lading/profile-rootfs/`) → grype JSON → `lading scan` → `decisions.jsonl` + optional `evidence-bundle/` → `scripts/corpus-aggregate.py` |
| **Tool versions** | Go **`go1.23.6`** · grype **`0.115.0`** (embedded Syft **v1.46.0**, DB schema **6**) · `bin/lading` built from this commit |
| **Scanner binary provenance** | Verified **2026-08-24** against official release tarballs (see below). CP-11 corpus numbers flow through **grype** only; **trivy** / standalone **syft** used in FINDING-001 / pairing-matrix work. |
| **Refusal-stage attribution** | `bash scripts/refusal-stages.sh` → `results/refusal-stages.csv`, `REFUSAL-STAGES.md` |

### Tool binary SHA256 (verified 2026-08-24)

| Tool | Version | Path | SHA256 | Official source | Match |
|------|---------|------|--------|-----------------|-------|
| **grype** | 0.115.0 | `/home/gautamtalksdev/bin/grype` | `05ffd2c28a607e48fb2269d9aac5b3d53e8a51bbac501946644745eae2119907` | [grype_0.115.0_linux_amd64.tar.gz](https://github.com/anchore/grype/releases/download/v0.115.0/grype_0.115.0_linux_amd64.tar.gz) (`3fad9294…` tarball) | **yes** — binary extracted from tarball matches installed file |
| **trivy** | 0.72.0 | `/home/gautamtalksdev/bin/trivy` | `0e69edd134a3c338baa1a6806920773615d682b18cbc6a0cba2a3b658ef9b63e` | [trivy_0.72.0_Linux-64bit.tar.gz](https://github.com/aquasecurity/trivy/releases/download/v0.72.0/trivy_0.72.0_Linux-64bit.tar.gz) (`bbb64b96…` tarball) | **yes** — post-dates Feb/Mar 2026 compromise window; not used for CP-11 corpus scan |
| **syft** | 1.51.0 | `.lading/tools/syft-1.51.0` | `5a8b71e94f4607973145f02e27e01d50b9f7c7bc41e38d40b39606ad138b43b5` | [syft_1.51.0_linux_amd64.tar.gz](https://github.com/anchore/syft/releases/download/v1.51.0/syft_1.51.0_linux_amd64.tar.gz) | **yes** — tarball checksum verified 2026-08-24 against `syft_1.51.0_checksums.txt`; binary hash matches an independent re-download to `~/bin/syft-1.51.0`. Used for FINDING-001 currency claim, `ANALYSIS-spdx`, `PAIRING-MATRIX`. |
| **syft** | 1.22.0 | `/home/gautamtalksdev/bin/syft` | `b94458fcc8d2b96320e40832a566d5a5fdfb9b8a7f8f9c9535cb699c5fd83d5a` | [syft_1.22.0_linux_amd64.tar.gz](https://github.com/anchore/syft/releases/download/v1.22.0/syft_1.22.0_linux_amd64.tar.gz) (`90ac44b1…` tarball) | **yes** — not used for CP-11 corpus scan (grype bundles Syft 1.46.0) |

**Note:** syft **1.22.0** is installed at two paths — `~/bin/syft` (table above) and `.lading/tools/syft-1.22.0` — with identical SHA256 `b94458fcc8d2b96320e40832a566d5a5fdfb9b8a7f8f9c9535cb699c5fd83d5a`.

**Install method:** manual extract to `~/bin/` (mtime grype/trivy **2026-07-15**, syft 1.22.0 **2025-04-01**); syft 1.51.0 under `.lading/tools/`. No `trivy-action` / cached Docker image on this host for CP-11. Re-verify before publication if binaries are refreshed.

**Inventory telemetry (all scans):** **27,670** binaries inventoried · **22,971** stripped (**83.0%**) · **5,194** static-linked (**18.8%** of inventoried).

---

## 2. KT-1 — Corpus decided coverage

**Observed:** **15,641** grype-reported CVE rows across **55** scanned artifacts (`scan-summary.json` aggregate).

**Decided with evidence:** **5** total (**0** `NOT_AFFECTED` with re-derivable evidence bundle · **5** `AFFECTED`). Pre-guard snapshot (S-15, frozen in `real-100.yaml`): **40** decided (**35** `NOT_AFFECTED` + **5** `AFFECTED`); those **35** D02 rows are now `symbol_not_observable` (S5b).

| Metric | Count | Rate | 95% Wilson CI |
|--------|------:|-----:|---------------|
| **`NOT_AFFECTED` + evidence bundle** | **0** / 15,641 | **0.0%** | **0.0%** – **0.0246%** |
| **Decided (NA + affected)** | **5** / 15,641 | **0.032%** | **0.0137%** – **0.0748%** |
| **Refused** | **15,636** | 99.97% | — |

**Measured decided rate:** **0.032%** — reported as observed pipeline output after the FINDING-002 guard, **not** as a PASS/FAIL answer to KT-1 (see refusal-stage table below). The pre-guard **0.2557%** (40 rows) is retained as the KT-2 scoring snapshot.

**KT-1: NOT EVALUABLE** — KT-1 asks whether ≥30% of scanner-reported CVEs resolve to a decidable `not_affected` with a re-derivable evidence bundle. The measured **0.032%** cannot be read as an answer to that question: on **`decisions.jsonl`** (**15,385** rows), **14,144 + 1,180 = 15,324** findings (**99.60%**) terminate at **S1 identity resolution** or **S2 manifest lookup** before any symbol-table gate fires; **zero** refusals cite `symbol_table_unusable`, `stripped_static_binary`, or `stripped_insufficient_dynsym`. The **35** S5b `symbol_not_observable` refusals are the FINDING-002 guard on internal OpenSSL symbols — they do not make symbol-evidence clearance evaluable at corpus scale. The pre-registered **30%** threshold is unchanged and was not tested.

**Withdrawn reading (evidence trail):** S-15 initially labeled **KT-1: FAIL** because 0.2557% < 30%. That comparison is retracted under CP-A3 / README §11.

### Refusal-stage termination (`decisions.jsonl`, n=15,385)

Re-derived: `bash scripts/refusal-stages.sh`. Stage order follows `internal/decide/context.go` `checkD03()` then `evaluate.go` (S5b after S5).

| Stage | Termination count | % of `decisions.jsonl` | Cumulative % |
|-------|------------------:|-----------------------:|-------------:|
| S1 identity_resolution | 14,144 | 91.93% | 91.93% |
| S2 manifest_lookup | 1,180 | 7.67% | 99.60% |
| S3 symbol_table_usability | **0** | 0.00% | 99.60% |
| S4 provenance_gate | 21 | 0.14% | 99.74% |
| S5 symbol_stripped_gates | **0** | 0.00% | 99.74% |
| S5b symbol_observability | 35 | 0.23% | 99.97% |
| S6 identity_unverified | 0 | 0.00% | 99.97% |
| S7 evidence_evaluation (decided) | 5 | 0.03% | 100.00% |

**Reached symbol evaluation (S3 or later):** **61** (21 provenance refusals + 35 S5b observability refusals + 5 decided). **Symbol-stage refusals (S3 or S5):** **0**.

### By stratum (decided / CVEs in)

| Stratum | Artifacts | CVEs in | Decided | Coverage |
|---------|----------:|--------:|--------:|---------:|
| **Combined (all classes)** | 55 | **15641** | **5** | **0.032%** |
| **`firmware` class** | 12 | **5553** | **1** | **0.018%** |
| **`substitute-container` class** | 7 | **1566** | **0** | **0.0%** |
| oci-app | 12 | 6498 | 4 | 0.0616% |
| oci-base | 9 | 1130 | 0 | 0% |
| static-binary | 8 | 487 | 0 | 0% |
| openwrt | 2 | 30 | 0 | 0% |
| rtos-sdk | 3 | 124 | 0 | 0% |

Firmware stratum: **0** `NOT_AFFECTED` with bundle; the single decided row is **`AFFECTED`**. Substitute-container stratum's pre-guard **12** D02 clears are now S5b refusals.

---

## 3. KT-2 — Ground truth soundness

**Evidence set:** `corpus/groundtruth/real-100.yaml` (100 real pipeline statements; synthetic `statements.yaml` is unit-test only).

**Frozen pipeline snapshot (pre-guard):** Each row's `pipeline_verdict` is copied from the S-15 `decisions.jsonl` emitted **before** the FINDING-002 `symbol_not_observable` guard. KT-2 scores whether those clearances were **sound when emitted** — not whether the post-fix engine would re-emit them. Rescoring `real-100.yaml` against the guarded instrument would test a different pipeline in response to the finding and void the pre-registered kill test. The guard is reported separately under §2 (post-guard re-decide: **0** `NOT_AFFECTED`, **5** `AFFECTED`, **0.032%** decided).

**Hand labels:** **100/100** filled (`seed: 20260824`).

**Supporting analysis:** [FINDING-002.md](FINDING-002.md) — D02 on internal OpenSSL symbols (35 corpus D02 rows; **28** unsound where the CVE applies, **7** accidental NA on CVE-2026-14456 / 3.0.x). [FINDING-003.md](FINDING-003.md) — version never computed; four KT-2 labels wrong.

**KT-2 is FAIL (unsound):** the pipeline emitted **16** false `not_affected` clearance(s) in the hand-labeled soundness subset after FINDING-003 — each remaining false clearance listed below; one false clearance violates the pre-registered kill criterion. Original hand labels recorded **20** disagreements; four of those (real-008, real-031, real-035, real-086) are accidental `NOT_AFFECTED` (CVE-2026-14456 does not apply to the observed 3.0.x).

### False `not_affected` clearances (pipeline claimed NOT_AFFECTED; CVE applies; FINDING-002 holds)

**By CVE (real-100 sample, FINDING-003-corrected):** CVE-2026-14456 ×9, CVE-2026-42767 ×6, CVE-2026-45445 ×1. DTLS wording in the FINDING-002 notes below is withdrawn; CVE-2026-14456 is QUIC ([FINDING-003.md](FINDING-003.md)).

- **real-002** — **CVE-2026-42767** on **`oci-redis-7`** / component **`openssl`**: pipeline claimed **`NOT_AFFECTED`** (`vulnerable_code_not_present`); hand-check found **`UNDER_INVESTIGATION`**. FINDING-002: D02 on OSSL_CRMF_ENCRYPTEDVALUE_decrypt unsound — internal symbol absent from .dynsym while OSSL_CRMF_* API is exported and objdump shows 597 CRMF references on oci-redis-7 libcrypto.so.3.
- **real-008** — **CVE-2026-14456** on **`oci-redis-7`** / component **`openssl`**: **withdrawn as false clearance (FINDING-003).** Observed OpenSSL **3.0.20**; CVE has no 3.0.x range. Pipeline `NOT_AFFECTED` was correct by accident. Original hand label `UNDER_INVESTIGATION` frozen in `real-100.yaml`.
- **real-010** — **CVE-2026-14456** on **`oci-python-3.12`** / component **`openssl`**: pipeline claimed **`NOT_AFFECTED`** (`vulnerable_code_not_present`); hand-check found **`UNDER_INVESTIGATION`**. FINDING-002 holds: D02 on internal `port_default_packet_handler` (QUIC, OpenSSL **3.5.6**, in range). DTLS wording in the original note is withdrawn (FINDING-003).
- **real-011** — **CVE-2026-14456** on **`subst-mosquitto`** / component **`openssl`**: pipeline claimed **`NOT_AFFECTED`** (`vulnerable_code_not_present`); hand-check found **`UNDER_INVESTIGATION`**. FINDING-002: D02 on port_default_packet_handler unsound — handler not in libssl.so.3 .dynsym (0 exported) while objdump shows 691 DTLS references, 13 exported DTLS symbols, 43 DTLS strings on oci-redis-7 libssl.so.3. Initial check used libcrypto.so.3 (wrong library).
- **real-013** — **CVE-2026-45445** on **`subst-golang-bookworm`** / component **`openssl`**: pipeline claimed **`NOT_AFFECTED`** (`vulnerable_code_not_present`); hand-check found **`UNDER_INVESTIGATION`**. FINDING-002: D02 clearance unsound — vulnerable symbol not observable in .dynsym on dynamically-linked libcrypto.so.3; symbol absence is guaranteed a priori for internal functions.
- **real-015** — **CVE-2026-42767** on **`oci-node-20`** / component **`openssl`**: pipeline claimed **`NOT_AFFECTED`** (`vulnerable_code_not_present`); hand-check found **`UNDER_INVESTIGATION`**. FINDING-002: D02 clearance unsound — vulnerable symbol not observable in .dynsym on dynamically-linked libcrypto.so.3; symbol absence is guaranteed a priori for internal functions.
- **real-016** — **CVE-2026-42767** on **`oci-nginx-1.25`** / component **`openssl`**: pipeline claimed **`NOT_AFFECTED`** (`vulnerable_code_not_present`); hand-check found **`UNDER_INVESTIGATION`**. FINDING-002: D02 clearance unsound — vulnerable symbol not observable in .dynsym on dynamically-linked libcrypto.so.3; symbol absence is guaranteed a priori for internal functions.
- **real-021** — **CVE-2026-14456** on **`subst-httpd-alpine`** / component **`openssl`**: pipeline claimed **`NOT_AFFECTED`** (`vulnerable_code_not_present`); hand-check found **`UNDER_INVESTIGATION`**. FINDING-002: D02 on port_default_packet_handler unsound — handler not in libssl.so.3 .dynsym (0 exported) while objdump shows 691 DTLS references, 13 exported DTLS symbols, 43 DTLS strings on oci-redis-7 libssl.so.3. Initial check used libcrypto.so.3 (wrong library).
- **real-022** — **CVE-2026-42767** on **`oci-rabbitmq-3`** / component **`openssl`**: pipeline claimed **`NOT_AFFECTED`** (`vulnerable_code_not_present`); hand-check found **`UNDER_INVESTIGATION`**. FINDING-002: D02 clearance unsound — vulnerable symbol not observable in .dynsym on dynamically-linked libcrypto.so.3; symbol absence is guaranteed a priori for internal functions.
- **real-024** — **CVE-2026-14456** on **`subst-httpd-alpine`** / component **`openssl`**: pipeline claimed **`NOT_AFFECTED`** (`vulnerable_code_not_present`); hand-check found **`UNDER_INVESTIGATION`**. FINDING-002: D02 on port_default_packet_handler unsound — handler not in libssl.so.3 .dynsym (0 exported) while objdump shows 691 DTLS references, 13 exported DTLS symbols, 43 DTLS strings on oci-redis-7 libssl.so.3. Initial check used libcrypto.so.3 (wrong library).
- **real-031** — **CVE-2026-14456** on **`oci-node-20`** / component **`openssl`**: **withdrawn as false clearance (FINDING-003).** Observed OpenSSL **3.0.19**; CVE has no 3.0.x range. Original hand label frozen.
- **real-035** — **CVE-2026-14456** on **`oci-nginx-1.25`** / component **`openssl`**: **withdrawn as false clearance (FINDING-003).** Observed OpenSSL **3.0.11**; CVE has no 3.0.x range. Original hand label frozen.
- **real-043** — **CVE-2026-14456** on **`oci-postgres-16`** / component **`openssl`**: pipeline claimed **`NOT_AFFECTED`** (`vulnerable_code_not_present`); hand-check found **`UNDER_INVESTIGATION`**. FINDING-002: D02 on port_default_packet_handler unsound — handler not in libssl.so.3 .dynsym (0 exported) while objdump shows 691 DTLS references, 13 exported DTLS symbols, 43 DTLS strings on oci-redis-7 libssl.so.3. Initial check used libcrypto.so.3 (wrong library).
- **real-055** — **CVE-2026-42767** on **`subst-golang-bookworm`** / component **`openssl`**: pipeline claimed **`NOT_AFFECTED`** (`vulnerable_code_not_present`); hand-check found **`UNDER_INVESTIGATION`**. FINDING-002: D02 clearance unsound — vulnerable symbol not observable in .dynsym on dynamically-linked libcrypto.so.3; symbol absence is guaranteed a priori for internal functions.
- **real-063** — **CVE-2026-14456** on **`oci-python-3.12`** / component **`openssl`**: pipeline claimed **`NOT_AFFECTED`** (`vulnerable_code_not_present`); hand-check found **`UNDER_INVESTIGATION`**. FINDING-002: D02 on port_default_packet_handler unsound — handler not in libssl.so.3 .dynsym (0 exported) while objdump shows 691 DTLS references, 13 exported DTLS symbols, 43 DTLS strings on oci-redis-7 libssl.so.3. Initial check used libcrypto.so.3 (wrong library).
- **real-065** — **CVE-2026-42767** on **`oci-nginx-1.25`** / component **`openssl`**: pipeline claimed **`NOT_AFFECTED`** (`vulnerable_code_not_present`); hand-check found **`UNDER_INVESTIGATION`**. FINDING-002: D02 clearance unsound — vulnerable symbol not observable in .dynsym on dynamically-linked libcrypto.so.3; symbol absence is guaranteed a priori for internal functions.
- **real-068** — **CVE-2026-14456** on **`oci-postgres-16`** / component **`openssl`**: pipeline claimed **`NOT_AFFECTED`** (`vulnerable_code_not_present`); hand-check found **`UNDER_INVESTIGATION`**. FINDING-002: D02 on port_default_packet_handler unsound — handler not in libssl.so.3 .dynsym (0 exported) while objdump shows 691 DTLS references, 13 exported DTLS symbols, 43 DTLS strings on oci-redis-7 libssl.so.3. Initial check used libcrypto.so.3 (wrong library).
- **real-074** — **CVE-2026-14456** on **`oci-ruby-3.3`** / component **`openssl`**: pipeline claimed **`NOT_AFFECTED`** (`vulnerable_code_not_present`); hand-check found **`UNDER_INVESTIGATION`**. FINDING-002: D02 on port_default_packet_handler unsound — handler not in libssl.so.3 .dynsym (0 exported) while objdump shows 691 DTLS references, 13 exported DTLS symbols, 43 DTLS strings on oci-redis-7 libssl.so.3. Initial check used libcrypto.so.3 (wrong library).
- **real-086** — **CVE-2026-14456** on **`subst-golang-bookworm`** / component **`openssl`**: **withdrawn as false clearance (FINDING-003).** Observed OpenSSL **3.0.20** (SO + dpkg); PURL asserted 3.0.15. CVE has no 3.0.x range. Original hand label frozen.
- **real-088** — **CVE-2026-14456** on **`oci-memcached-1.6`** / component **`openssl`**: pipeline claimed **`NOT_AFFECTED`** (`vulnerable_code_not_present`); hand-check found **`UNDER_INVESTIGATION`**. FINDING-002: D02 on port_default_packet_handler unsound — handler not in libssl.so.3 .dynsym (0 exported) while objdump shows 691 DTLS references, 13 exported DTLS symbols, 43 DTLS strings on oci-redis-7 libssl.so.3. Initial check used libcrypto.so.3 (wrong library).

**KT-2: FAIL** — false `not_affected` count **16** after FINDING-003 (pre-registered bar: zero). Frozen labels still show 20 disagreements; four are accidental NA.

**Pipeline–human agreement (frozen labels):** **80/100** (**80.00%**). FINDING-003-corrected agreement on the NA subset: **84/100** if the four accidental NAs are scored as agreement.

### Precision / recall per pipeline `reason_code` (refusal rows only)

Computed on statements where the pipeline emitted `UNDER_INVESTIGATION`; precision = TP/(TP+FP), recall = TP/(TP+FN) vs hand `UNDER_INVESTIGATION`.

| reason_code | precision | recall | tp | fp | fn |
|-------------|----------:|-------:|---:|---:|---:|
| `(none)` | — | 0.000 | 0 | 0 | 20 |
| `manifest_no_entry` | 1.000 | 1.000 | 8 | 0 | 0 |
| `mapping_probable_only` | 1.000 | 1.000 | 13 | 0 | 0 |
| `no_identity_mapping` | 1.000 | 1.000 | 9 | 0 | 0 |
| `purl_match_insufficient` | 1.000 | 1.000 | 50 | 0 | 0 |

The four labeled `reason_code` rows show precision and recall **1.000 on refusal rows only**; the `(none)` row (recall **0.000**, fn=**20**) is the frozen-label count of pipeline `NOT_AFFECTED` vs hand `UNDER_INVESTIGATION`. FINDING-003 overlay: **4** of those 20 are accidental NA (real-008, real-031, real-035, real-086); fn would be **16** if rescored. Table not recomputed; `cp11-metrics.json` remains the frozen snapshot.

### Pipeline vs hand label (all disagreements)

Frozen labels below. FINDING-003: DTLS wording withdrawn (CVE-2026-14456 is QUIC). **real-008, real-031, real-035, real-086** are accidental `NOT_AFFECTED`, not remaining disagreements.

- **real-002** **CVE-2026-42767** **`oci-redis-7`** (component `openssl`): pipeline **`NOT_AFFECTED`** → hand **`UNDER_INVESTIGATION`** — FINDING-002: D02 on OSSL_CRMF_ENCRYPTEDVALUE_decrypt unsound — internal symbol absent from .dynsym while OSSL_CRMF_* API is exported and objdump shows 597 CRMF references on oci-redis-7 libcrypto.so.3.
- **real-008** **CVE-2026-14456** **`oci-redis-7`** (component `openssl`): **withdrawn as disagreement (FINDING-003).** Observed OpenSSL **3.0.20**; CVE has no 3.0.x range. Frozen hand label `UNDER_INVESTIGATION`.
- **real-010** **CVE-2026-14456** **`oci-python-3.12`** (component `openssl`): pipeline **`NOT_AFFECTED`** → hand **`UNDER_INVESTIGATION`** — FINDING-002: D02 on port_default_packet_handler unsound — handler not in libssl.so.3 .dynsym (0 exported) while objdump shows 691 DTLS references, 13 exported DTLS symbols, 43 DTLS strings on oci-redis-7 libssl.so.3. Initial check used libcrypto.so.3 (wrong library).
- **real-011** **CVE-2026-14456** **`subst-mosquitto`** (component `openssl`): pipeline **`NOT_AFFECTED`** → hand **`UNDER_INVESTIGATION`** — FINDING-002: D02 on port_default_packet_handler unsound — handler not in libssl.so.3 .dynsym (0 exported) while objdump shows 691 DTLS references, 13 exported DTLS symbols, 43 DTLS strings on oci-redis-7 libssl.so.3. Initial check used libcrypto.so.3 (wrong library).
- **real-013** **CVE-2026-45445** **`subst-golang-bookworm`** (component `openssl`): pipeline **`NOT_AFFECTED`** → hand **`UNDER_INVESTIGATION`** — FINDING-002: D02 clearance unsound — vulnerable symbol not observable in .dynsym on dynamically-linked libcrypto.so.3; symbol absence is guaranteed a priori for internal functions.
- **real-015** **CVE-2026-42767** **`oci-node-20`** (component `openssl`): pipeline **`NOT_AFFECTED`** → hand **`UNDER_INVESTIGATION`** — FINDING-002: D02 clearance unsound — vulnerable symbol not observable in .dynsym on dynamically-linked libcrypto.so.3; symbol absence is guaranteed a priori for internal functions.
- **real-016** **CVE-2026-42767** **`oci-nginx-1.25`** (component `openssl`): pipeline **`NOT_AFFECTED`** → hand **`UNDER_INVESTIGATION`** — FINDING-002: D02 clearance unsound — vulnerable symbol not observable in .dynsym on dynamically-linked libcrypto.so.3; symbol absence is guaranteed a priori for internal functions.
- **real-021** **CVE-2026-14456** **`subst-httpd-alpine`** (component `openssl`): pipeline **`NOT_AFFECTED`** → hand **`UNDER_INVESTIGATION`** — FINDING-002: D02 on port_default_packet_handler unsound — handler not in libssl.so.3 .dynsym (0 exported) while objdump shows 691 DTLS references, 13 exported DTLS symbols, 43 DTLS strings on oci-redis-7 libssl.so.3. Initial check used libcrypto.so.3 (wrong library).
- **real-022** **CVE-2026-42767** **`oci-rabbitmq-3`** (component `openssl`): pipeline **`NOT_AFFECTED`** → hand **`UNDER_INVESTIGATION`** — FINDING-002: D02 clearance unsound — vulnerable symbol not observable in .dynsym on dynamically-linked libcrypto.so.3; symbol absence is guaranteed a priori for internal functions.
- **real-024** **CVE-2026-14456** **`subst-httpd-alpine`** (component `openssl`): pipeline **`NOT_AFFECTED`** → hand **`UNDER_INVESTIGATION`** — FINDING-002: D02 on port_default_packet_handler unsound — handler not in libssl.so.3 .dynsym (0 exported) while objdump shows 691 DTLS references, 13 exported DTLS symbols, 43 DTLS strings on oci-redis-7 libssl.so.3. Initial check used libcrypto.so.3 (wrong library).
- **real-031** **CVE-2026-14456** **`oci-node-20`** (component `openssl`): **withdrawn as disagreement (FINDING-003).** Observed OpenSSL **3.0.19**; CVE has no 3.0.x range. Frozen hand label `UNDER_INVESTIGATION`.
- **real-035** **CVE-2026-14456** **`oci-nginx-1.25`** (component `openssl`): **withdrawn as disagreement (FINDING-003).** Observed OpenSSL **3.0.11**; CVE has no 3.0.x range. Frozen hand label `UNDER_INVESTIGATION`.
- **real-043** **CVE-2026-14456** **`oci-postgres-16`** (component `openssl`): pipeline **`NOT_AFFECTED`** → hand **`UNDER_INVESTIGATION`** — FINDING-002: D02 on port_default_packet_handler unsound — handler not in libssl.so.3 .dynsym (0 exported) while objdump shows 691 DTLS references, 13 exported DTLS symbols, 43 DTLS strings on oci-redis-7 libssl.so.3. Initial check used libcrypto.so.3 (wrong library).
- **real-055** **CVE-2026-42767** **`subst-golang-bookworm`** (component `openssl`): pipeline **`NOT_AFFECTED`** → hand **`UNDER_INVESTIGATION`** — FINDING-002: D02 clearance unsound — vulnerable symbol not observable in .dynsym on dynamically-linked libcrypto.so.3; symbol absence is guaranteed a priori for internal functions.
- **real-063** **CVE-2026-14456** **`oci-python-3.12`** (component `openssl`): pipeline **`NOT_AFFECTED`** → hand **`UNDER_INVESTIGATION`** — FINDING-002: D02 on port_default_packet_handler unsound — handler not in libssl.so.3 .dynsym (0 exported) while objdump shows 691 DTLS references, 13 exported DTLS symbols, 43 DTLS strings on oci-redis-7 libssl.so.3. Initial check used libcrypto.so.3 (wrong library).
- **real-065** **CVE-2026-42767** **`oci-nginx-1.25`** (component `openssl`): pipeline **`NOT_AFFECTED`** → hand **`UNDER_INVESTIGATION`** — FINDING-002: D02 clearance unsound — vulnerable symbol not observable in .dynsym on dynamically-linked libcrypto.so.3; symbol absence is guaranteed a priori for internal functions.
- **real-068** **CVE-2026-14456** **`oci-postgres-16`** (component `openssl`): pipeline **`NOT_AFFECTED`** → hand **`UNDER_INVESTIGATION`** — FINDING-002: D02 on port_default_packet_handler unsound — handler not in libssl.so.3 .dynsym (0 exported) while objdump shows 691 DTLS references, 13 exported DTLS symbols, 43 DTLS strings on oci-redis-7 libssl.so.3. Initial check used libcrypto.so.3 (wrong library).
- **real-074** **CVE-2026-14456** **`oci-ruby-3.3`** (component `openssl`): pipeline **`NOT_AFFECTED`** → hand **`UNDER_INVESTIGATION`** — FINDING-002: D02 on port_default_packet_handler unsound — handler not in libssl.so.3 .dynsym (0 exported) while objdump shows 691 DTLS references, 13 exported DTLS symbols, 43 DTLS strings on oci-redis-7 libssl.so.3. Initial check used libcrypto.so.3 (wrong library).
- **real-086** **CVE-2026-14456** **`subst-golang-bookworm`** (component `openssl`): **withdrawn as disagreement (FINDING-003).** Observed OpenSSL **3.0.20** (SO + dpkg); PURL asserted 3.0.15. CVE has no 3.0.x range. Frozen hand label `UNDER_INVESTIGATION`.
- **real-088** **CVE-2026-14456** **`oci-memcached-1.6`** (component `openssl`): pipeline **`NOT_AFFECTED`** → hand **`UNDER_INVESTIGATION`** — FINDING-002: D02 on port_default_packet_handler unsound — handler not in libssl.so.3 .dynsym (0 exported) while objdump shows 691 DTLS references, 13 exported DTLS symbols, 43 DTLS strings on oci-redis-7 libssl.so.3. Initial check used libcrypto.so.3 (wrong library).

---

## 4. Refusal breakdown (reason codes)

From **`corpus/results/*/decisions.jsonl`** (**15,380** refusal rows; **256** CVE rows on **10** zero/low-finding artifacts lack `decisions.jsonl` from pre-`decisions.jsonl` scans — aggregate refused total **15,636** includes those via `scan-summary.json`).

| Reason code | Count |
|-------------|------:|
| `purl_match_insufficient` | 6591 |
| `mapping_probable_only` | 4183 |
| `no_identity_mapping` | 3370 |
| `manifest_no_entry` | 1180 |
| `symbol_not_observable` | 35 |
| `provenance_unverified` | 21 |

**0** `NOT_AFFECTED` verdicts after the FINDING-002 guard. The pre-guard **35** D02 `vulnerable_code_not_present` clearances now refuse with `symbol_not_observable`. **5** `AFFECTED` (D04) remain; each has an on-disk evidence bundle.

---

## 5. What this result is

We measured **where** a refusal-first, binary-grounded VEX clearance pipeline fails on real shipped artifacts — not whether symbol-table evidence is sufficient in the abstract.

The pipeline **terminates at identity resolution** for **91.9%** of scanner findings and at **manifest lookup** for another **7.7%**. **Zero** findings terminate at S3/S5 symbol-table stages. **35** terminate at S5b (`symbol_not_observable`) — the FINDING-002 guard, not a corpus-scale symbol-evidence test. The binding constraint on binary-grounded VEX clearance at v1 integration is **CVE-to-component identity** (PURL match, distro upstream mapping, manifest coverage) — not evidence availability or stripped-binary limits. The symbol-evidence question is **not yet reachable** in practice for 99.6% of scanner output; that is a different and more useful claim than “symbols don't work.”

The **0.032%** decided rate is real (**5** `AFFECTED` rows with re-derivable bundles). The pre-guard **0.2557%** (40 rows) is the snapshot KT-2 scored. Neither is a corpus-scale answer to KT-1.

### D01 — no natural corpus instance

Corpus scan produced **zero** D01 (`component_not_present`) rows.

| Count | Criterion |
|------:|-----------|
| **55** | Scanned artifacts (`scan-summary.json`) |
| **22** | Grype match where package **name or PURL** names `openssl` / `libssl` / `libcrypto` |
| **19** | `decisions.jsonl` row with `component=openssl` (identity bound) |
| **0** | Grype package-match artifacts with no `libssl.so*` / `libcrypto.so*` on rootfs |

Selection criterion and IDs: `cp11-metrics.json` → `d01_corpus_absence` (re-derive:
`bash scripts/rederive-results.sh`). Path-agnostic check:

```bash
find <rootfs> -name 'libssl.so*' -o -name 'libcrypto.so*'
```

locates OpenSSL shared objects on **all 22** grype package-match artifacts. D01 had no
natural corpus instance. The busybox probe (`go test ./corpus/groundtruth/ -run TestD01Probe -v`)
is synthetic only.

**Interpretation:** grype package presence was correct in every testable case; the open
question was always vulnerable **code** (D02), not component absence (D01). Only **19 / 55**
artifacts ever bound a finding to `component=openssl` — identity resolution limits how
often the pipeline reaches even manifest lookup for OpenSSL CVEs.

---

## 6. Third consecutive NOT EVALUABLE (README §11)

Pre-registered decision rule ([README.md](README.md) **§11**, CP-0), quoted verbatim:

> **§11 — Kill-test evaluability.** KT-1 tests whether ≥30% of scanner-reported CVEs resolve to a decidable `not_affected` with a re-derivable evidence bundle. If refusal-stage attribution shows the instrument did not reach symbol-table or evidence evaluation — zero symbol-table refusals and ≥99% of findings terminate at identity resolution or manifest lookup — KT-1 is **NOT EVALUABLE**, not FAIL; the measured decided rate must not be read as an answer to the pre-registered question. Three consecutive NOT EVALUABLE results on the same corpus after instrument passes intended to restore evaluability constitute a **pattern**; the pre-registered action is **stop**.

**Instrument passes on this corpus (all NOT EVALUABLE when correctly read):**

| Pass | Date | Instrument state | Decided | Correct KT-1 verdict |
|------|------|------------------|--------:|----------------------|
| 1 | 2026-08-23 | Pre-identity layer; 100% `purl_match_insufficient` | 0 / 10,088 | NOT EVALUABLE (RP-1) |
| 2 | 2026-08-24 | Identity aliases + partial manifest; mislabeled | 40 / 15,641 | NOT EVALUABLE (this correction) |
| 3 | 2026-08-24 | S-15 re-run confirms refusal-stage histogram | 40 / 15,641 | NOT EVALUABLE |

**Pattern met → stop.** Do not publish the 0.2557% rate as a scientific negative about firmware or symbols. Do not lower the 30% threshold. Do not claim corpus-scale clearance or its absence until evaluability is restored and KT-1 is re-run.

---

## 7. Limitations

1. **Manifest seed (25 components, ~29 CVE entries after OpenSSL expansion)** — most scanner CVE/component pairs have no manifest entry (`manifest_no_entry`: **1180** refusals on decided-path artifacts).
2. **Identity layer immature** — **9/10** aliases remain `probable`; only **expat** is hand-verified `definitive`. **`mapping_probable_only`** (**4183**) and **`no_identity_mapping`** (**3370**) dominate refusals.
3. **Firmware extraction** — flash images scanned via **profile-rootfs** extraction (binwalk/unsquashfs); **83%** stripped binaries corpus-wide; symbol rules rarely reachable on firmware stratum (**1/5553** decided).
4. **Unreachable / failed fetches** — TP-Link GPL portal, Netgear GPL source zips, Buildroot prebuilt (recorded in `corpus/FIRMWARE-FETCH-LOG.txt`); **7** `substitute-container` stand-ins retained with honest class labels.
5. **Static / musl release binaries** — **8** static-binary artifacts: **0** decided; grype Go/stdlib noise without manifest alignment.
6. **Rules not exercised at scale** — D01 had **no natural corpus instance** (see §5); D04 (`AFFECTED`) fired **5** times (OpenSSL symbol-present paths on OCI apps).
7. **KT-2 FAIL (soundness)** — [FINDING-002.md](FINDING-002.md): **28 of 35** corpus D02 clearances unsound where the CVE applies; **7** accidental NA on CVE-2026-14456 / 3.0.x ([FINDING-003.md](FINDING-003.md)). Frozen labels: **20/20** pipeline `NOT_AFFECTED` vs hand `UNDER_INVESTIGATION`. Overlay: **16 of 20** remain false clearances. **80/80** refusal rows agree. Post-guard re-decide converted the 35 D02 rows to `symbol_not_observable`.
8. **Frozen KT-2 snapshot** — `real-100.yaml` scores the pre-guard S-15 pipeline (see §3); not rescored after the guard or after FINDING-003 (deliberate pre-registration discipline). Overlay lives in `amendment_2026_08_25`; `cp11-metrics.json` still reports `false_not_affected: 20`.
9. **D01: no corpus instance; one synthetic probe** — **22 / 55** grype package-match;
   **19 / 55** `component=openssl` in `decisions.jsonl`; `.so` on **all 22** (see §5);
   **zero** D01 rows; busybox probe did not fail but is not KT evidence.
10. **OpenSSL-only soundness path** — All **35** pre-guard D02 clearances and all **20** frozen-label KT-2 NA disagreements are OpenSSL internal-symbol CVEs; other components untested at the evidence stage. Version applicability was never computed (FINDING-003); a version gate would have caught **7 of 40** pre-guard decisions.
11. **Layout assumptions** — Engine and analysis scripts initially assumed Debian multiarch paths (`usr/lib/*/`); three false D01 candidates (including Netgear) cleared only after path-agnostic search — same defect class as FINDING-002 wrong-library check. FINDING-003 adds a fourth instance: RabbitMQ D04 `symbols_present` on `/opt/openssl` **3.1.8** while the finding is bound to distro **3.0.13** — unsupported `AFFECTED` that happens to be version-right.
12. **Firmware stratum size** — **12** firmware-class artifacts; **1/5,553** decided post-guard.
13. **No refitting** — taxonomy, alias promotion, and manifest expansion needed for v2 are **future work** (`IDEAS.md`, SPEC-IDENTITY §10); this document reports v1 honest output only.
14. **FINDING-001 / pairing-matrix tool paths** — Tool binaries used for the FINDING-001 and pairing-matrix work live in `.lading/tools/`, which is gitignored. They are therefore not independently verifiable from the repository; recording their SHA-256 hashes against official release checksums is the mitigation. The SPDX and pairing-matrix figures reported here were computed from cached SBOMs under `.lading/spdx-anomaly/` rather than regenerated at write time.
15. **Version string vs distro backport** — FINDING-003 observed versions use `strings -a` plus `dpkg`/`apk`. A rebuilt or patched distro object can carry a version token that does not reflect backported fixes (Debian’s CVE handling). In-range / out-of-range calls use that upstream token; they do not prove a specific Debian patch.

---

## Decision

| Outcome | Result | Action |
|---------|--------|--------|
| KT-1 ≥30% | **NOT EVALUABLE** (0.032% measured after guard; 0.2557% pre-guard snapshot; instrument did not reach evidence stage at corpus scale) | Stop per README §11; do not publish as FAIL or as corpus-scale negative |
| KT-2 zero false NA | **FAIL** | Frozen labels **20/20**; FINDING-003 overlay **16/20** remaining false clearances; engine guard `symbol_not_observable` added; version still uncomputed |
| **Combined gate** | **Stop** | KT-2 unsound; KT-1 third consecutive NOT EVALUABLE (§11) |

---

## Reproduce

```bash
go build -o bin/lading ./cmd/lading
bash scripts/corpus-download.sh          # if payloads absent
bash scripts/corpus-scan.sh              # or scripts/corpus-redecide.sh for re-eval only
python3 scripts/sample-real-groundtruth.py
bash scripts/rederive-results.sh
grep -nE 'KT-1: NOT EVALUABLE|KT-2: (PASS|FAIL|NOT EVALUABLE)|third consecutive' RESULTS.md
```
