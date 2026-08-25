# Binary-grounded VEX clearance fails twice: upstream of evidence, and on internal symbols

**Gautam Khosla**  
Draft · 2026-08-24 · Engine `evidence-v1` · Commit `97eca4038f5d2e7ff6a4e053c01a1a0841671eb1`

All figures re-derive from `bash scripts/rederive-results.sh` → `corpus/results/cp11-metrics.json`,
except FINDING-003 counts (28/35, 16/20, 7/40), which are read from `decisions.jsonl`
and advisory ranges and are **not** in `cp11-metrics.json`.

**Correction (2026-08-25, [FINDING-003.md](FINDING-003.md)):** Version applicability was
never computed. Corpus OpenSSL is seven versions, not a single 3.0.20. **28 of 35**
pre-guard D02 rows remain unsound; **7** are accidental `NOT_AFFECTED` (CVE-2026-14456
has no 3.0.x range). KT-2 overlay: **16 of 20** remaining false clearances (frozen labels
still 20/20). CVE-2026-14456 is QUIC, not DTLS. The five `AFFECTED` rows are not all
CVE-2023-0286 / `GENERAL_NAME_cmp`. RabbitMQ D04 is an unsupported verdict that happens
to be version-right. A version gate would have terminated **7 of 40** pre-guard
decisions. `real-100.yaml` `human_label` values are frozen; overlay is
`amendment_2026_08_25`.

---

## Abstract

We measured a refusal-first pipeline that would clear scanner CVEs only with re-derivable
binary evidence across **55** shipped artifacts, **15,641** grype CVE rows, and **27,670**
inventoried binaries. Two pre-registered kill tests resolve with real numbers:

**Result 1 (reach).** **99.6%** of decisions terminate at identity resolution (**91.9%**)
or manifest lookup (**7.7%**) before symbol-table gates. **Zero** S3/S5 symbol-stage
refusals. KT-1 (≥30% decided with evidence) is **NOT EVALUABLE** — the instrument never
reached symbol evaluation at corpus scale. Post-guard decided rate: **5 / 15,641 = 0.032%**
(all `AFFECTED`).

**Result 2 (soundness).** On the **40** paths that did decide before the guard, **35**
used D02 (`vulnerable_code_not_present`) on **internal** OpenSSL symbols — absent from
`.dynsym` by construction while related code ships in the `.so`. **28 of 35** are
unfalsifiable where the CVE applies ([FINDING-002.md](FINDING-002.md)). **7 of 35** are
accidental `NOT_AFFECTED`: CVE-2026-14456 does not apply to OpenSSL 3.0.x, a fact nobody
computed ([FINDING-003.md](FINDING-003.md)). KT-2 on **100** hand-labeled real
statements: **FAIL** — frozen labels **20/20** pipeline `not_affected` vs hand
`UNDER_INVESTIGATION`; overlay **16/20** remaining false clearances; **80/80** refusals
agree. Version applicability was never computed; a version gate would have terminated
**7 of 40** pre-guard decisions. This is not bidirectional unsoundness: the seven
accidental NAs and three of the five `AFFECTED` rows are version-plausible for the CVEs
they decided; two RabbitMQ D04 rows are unsupported as to which binary the symbol was
observed on.

A post-hoc D01 probe on `oci-busybox-latest` / `busybox` did not fail on the single
synthetic case tested; D01 had **no natural corpus instance** and is untested at scale.
Of **55** scanned artifacts, **22** have grype matches on package name/PURL naming OpenSSL;
path-agnostic `find` locates `libssl`/`libcrypto` on **all 22** (**0** without) — only
**19** ever bind `component=openssl` in the pipeline. Grype package presence was correct
in every testable case on **name**; FINDING-003 records a **version** mismatch on
`subst-golang-bookworm` (PURL `3.0.15`, `.so` and dpkg `3.0.20`). The open question on
in-range rows was vulnerable **code**, which D02 could not answer. The precise claim:
**D02 on internal symbols is unsound where the CVE applies; version applicability was
never computed; D01 did not fail on one synthetic probe but had no corpus instance;
identity resolution is the binding constraint at corpus scale.**

Negative result under a pre-registered stop rule (README §11).

---

## 1. Introduction

Under the EU Cyber Resilience Act and comparable regimes, manufacturers must document
vulnerabilities in products they place on the market. Automated **binary-grounded**
clearance would matter if it worked: map each scanner CVE to binaries on disk, consult a
curated manifest, emit VEX (`not_affected` / `affected`) only with a re-derivable evidence
bundle — or refuse.

We built that pipeline (`evidence-v1`, [SPEC-EVIDENCE.md](SPEC-EVIDENCE.md)) and measured
where it fails on firmware, containers, static release binaries, and SDK archives. The
paper reports two independent results:

1. **Reach** — the pipeline stops before evidence evaluation for almost all scanner output.
2. **Soundness** — where it did clear, the evidence type could not support the claim.

Neither Churakova et al. (VEX tool consistency) nor Rasheed et al. (VEX scope asymmetry)
measure refusal-stage termination on heterogeneous shipped artifacts or demonstrate a
named, reproducible false-clearance mode on internal library symbols. Result 2 is the
sharper contribution.

---

## 2. Related work

### Churakova, Ekstedt, and Schmid — “Vexed by VEX Tools” (arXiv:2503.14388)

Cross-tool consistency on **48** Docker images; divergence tracks vulnerability-database
coverage. No false-`not_affected` scoring, no binary inspection.

### Rasheed et al. — “Hidden Dependencies and Component Variants…” (arXiv:2604.21278)

VEX scope asymmetry on Java fixtures (Grype inert, Trivy overbroad). No stage-attributed
termination on firmware plus containers.

### SBOM identity (prior art)

Cofano (~80% vulnerability loss from low SBOM precision), Benedetti (~20% identifiable),
Dann (~34% TP on Java scanners). Our contribution is **locating where identity terminates
a binary-grounded pipeline**, not discovering that identity is hard.

See `RELATED-WORK.md` for full conservative positioning.

---

## 3. Method

### 3.1 Pre-registered kill tests

| ID | Question | Pass bar | Outcome |
|----|----------|----------|---------|
| **KT-1** | Fraction of scanner CVE rows that decide with re-derivable evidence | ≥**30%** | **NOT EVALUABLE** |
| **KT-2** | Any false `not_affected` in 100 hand-verified real statements | **0** false NA | **FAIL** |

**Evaluability (README §11):** If ≥**99%** terminate at identity/manifest and **zero**
S3/S5 symbol refusals, KT-1 is **NOT EVALUABLE**, not FAIL. Three consecutive NOT
EVALUABLE → **stop**.

### 3.2 Corpus and procedure

**53** product artifacts in `corpus/ARTIFACTS.yaml` **`cp11-3`** (**12** firmware-class);
**55** scan dirs; hashes verified. Per artifact: grype → `lading scan` → `decisions.jsonl`.
Manifest seed: **25** components (`0.2.0`); **10** identity aliases (**1** definitive).

### 3.3 Refusal stages

S1 identity → S2 manifest → S3 symbol usability → S4 provenance → S5 stripped gates →
**S5b** observability (`symbol_not_observable`, post-FINDING-002) → S7 evidence.
Attributed by `bash scripts/refusal-stages.sh`.

### 3.4 KT-2 sample and frozen snapshot

`corpus/groundtruth/real-100.yaml` (seed **20260824**): **100** statements from real
`decisions.jsonl` — **80** refusals, **20** pre-guard `NOT_AFFECTED`.

**Frozen snapshot discipline:** Each row's `pipeline_verdict` is from the S-15 decide run
**before** the FINDING-002 guard. KT-2 scores whether those clearances were sound **when
emitted**. Rescoring against the post-fix engine would test a different instrument in
response to the finding and void the kill test. Post-guard corpus numbers are reported
separately (§4.2).

### 3.5 D01 — no natural corpus instance; synthetic probe only

Corpus scan produced **zero** D01 (`component_not_present`) rows. For the D01-absence
check we selected artifacts where grype reports a match on a package whose **name or PURL**
names `openssl`, `libssl`, or `libcrypto` — **22 / 55** scanned artifacts (`cp11-metrics.json`
→ `d01_corpus_absence`; not the **19** artifacts where `decisions.jsonl` bound
`component=openssl`, and not a substring grep of the whole grype JSON). On each profile
rootfs:

```bash
find <rootfs> -name 'libssl.so*' -o -name 'libcrypto.so*'
```

locates `libssl`/`libcrypto` on **all 22** — **0** without a matching shared object.
Layout-assumption caveats for this search are in §6. The busybox probe
(`go test ./corpus/groundtruth/ -run TestD01Probe -v`) is a synthetic existence proof only.

---

## 4. Results

### 4.1 Result 1 — termination upstream of evidence

On **`decisions.jsonl`** (**n = 15,385**, post-guard re-decide):

| Stage | Terminations | % | Cumulative % |
|-------|-------------:|--:|-------------:|
| **S1** identity_resolution | **14,144** | **91.93%** | 91.93% |
| **S2** manifest_lookup | **1,180** | **7.67%** | **99.60%** |
| S3 symbol_table_usability | **0** | 0.00% | 99.60% |
| S4 provenance_gate | 21 | 0.14% | 99.74% |
| S5 symbol_stripped_gates | **0** | 0.00% | 99.74% |
| S5b symbol_observability | 35 | 0.23% | 99.97% |
| S7 decided | **5** | 0.03% | 100.00% |

**Reached S3+:** **61** (21 provenance + 35 S5b + 5 decided). **S3/S5 symbol refusals:** **0**.

Dominant reason codes: `purl_match_insufficient` (**6,591**), `mapping_probable_only`
(**4,183**), `no_identity_mapping` (**3,370**), `manifest_no_entry` (**1,180**).

Identity termination is **not uniform across packaging ecosystems.** On the three
RPM-base corpus artifacts (`oci-fedora-40`, `oci-rockylinux-9`, `oci-ubi9-minimal`),
`no_identity_mapping` alone accounts for **19**, **318**, and **61** refusals respectively —
not a `.src.rpm` normalization failure but **no alias entry at all** in a manifest seed
that is Debian-shaped (`manifest/data/identity-aliases.json`: **10** rows, **9** probable).
RPM artifacts fail at identity **earlier** than deb OCI apps.

Firmware stratum (**5,553** findings, **12** artifacts): **95.5%** S1, **4.3%** S2,
**1** decided (**0.02%**).

### 4.2 KT-1 — NOT EVALUABLE

| Metric | Post-guard | Pre-guard (KT-2 snapshot) |
|--------|----------:|--------------------------:|
| Decided | **5** / 15,641 (**0.032%**) | **40** / 15,641 (**0.2557%**) |
| `NOT_AFFECTED` + bundle | **0** | **35** |
| `AFFECTED` | **5** | **5** |

Neither rate answers the pre-registered ≥30% question: **99.60%** never reached evidence
evaluation. Initial KT-1 **FAIL** label (0.2557% < 30%) withdrawn (CP-A3).

### 4.3 Result 2 — D02 on internal symbols is unfalsifiable (FINDING-002)

Where identity and manifest gates cleared (pre-guard), **35 / 40** decided rows were
**NOT_AFFECTED** via D02 on OpenSSL CVEs whose vulnerable symbols are **file-static** —
never exported on `.dynsym` in stripped, dynamically-linked builds.

**FINDING-003 split.** **28 of 35** are unsound: the CVE applies, and D02 on an
unobservable internal symbol is unfalsifiable. **7 of 35** (CVE-2026-14456 on OpenSSL
3.0.x) are accidental `NOT_AFFECTED` — the advisory excludes 3.0.x; nobody computed
that. Corpus OpenSSL is seven versions, not 3.0.20.

Evidence from oci-redis-7 (OpenSSL **3.0.20** — in range for 42767 and 45445; **out of
range** for 14456):

| CVE | Symbol | Library | `.dynsym` | Code present |
|-----|--------|---------|-----------|--------------|
| CVE-2026-42767 | `OSSL_CRMF_ENCRYPTEDVALUE_decrypt` | `libcrypto.so.3` | absent (CRMF API exported) | **597** `crmf` refs in `.text` |
| CVE-2026-45445 | `aes_ocb_cipher` | `libcrypto.so.3` | **0** exported | **304** `ocb` refs |
| CVE-2026-14456 | `port_default_packet_handler` | `libssl.so.3` | **0** exported | QUIC handler; not DTLS. This artifact is 3.0.20, which the advisory excludes. Unsound 14456 rows are the **15** on 3.5.x. |

**Withdrawn (DTLS wording):** earlier text treated 691 `dtls` refs / 13 exported DTLS
symbols / 43 DTLS strings on this 3.0.20 `libssl.so.3` as proof the vulnerable code is
present. CVE-2026-14456 is a QUIC incoming-channel DoS, present since 3.5. The symbol
is the patch-touched function in `ssl/quic/quic_port.c`. The initial wrong-library
check (`libcrypto.so.3`) is retained only as the reason the measurement was re-run.

**Contrast (exported, D02-sound in principle):** `GENERAL_NAME_cmp` is exported from
`libcrypto.so.3` (`T GENERAL_NAME_cmp@@OPENSSL_3.0.0`) — CVE-2023-0286 only.

**Withdrawn (PAPER.md 200–202):** this draft previously asserted that all five
post-guard `AFFECTED` rows use the `GENERAL_NAME_cmp` path. They do not. One is
CVE-2023-0286 / `GENERAL_NAME_cmp` on Netgear 1.0.2h (in range). Two are
CVE-2026-45445 / `aes_ocb_cipher` on oci-node-20 3.0.19 (in range, symbol in
`/usr/local/bin/node` `.symtab`). Two are CVE-2026-45445 on oci-rabbitmq-3: finding
PURL 3.0.13 is in range, but `symbols_present` evidence is `/opt/openssl` **3.1.8**,
not the distro 3.0.13 object — an unsupported `AFFECTED` that happens to be
version-right ([FINDING-003.md](FINDING-003.md)).

**Mechanism:** On a dynamically-linked `.so`, D02 observes only `.dynsym`. Internal
functions are absent from the export map whether or not their code is compiled in.
Absence is guaranteed a priori → verdict unfalsifiable.

Post-guard engine response: refuse D02 when `dynsym_export_verified` is unset
(`symbol_not_observable`, S5b). All **35** D02 rows converted to S5b. That guard is
observability-only; version applicability is still uncomputed. A version gate would
have terminated **7 of 40** pre-guard decisions before any symbol rule.

Full analysis: [FINDING-002.md](FINDING-002.md), [FINDING-003.md](FINDING-003.md).

### 4.4 KT-2 — FAIL

| Metric | Frozen labels | FINDING-003 overlay |
|--------|--------------:|--------------------:|
| Hand labels | **100 / 100** | same file; `human_label` unchanged |
| False `not_affected` | **20 / 20** pipeline `NOT_AFFECTED` rows | **16 / 20** remaining; **4** accidental NA (real-008, real-031, real-035, real-086) |
| Refusal agreement | **80 / 80** | **80 / 80** |
| **Verdict** | **FAIL** | **FAIL** (bar was one) |

All **20** frozen disagreements are OpenSSL D02 on the three internal-symbol CVEs.
Overlay: **16** remain false clearances (FINDING-002 holds; CVE applies). **4** are
accidental `NOT_AFFECTED` (CVE-2026-14456 vs observed 3.0.x). Hand check on the
frozen file is still `UNDER_INVESTIGATION`; the overlay lives in
`amendment_2026_08_25`. On refusal rows only, precision and recall are **1.000** for
the four labeled `reason_code` values; the `(none)` row (recall **0.000**, fn=**20**)
is the frozen-label count. `cp11-metrics.json` was not re-derived.

### 4.5 D01 — no corpus instance; synthetic probe only

**Corpus measurement (CP-11, 55 scanned artifacts):**

| Count | Criterion |
|------:|-----------|
| **55** | Artifacts with `scan-summary.json` |
| **22** | Grype match on package **name or PURL** naming `openssl` / `libssl` / `libcrypto` |
| **19** | At least one `decisions.jsonl` row with `component=openssl` (identity bound) |
| **0** | Grype package-match artifacts with **no** `libssl.so*` / `libcrypto.so*` on rootfs |

The D01-absence check uses the **22** grype package-match set, not the **19**
identity-bound set. Three RPM-base images (`oci-fedora-40`, `oci-rockylinux-9`,
`oci-ubi9-minimal`) appear in the **22** but not the **19** — grype sees OpenSSL packages,
but identity never mapped them to `component=openssl` (Result 1). Path-agnostic `find` on
each of the **22** locates OpenSSL shared objects; D01 (`component_not_present`) had no
natural corpus instance.

**Synthetic probe:** `oci-busybox-latest` / `busybox` — no OpenSSL on rootfs. With a libssl3
PURL → D01 / `component_not_present`. D01 did not fail on this one artifact; corpus-scale
D01 soundness remains untested.

**Interpretation:** for every grype package-match case we could test, scanner **name**
presence was correct; FINDING-003 records a **version** mismatch on
`subst-golang-bookworm`. On in-range rows the open question was vulnerable **code** —
precisely what D02 could not answer.

### 4.6 Binary profile

**27,670** binaries inventoried; **83.0%** stripped. Firmware: **75%** stripped,
**43%** static-linked — the profile that would favor symbol rules if identity cleared.
Stripping did not bind: identity stopped evaluation first.

---

## 5. Discussion

### Two independent stop reasons

| | KT-1 | KT-2 |
|---|------|------|
| Question | Can the pipeline decide at scale? | Are decided clearances sound? |
| Answer | **NOT EVALUABLE** — stops at identity | **FAIL** — D02 unfalsifiable on internals where the CVE applies; version never computed |
| Implication | Fix identity before measuring clearance rate | D02 needs export verification or disassembly |

Per §11, **both** justify stop: unreachable instrument **and** unsound clearances where
it did reach evidence.

### What D02 requires going forward

D02 is sound only for symbols verified in `.dynsym` on reference builds
(`dynsym_export_verified`). Internal functions need **disassembly-level** evidence of
absence — not export-map absence on the consumer binary. The engine must also know
**which library** hosts a symbol; searching every inventoried `.dynsym` indiscriminately
allowed the wrong-library CVE-2026-14456 check until corrected.

### What D01 implies

`component_not_present` uses identity symbols and `DT_NEEDED` — observable on stripped
dynamic binaries. FINDING-002 explicitly leaves D01 unaffected. The corpus produced **zero**
D01 rows because no artifact paired an OpenSSL scanner finding with absent OpenSSL
binaries; the busybox probe is synthetic only. D01 did not fail on that probe; corpus-scale
D01 soundness remains untested.

### What would have to change (measurement-informed)

1. Verifiable distro source-package ↔ upstream mappings (S1 dominates today).
2. PURL `upstream=` as assertion, not evidence ([FINDING-001.md](FINDING-001.md)).
3. Manifest depth beyond **25** seed components.
4. A version-applicability gate before any symbol rule
   ([FINDING-003.md](FINDING-003.md)); the observability guard did not close that hole.

---

## 6. Limitations

1. **Single engine implementation** — `evidence-v1`; not independently reimplemented.
2. **Frozen KT-2 snapshot** — scores pre-guard pipeline; deliberate pre-registration
   discipline (§3.4).
3. **OpenSSL-only soundness path** — all **35** D02 clears and **20** frozen KT-2 NA
   disagreements are OpenSSL internal-symbol CVEs; other components untested at evidence
   stage. Overlay: **28 of 35** unsound; **16 of 20** remaining false clearances
   ([FINDING-003.md](FINDING-003.md)). Observed versions use `strings -a` plus
   `dpkg`/`apk`; a rebuilt or patched distro object can carry a version token that does
   not reflect backported fixes (Debian’s CVE handling). FINDING-003 in-range /
   out-of-range calls use that upstream token; they do not prove a specific Debian patch.
4. **D01: no corpus instance; one synthetic probe** — **22 / 55** artifacts have grype
   package-name/PURL OpenSSL matches; **19 / 55** bind `component=openssl` in
   `decisions.jsonl`; path-agnostic `find` locates `.so` on **all 22**; **zero** D01 rows
   in scan; busybox probe did not fail but is not KT evidence.
5. **Layout assumptions** — analysis scripts and the engine initially assumed Debian
   multiarch paths (`usr/lib/*/`); three false D01 candidates (including Netgear) cleared
   only after path-agnostic search — same defect class as the wrong-library CVE-2026-14456
   check (FINDING-002). RabbitMQ D04 `symbols_present` on `/opt/openssl` 3.1.8 vs finding
   PURL 3.0.13 is a fourth instance (FINDING-003).
6. **Firmware stratum** — **12** artifacts; **1/5,553** decided post-guard.
7. **Manifest seed** — **25** components; **7** provenance-verified.
8. **Identity aliases** — **9/10** probable only.
9. **Three instrument passes, three NOT EVALUABLE** readings (documented in
   [RESULTS.md](RESULTS.md) §6).
10. **Single scanner** — grype **0.115.0** only.
11. **No threshold refitting.**

---

## 7. Stop decision

Under README §11:

**Stop.** KT-1 **NOT EVALUABLE** (third consecutive). KT-2 **FAIL** (frozen 20/20;
overlay **16/20** remaining false clearances). Post-guard: **0** `not_affected`,
**5** `affected`, **0.032%** decided. Version applicability was never computed.

**Publish:** A stage-attributed termination map plus a named internal-symbol D02 failure
mode with re-derivable binary evidence, plus the missing version gate
([FINDING-003.md](FINDING-003.md)) — not a clearance product.

**Do not publish:** The pipeline rarely clears **and** where the CVE applied, D02
clearance on internal symbols was unfalsifiable. Those are different claims; both are
supported. Do not publish that every decided row was the wrong verdict: seven D02 NAs
and three of five `AFFECTED` rows are version-plausible; two RabbitMQ D04 rows are
unsupported, not version-wrong.

---

## Appendix A — Instrument summary

| Artifact | Purpose |
|----------|---------|
| `SPEC-EVIDENCE.md` | Normative `evidence-v1` rules |
| `cmd/lading/` | Reference implementation |
| `FINDING-002.md` | Soundness failure evidence |
| `corpus/groundtruth/d01_probe_test.go` | D01 post-hoc probe |
| `scripts/rederive-results.sh` | Reproduce headline numbers |

---

## Appendix B — Figure provenance

| Claim | Source | Re-derive |
|-------|--------|-----------|
| Stage table §4.1 | `REFUSAL-STAGES.md` | `bash scripts/refusal-stages.sh` |
| KT-1/KT-2 §4.2–4.4 | `cp11-metrics.json` | `bash scripts/rederive-results.sh` |
| FINDING-002 evidence §4.3 | `FINDING-002.md` | manual + `objdump`/`nm`/`strings` |
| D01 corpus absence §4.5 | `cp11-metrics.json` → `d01_corpus_absence` | `bash scripts/rederive-results.sh` |
| D01 synthetic probe §4.5 | `d01_probe_test.go` | `go test ./corpus/groundtruth/ -run TestD01Probe` |
| KT-2 labels §4.4 | `real-100.yaml` | `go test ./corpus/groundtruth/ -run TestKT2` |

---

## References (selected)

- Churakova, Ekstedt, Schmid. arXiv:2503.14388 — VEX tool consistency.
- Rasheed et al. arXiv:2604.21278 — hidden dependencies and component variants.
- Cofano et al.; Benedetti et al.; Dann et al. — SBOM/scanner precision.
- OpenVEX / CycloneDX VEX / CSAF — machine-readable exploitability formats.
