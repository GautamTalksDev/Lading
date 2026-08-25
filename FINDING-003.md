# FINDING-003: Version applicability was never computed

**Status:** Draft. Not published. Labels, manifest, RESULTS, and PAPER are frozen until this finding is committed.
**Date of measurement:** 2026-08-25
**Measurement record:** [audit/CP-V2-RECHECK.md](audit/CP-V2-RECHECK.md)
**Author:** Gautam Khosla

## Claim

Three independent layers failed to compute whether a CVE applies to the OpenSSL version on the artifact:

1. **The scanner** reported CVEs on artifacts whose observed version the advisory excludes, and on one artifact (`subst-golang-bookworm`) reported a version the package metadata and shipped object both contradict. Emitting a finding the scanner cannot fully adjudicate is not the defect; the triage tool is what was supposed to filter it.
2. **The engine** never compares a finding version to manifest `affected_versions` before a symbol rule fires. That is where the gate should have been, and provably is not.
3. **The human verifier** scored the symbol-observability question without asking whether the CVE applied.

FINDING-002 found the symbol defect. The guard that followed fixed the symbol defect. The version defect sat underneath it, untouched. On the rows where the CVE does apply, FINDING-002 still holds. On the rows where it does not, `NOT_AFFECTED` was the right verdict for a reason nobody computed.

This is not a wording fix. Every version-sensitive claim in the paper treated the corpus as OpenSSL 3.0.20. The corpus has seven.

## Advisory ground truth (2026-08-25)

Verified against nvd.nist.gov and openssl-library.org. CVE-2026-14456 advisory text from `https://openssl-library.org/news/secadv/20260813.txt`: “OpenSSL 4.0, 3.6 and 3.5 are vulnerable to this issue. OpenSSL 3.4, 3.0, 1.1.1 and 1.0.2 are not affected.” Present since 3.5, when the QUIC server was added. **Not DTLS.**

| CVE | Affected ranges | 3.0.20 |
|-----|-----------------|--------|
| CVE-2026-42767 | 3.0.0 to <3.0.21, 3.4.0 to <3.4.6, 3.5.0 to <3.5.7, 3.6.0 to <3.6.3, 4.0.0 | in range |
| CVE-2026-45445 | 3.0.0 to <3.0.21, plus 3.4 / 3.5 / 3.6 / 4.0 | in range |
| CVE-2026-14456 | 4.0.0 to <4.0.2, 3.6.0 to <3.6.4, 3.5.0 to <3.5.8. No 3.0.x range. | **not** in range |
| CVE-2023-0286 | 1.0.2 to <1.0.2zg, 1.1.1 to <1.1.1t, 3.0.0 to <3.0.8 | **not** in range |

Published assumption of a single corpus version: FINDING-002.md line 7 (“Evidence (oci-redis-7, OpenSSL 3.0.20)”); PAPER.md line 188 (“Evidence from oci-redis-7 (OpenSSL **3.0.20**)”).

## Seven observed OpenSSL versions

Primary observation: `strings -a` of the profile-rootfs `libcrypto` shared object, first line matching `^OpenSSL [0-9]+\.[0-9]+\.[0-9]+`. Package metadata (`dpkg` / `apk`) as corroboration. Finding PURLs from `decisions.jsonl` are not treated as ground truth.

**Limitation.** A rebuilt or patched distro object can carry a version string that does not reflect backported fixes, which is exactly how Debian handles CVEs. `strings` plus `dpkg`/`apk` identify the upstream version token the advisory ranges are written in; they do not prove the presence or absence of a specific Debian patch. This finding’s in-range / out-of-range calls use that upstream token.

| Version string | How determined | Artifacts that produced a decision on the four CVEs |
|----------------|----------------|-----------------------------------------------------|
| **1.0.2h** | `strings` on `lib/libcrypto.so.1.0.0` → `OpenSSL 1.0.2h  3 May 2016` | fw-netgear-r7000-firmware-1.0.12.216 |
| **3.0.11** | `strings` → `OpenSSL 3.0.11 19 Sep 2023`; dpkg `libssl3`/`openssl` `3.0.11-1~deb12u2` | oci-nginx-1.25 |
| **3.0.13** | `strings` on distro `usr/lib/x86_64-linux-gnu/libcrypto.so.3` → `OpenSSL 3.0.13 30 Jan 2024`; dpkg `3.0.13-0ubuntu3.6` | oci-rabbitmq-3 (distro package under test) |
| **3.0.19** | `strings` → `OpenSSL 3.0.19 27 Jan 2026` on distro libcrypto **and** `/usr/local/bin/node`; dpkg `3.0.19-1~deb12u2` | oci-node-20 |
| **3.0.20** | `strings` → `OpenSSL 3.0.20 7 Apr 2026`; dpkg `libssl3` `3.0.20-1~deb12u2` (oci-redis-7). subst-golang: same SO string; distroless `var/lib/dpkg/status.d/libssl3` `Version: 3.0.20-1~deb12u2` | oci-redis-7, subst-golang-bookworm |
| **3.5.6** | `strings` → `OpenSSL 3.5.6 7 Apr 2026`; dpkg `libssl3t64`/`openssl` `3.5.6-1~deb13u2` | oci-httpd-2.4, oci-memcached-1.6, oci-postgres-16, oci-python-3.12, oci-ruby-3.3 |
| **3.5.7** | `strings` → `OpenSSL 3.5.7 9 Jun 2026`; apk `libssl3`/`libcrypto3` `3.5.7-r0` | subst-httpd-alpine, subst-memcached-alpine, subst-mosquitto |

A second copy on oci-rabbitmq-3 is **3.1.8** (`strings` on `/opt/openssl/lib/libcrypto.so.3` → `OpenSSL 3.1.8 11 Feb 2025`). That is not a seventh corpus distro; it is the wrong-binary defect below.

## The engine has no version gate

`internal/decide/evaluate.go` never reads `affected_versions`. After `checkD03`, symbol presence fires D04; symbol absence plus `dynsym_export_verified` fires D02; otherwise S5b:

```go
if ctx.anyDefinitivePresent() {
    base.Verdict = VerdictAffected
    base.RuleID = RuleD04
    return base, nil
}

if ctx.componentIdentified && len(ctx.definitiveSymbols) > 0 {
    if !ctx.allDefinitiveSymbolsDynsymExportVerified() {
        base.Verdict = VerdictUnderInvestigation
        base.RuleID = RuleD03
        base.ReasonCode = ReasonSymbolNotObservable
        return base, nil
    }
    base.Verdict = VerdictNotAffected
    base.Justification = JustificationVulnerableCodeNotPresent
    base.RuleID = RuleD02
    return base, nil
}
```

`buildContext` loads `ctx.entry` only to take `definitiveSymbols`. Grep of `internal/decide` for `AffectedVersions` hits test fixtures only. The FINDING-002 guard (`symbol_not_observable`) is observability-only. Version applicability is still uncomputed.

The manifest lists exact strings (SPEC-MANIFEST.md: no ranges). CVE-2026-14456’s list has no 3.0.x. That did not stop D02 on 3.0.11 / 3.0.19 / 3.0.20, because the list is unused.

## Size of the missing gate

A version gate cannot be scored over all **15,385** attributed `decisions.jsonl` rows: RESULTS.md line 84, **99.60%** terminate at S1 or S2 before any symbol-table gate. The paper’s reachable set is the **61** that reached S3 or later (21 provenance + 35 S5b + 5 decided) and, for decided rows, the pre-guard **40** (35 D02 + 5 D04).

Over those 40, using observed OpenSSL versions from the table above and the advisory ranges in this finding — no re-run of `decide`:

| Pre-guard decision | n | Version gate would terminate before a symbol rule? |
|--------------------|--:|-----------------------------------------------------|
| CVE-2026-14456 D02 on 3.0.x (nginx 3.0.11 ×2, node 3.0.19 ×2, redis 3.0.20 ×1, golang 3.0.20 ×2) | 7 | **yes** — no 3.0.x range |
| CVE-2026-14456 D02 on 3.5.6/3.5.7 | 15 | no — in `3.5.0 to <3.5.8` |
| CVE-2026-42767 D02 on 3.0.x | 9 | no — in `3.0.0 to <3.0.21` |
| CVE-2026-45445 D02 on 3.0.x | 4 | no — in `3.0.0 to <3.0.21` |
| CVE-2023-0286 D04 on 1.0.2h | 1 | no — in `1.0.2 to <1.0.2zg` |
| CVE-2026-45445 D04 on 3.0.19 / 3.0.13 (finding PURL) | 4 | no — finding package in `3.0.0 to <3.0.21` |

**7 of 40** pre-guard decisions would have terminated at a version gate before any symbol rule fired.

Over the 61 S3+ rows: those 7 are a subset of the 35 S5b. The 5 D04 finding-PURL versions are in range (RabbitMQ’s *evidence binary* is a separate defect below, not a finding-version miss). The remaining **21** are `provenance_unverified`: 15× CVE-2022-48174 (busybox) and 6× CVE-2024-2236 (libgcrypt). This finding does not have advisory ranges for those CVEs. Whether a version gate would have terminated them is **UNRESOLVED**. Settling it: look up each CVE’s affected range and compare to the PURL versions already in `decisions.jsonl`; do not re-run `corpus-redecide.sh`.

## Seven out-of-range corpus clearances

Pre-guard D02 = the 35 current `reason_code=symbol_not_observable` rows (22× CVE-2026-14456, 9× CVE-2026-42767, 4× CVE-2026-45445). FINDING-002 treated all 35 as unsound. Seven of the 22 CVE-2026-14456 rows are on 3.0.x, which the advisory excludes:

| Artifact | n | Observed version | CVE applies? |
|----------|--:|------------------|--------------|
| oci-nginx-1.25 | 2 | 3.0.11 | no |
| oci-node-20 | 2 | 3.0.19 | no |
| oci-redis-7 | 1 | 3.0.20 | no |
| subst-golang-bookworm | 2 | 3.0.20 | no |

Those **7** `NOT_AFFECTED` verdicts were correct by accident. The other **28** (9× CVE-2026-42767, 4× CVE-2026-45445, 15× CVE-2026-14456 on 3.5.6/3.5.7) remain FINDING-002 unsound: the CVE applies, and D02 was unfalsifiable absence of an internal symbol.

Corrected unsound corpus clearances: **28 of 35**.

## Four accidentally-correct KT-2 labels

`corpus/groundtruth/real-100.yaml` records 20 pipeline `NOT_AFFECTED` rows, all labelled `UNDER_INVESTIGATION` as FINDING-002 false clearances. Four of those 20 are the out-of-range CVE-2026-14456 cases:

| id | Artifact | Observed OpenSSL | Current human_label | Corrected |
|----|----------|------------------|---------------------|-----------|
| real-008 | oci-redis-7 | 3.0.20 | UNDER_INVESTIGATION | NOT_AFFECTED (CVE does not apply) |
| real-031 | oci-node-20 | 3.0.19 | UNDER_INVESTIGATION | NOT_AFFECTED (CVE does not apply) |
| real-035 | oci-nginx-1.25 | 3.0.11 | UNDER_INVESTIGATION | NOT_AFFECTED (CVE does not apply) |
| real-086 | subst-golang-bookworm | 3.0.20 | UNDER_INVESTIGATION | NOT_AFFECTED (CVE does not apply) |

The other 16 remain false clearances. KT-2 still fails: the bar was one. The paper must say four hand labels were wrong.

Corrected false-clearance count: **16 of 20**. `real-100.yaml` is not amended in this finding.

The human notes on those four rows (and on every other CVE-2026-14456 label) argue DTLS symbol presence on oci-redis-7’s `libssl.so.3`. They never state an affected-version check.

## subst-golang: PURL 3.0.15, `.so` and dpkg 3.0.20

`corpus/results/subst-golang-bookworm/decisions.jsonl` binds OpenSSL findings to `pkg:deb/debian/libssl3@3.0.15-1~deb12u1` and `pkg:deb/debian/openssl@3.0.15-1~deb12u1`.

On the same artifact:

- `strings -a .lading/profile-rootfs/subst-golang-bookworm/usr/lib/x86_64-linux-gnu/libcrypto.so.3` → `OpenSSL 3.0.20 7 Apr 2026`
- `.lading/profile-rootfs/subst-golang-bookworm/var/lib/dpkg/status.d/libssl3` → `Version: 3.0.20-1~deb12u2`

The scanner asserted a version the package metadata and the shipped `.so` both contradict. FINDING-002’s implication that “Grype package presence was correct in every testable case” (line 89) is true of *name* and false of *version* on this row. This is Result 1 — identity failure upstream of evidence — sitting inside the soundness corpus unnoticed. Bucket classification for CVE-2026-14456 does not flip (3.0.15 and 3.0.20 are both out of range); the identity error is independent of that.

## RabbitMQ: D04 evidence from a second OpenSSL at `/opt/openssl` 3.1.8

Post-guard `AFFECTED` (D04) on oci-rabbitmq-3 is CVE-2026-45445 against ubuntu `libssl3t64@3.0.13-0ubuntu3.6` (`decisions.jsonl` lines 84–85). Distro libcrypto strings as **3.0.13**, which **is** in range for that CVE.

The evidence bundle does not show `aes_ocb_cipher` on the distro `.so`. `corpus/results/oci-rabbitmq-3/evidence-bundle/statements/cve-2026-45445/observations.json` lines 2–30 list `symbols_present` only on:

- `.lading/profile-rootfs/oci-rabbitmq-3/opt/openssl/lib/libcrypto.so`
- `.lading/profile-rootfs/oci-rabbitmq-3/opt/openssl/lib/libcrypto.so.3`

Those files string as **OpenSSL 3.1.8 11 Feb 2025**. 3.1 is not in CVE-2026-45445’s ranges (3.0.0 to <3.0.21, plus 3.4/3.5/3.6/4.0).

D04 fires when `anyDefinitivePresent()` sees the symbol in **any** inventoried binary (`evaluate.go` above). The engine does not bind a finding PURL to a library home. Same defect class as FINDING-002’s wrong-library check (CVE-2026-14456 measured on `libcrypto.so.3`) and the Debian-multiarch path glob that produced false D01 candidates. This instance belongs on FINDING-002’s implication list; it is recorded here so that amendment has a citation.

**Consequence.** The `AFFECTED` verdict is correct by coincidence: 3.0.13 is in range. Nothing in the evidence bundle demonstrates `aes_ocb_cipher` on the binary the finding refers to. It is an **unsupported verdict that happens to be right** — the same epistemic shape as the seven accidental `NOT_AFFECTED` rows.

## PAPER.md misattributes the five AFFECTED rows

PAPER.md lines 200–202 assert that the five post-guard AFFECTED rows use `GENERAL_NAME_cmp` / CVE-2023-0286. They do not. One is CVE-2023-0286 on Netgear OpenSSL **1.0.2h**. Four are CVE-2026-45445 on oci-node-20 **3.0.19** and oci-rabbitmq-3 **3.0.13**. Two CVEs, two version families.

Bidirectional unsoundness — “zero correct decisions of any kind” — is not this finding.

## DTLS wording, not a wrong symbol

`port_default_packet_handler` is the QUIC function the advisory’s fix commits touch. GitHub patches for `08e7756` (3.5), `4084152` (3.6), and `f2f1465` (4.0) all hunk `ssl/quic/quic_port.c` at `static void port_default_packet_handler(...)`. OpenSSL 3.5.7 `ssl/quic/quic_port.c` defines it at line 1482. Manifest notes (`openssl.yaml` lines 65–73) already say QUIC.

FINDING-002 used DTLS `.text` / export / strings counts on a **3.0.20** `libssl.so.3` as proof that this QUIC-internal function’s code is present. On 3.0.20 there is no QUIC server. The symbol choice was right; the wording and the 3.0.20 stand-in measurement were wrong.

Locations that describe CVE-2026-14456 as DTLS (not edited by this finding):

| Location | Form |
|----------|------|
| FINDING-002.md:40, 42–44, 47 | “DTLS/QUIC”; `grep -ic dtls` → 691; 13 exported DTLS symbols; 43 DTLS strings; retained first check as “0 DTLS references” |
| PAPER.md:194, 197 | Table cell “691 `dtls` refs; 13 exported DTLS syms; 43 DTLS strings”; “DTLS lives in `libssl.so.3`” |
| RESULTS.md:120–138 and 161–179 | Every CVE-2026-14456 real-\* write-up copies the FINDING-002 DTLS sentence |
| corpus/groundtruth/real-100.yaml | 13 `human_notes` blocks (real-008, 010, 011, 021, 024, 031, 035, 043, 063, 068, 074, 086, 088) |
| corpus/results/cp11-metrics.json | Same sentence in `kt2.false_clearances` and `disagreements` |

Not present: `launch/` (including hn-draft and workshop-draft), `UPSTREAM-DRAFTS.md`.

## What this does not change

- KT-2 still **FAIL**. 16 false `not_affected` in the labelled sample; the pre-registered bar was one.
- FINDING-002’s mechanism is intact for the 28 corpus rows and 16 labels where the CVE applies.
- The five AFFECTED rows are not a version-range wipeout. Two of five (RabbitMQ) are unsupported D04 that happen to be version-right.
- The FINDING-002 guard closed observability. It did not close version, library home, or extra-copy binding.

## Implication

- A clearance on an internal symbol is unsound **when the CVE applies**. When it does not, the same D02 is accidental-correct, and counting it as a FINDING-002 failure overstates the symbol result.
- `affected_versions` in the manifest is documentation the engine does not execute. Exact-string lists cannot compensate for a missing gate. Stated in the paper’s unit: the gate would have caught **7 of 40** pre-guard decisions.
- Scanner version in the PURL is not the version on disk. subst-golang is the measured case.
- Layout priors (wrong `.so`, wrong path glob, extra copy under `/opt/openssl`) are one defect class. RabbitMQ D04 is the fourth instance: an unsupported `AFFECTED` that happens to be right.
- Amend labels, FINDING-002 counts, RESULTS, and PAPER **against this finding**, not before it. If the labels move first, the record shows a corpus that always had seven versions and a sample that was always 16/20, and the discovery disappears.
