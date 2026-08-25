# CP-V2: CVE Version Applicability Recheck

**Date:** 2026-08-25  
**Mode:** READ-ONLY. No published datasets, metrics, decisions, labels, or findings were modified.  
**Scope:** Establish version facts for the four OpenSSL CVEs. Change no data.

**Session hygiene:** `git status --porcelain` was empty before this write. This recheck creates only `audit/CP-V2-RECHECK.md`. `corpus/` and `manifest/` were not edited.

**Ground truth (session, 2026-08-25, against nvd.nist.gov and openssl-library.org/news/vulnerabilities):**

| CVE | Advisory affected ranges | 3.0.20 |
|-----|--------------------------|--------|
| CVE-2026-42767 | 3.0.0 to &lt;3.0.21, 3.4.0 to &lt;3.4.6, 3.5.0 to &lt;3.5.7, 3.6.0 to &lt;3.6.3, 4.0.0 | **in** range |
| CVE-2026-45445 | 3.0.0 to &lt;3.0.21, plus 3.4 / 3.5 / 3.6 / 4.0 | **in** range |
| CVE-2026-14456 | 4.0.0 to &lt;4.0.2, 3.6.0 to &lt;3.6.4, 3.5.0 to &lt;3.5.8. No 3.0.x range. Present since 3.5 (QUIC server). **Not DTLS.** | **not** in range |
| CVE-2023-0286 | 1.0.2 to &lt;1.0.2zg, 1.1.1 to &lt;1.1.1t, 3.0.0 to &lt;3.0.8 | **not** in range |

Advisory text for CVE-2026-14456 was re-fetched this session from `https://openssl-library.org/news/secadv/20260813.txt`: “OpenSSL 4.0, 3.6 and 3.5 are vulnerable to this issue. OpenSSL 3.4, 3.0, 1.1.1 and 1.0.2 are not affected.” Fix commits named there: `f2f1465` (4.0), `4084152` (3.6), `08e7756` (3.5).

**Pre-guard D02 identification.** Current `corpus/results/*/decisions.jsonl` has **zero** `NOT_AFFECTED` rows (post-FINDING-002 guard). The 35 pre-guard D02 clearances are the 35 current `reason_code=symbol_not_observable` rows (22× CVE-2026-14456, 9× CVE-2026-42767, 4× CVE-2026-45445), matching FINDING-002.md lines 55–59 and RESULTS.md line 111. This recheck treats those 35 S5b rows as the pre-guard D02 set. Decisions.jsonl was not modified.

---

## B1. Manifest version assertions

**Status: DISCREPANCY**

SPEC-MANIFEST.md line 75: `affected_versions` is “**Exact** version strings only — **no ranges in v1**.” Line 114: “List **exact** affected version strings (no ranges).” Quoted below is what is actually written in `manifest/components/native/openssl.yaml`.

### CVE-2023-0286 (`openssl.yaml` lines 28–36)

```
affected_versions:
  - "3.0.0"
  - "3.0.1"
  - "3.0.2"
  - "3.0.3"
  - "3.0.4"
  - "3.0.5"
  - "3.0.6"
  - "3.0.7"
```

Every listed string is inside advisory `3.0.0 to <3.0.8`. The entry does **not** assert a version the advisory lists as unaffected. It **omits** the 1.0.2 and 1.1.1 lineages (which **are** affected). Notes at lines 48–51 say “exact 3.0.x strings known affected before the fix” — that incompleteness is written down, not a false-positive version.

### CVE-2026-14456 (`openssl.yaml` lines 55–60)

```
affected_versions:
  - "3.5.0"
  - "3.5.6"
  - "3.5.7"
  - "3.6.0"
  - "4.0.0"
```

Every listed string is inside the advisory ranges. **3.0.20 is not listed.** The entry does not assert any 3.0.x string. Incomplete (missing 3.5.1–3.5.5, 3.6.1–3.6.3, 4.0.1) because the spec forbids ranges.

### CVE-2026-45445 (`openssl.yaml` lines 77–84)

```
affected_versions:
  - "3.0.0"
  - "3.0.11"
  - "3.0.15"
  - "3.0.19"
  - "3.0.20"
  - "3.5.6"
  - "3.5.7"
```

All 3.0.x strings are inside `3.0.0 to <3.0.21`. `3.0.20` **is** listed and **is** affected. `3.5.6` / `3.5.7` sit in the 3.5 family the session ground truth names as affected (upper bound for 3.5 on this CVE was given only as “plus 3.4/3.5/3.6/4.0”, not a cutoff). No listed string is a 3.0.x the advisory excludes.

### CVE-2026-42767 (`openssl.yaml` lines 101–108)

```
affected_versions:
  - "3.0.0"
  - "3.0.11"
  - "3.0.15"
  - "3.0.19"
  - "3.0.20"
  - "3.5.6"
  - "3.5.7"
```

3.0.x strings are inside `3.0.0 to <3.0.21`. **`"3.5.7"` is not.** Advisory range for 3.5 is `3.5.0 to <3.5.7`, so 3.5.7 is **outside**. This is the one list that asserts a version the advisory does not list as affected. No corpus decision on this CVE used 3.5.7 (see B2/B3); the stale string did not move a count.

### Corrected value

Manifest 3.0.x lists are exact-string **subsets** of the 3.0 advisory ranges, except CVE-2026-42767’s `"3.5.7"`. The pipeline’s version error is not “the manifest claimed 3.0.20 is affected by CVE-2026-14456 / CVE-2023-0286” — those entries do not list 3.0.20. The engine never consulted the lists (B6).

---

## B2. Which corpus artifacts run which OpenSSL version

**Status: CONFIRMED**

OpenSSL is **not** 3.0.20 across the board. Primary observation: `strings -a` of the profile-rootfs `libcrypto` shared object, first line matching `^OpenSSL [0-9]+\.[0-9]+\.[0-9]+`. Package metadata (`dpkg` / `apk`) used as corroboration. Finding PURLs from `decisions.jsonl` are **not** treated as ground truth (see subst-golang-bookworm).

Command (abridged; full set run 2026-08-25):

```text
strings -a .lading/profile-rootfs/<id>/.../libcrypto.so.3 | rg -m1 '^OpenSSL [0-9]'
```

| Artifact | SO string (libcrypto) | Package metadata | Finding PURL (decisions.jsonl) | Match? |
|----------|----------------------|------------------|--------------------------------|--------|
| fw-netgear-r7000-firmware-1.0.12.216 | `OpenSSL 1.0.2h  3 May 2016` (`lib/libcrypto.so.1.0.0`) | no dpkg; grype `pkg:generic/openssl@1.0.2h` | `@1.0.2h` | yes |
| oci-nginx-1.25 | `OpenSSL 3.0.11 19 Sep 2023` | dpkg `libssl3`/`openssl` `3.0.11-1~deb12u2` | `@3.0.11-1~deb12u2` | yes |
| oci-node-20 | `OpenSSL 3.0.19 27 Jan 2026` (distro libcrypto **and** `/usr/local/bin/node`) | dpkg `libssl3`/`openssl` `3.0.19-1~deb12u2` | `@3.0.19-1~deb12u2` | yes |
| oci-redis-7 | `OpenSSL 3.0.20 7 Apr 2026` | dpkg `libssl3` `3.0.20-1~deb12u2` | `@3.0.20-1~deb12u2` | yes |
| oci-rabbitmq-3 | distro: `OpenSSL 3.0.13 30 Jan 2024`; **also** `/opt/openssl`: `OpenSSL 3.1.8 11 Feb 2025` | dpkg `libssl3t64`/`openssl` `3.0.13-0ubuntu3.6` | `@3.0.13-0ubuntu3.6` | distro yes; second copy is 3.1.8 |
| subst-golang-bookworm | `OpenSSL 3.0.20 7 Apr 2026` | distroless `var/lib/dpkg/status.d/libssl3`: `Version: 3.0.20-1~deb12u2` | `@3.0.15-1~deb12u1` | **PURL stale.** SO + dpkg = **3.0.20** |
| oci-httpd-2.4 | `OpenSSL 3.5.6 7 Apr 2026` | dpkg `libssl3t64`/`openssl` `3.5.6-1~deb13u2` | `@3.5.6-1~deb13u2` | yes |
| oci-memcached-1.6 | `OpenSSL 3.5.6 7 Apr 2026` | dpkg `libssl3t64` `3.5.6-1~deb13u2` | `@3.5.6-1~deb13u2` | yes |
| oci-postgres-16 | `OpenSSL 3.5.6 7 Apr 2026` | dpkg `3.5.6-1~deb13u2` | `@3.5.6-1~deb13u2` | yes |
| oci-python-3.12 | `OpenSSL 3.5.6 7 Apr 2026` | dpkg `3.5.6-1~deb13u2` | `@3.5.6-1~deb13u2` | yes |
| oci-ruby-3.3 | `OpenSSL 3.5.6 7 Apr 2026` | dpkg `3.5.6-1~deb13u2` | `@3.5.6-1~deb13u2` | yes |
| subst-httpd-alpine | `OpenSSL 3.5.7 9 Jun 2026` | apk `libssl3`/`libcrypto3` `3.5.7-r0` | `@3.5.7-r0` | yes |
| subst-memcached-alpine | `OpenSSL 3.5.7 9 Jun 2026` | apk `3.5.7-r0` | `@3.5.7-r0` | yes |
| subst-mosquitto | `OpenSSL 3.5.7 9 Jun 2026` | apk `3.5.7-r0` | `@3.5.7-r0` | yes |

**subst-golang-bookworm:** observed version used below is **3.0.20** (SO + `status.d/libssl3`). Grype PURL `3.0.15-1~deb12u1` is a scanner/package-string mismatch. Both 3.0.15 and 3.0.20 classify the same way against all four advisory ranges, so B3/B4 buckets do not flip on this conflict.

### Decision rows: artifact × CVE × observed version × in advisory range

“Decision” = pre-guard D02 (now S5b) or post-guard D04. Duplicate package PURLs on the same artifact (e.g. `libssl3` and `openssl`) share one SO version; `n` is the number of `decisions.jsonl` rows.

| Artifact | CVE | n | Observed OpenSSL | In advisory range |
|----------|-----|--:|------------------|-------------------|
| oci-httpd-2.4 | CVE-2026-14456 | 2 | 3.5.6 | **yes** (3.5.0 to &lt;3.5.8) |
| oci-memcached-1.6 | CVE-2026-14456 | 1 | 3.5.6 | **yes** |
| oci-nginx-1.25 | CVE-2026-14456 | 2 | 3.0.11 | **no** |
| oci-nginx-1.25 | CVE-2026-42767 | 2 | 3.0.11 | **yes** (3.0.0 to &lt;3.0.21) |
| oci-nginx-1.25 | CVE-2026-45445 | 2 | 3.0.11 | **yes** |
| oci-node-20 | CVE-2026-14456 | 2 | 3.0.19 | **no** |
| oci-node-20 | CVE-2026-42767 | 2 | 3.0.19 | **yes** |
| oci-node-20 | CVE-2026-45445 | 2 (D04) | 3.0.19 | **yes** |
| oci-postgres-16 | CVE-2026-14456 | 2 | 3.5.6 | **yes** |
| oci-python-3.12 | CVE-2026-14456 | 2 | 3.5.6 | **yes** |
| oci-rabbitmq-3 | CVE-2026-42767 | 2 | distro 3.0.13 | **yes** |
| oci-rabbitmq-3 | CVE-2026-45445 | 2 (D04) | finding PURL / distro **3.0.13**; symbol observed on `/opt/openssl` **3.1.8** | distro **yes**; opt copy **no** (3.1 not in 3.0.0–&lt;3.0.21 or 3.4/3.5/3.6/4.0) |
| oci-redis-7 | CVE-2026-14456 | 1 | 3.0.20 | **no** |
| oci-redis-7 | CVE-2026-42767 | 1 | 3.0.20 | **yes** |
| oci-ruby-3.3 | CVE-2026-14456 | 2 | 3.5.6 | **yes** |
| subst-golang-bookworm | CVE-2026-14456 | 2 | 3.0.20 | **no** |
| subst-golang-bookworm | CVE-2026-42767 | 2 | 3.0.20 | **yes** |
| subst-golang-bookworm | CVE-2026-45445 | 2 | 3.0.20 | **yes** |
| subst-httpd-alpine | CVE-2026-14456 | 2 | 3.5.7 | **yes** |
| subst-memcached-alpine | CVE-2026-14456 | 2 | 3.5.7 | **yes** |
| subst-mosquitto | CVE-2026-14456 | 2 | 3.5.7 | **yes** |
| fw-netgear-r7000-firmware-1.0.12.216 | CVE-2023-0286 | 1 (D04) | 1.0.2h | **yes** (1.0.2 to &lt;1.0.2zg) |

S5b row total 22+9+4 = **35**. D04 row total **5**. Mapping-probable-only rows (Rocky, UBI, `libssl-dev`, `openssl-provider-legacy`) are refusals, not decisions; omitted.

---

## B3. Reclassify the 35 corpus clearances

**Status: DISCREPANCY**

FINDING-002.md lines 51–59: “All **35** corpus `NOT_AFFECTED` clearances were D02 on these three CVEs. All are therefore unsound.” That claim does not survive version applicability.

Buckets:

- **(a)** CVE applies to the observed version, and the named symbol is internal / unobservable → FINDING-002 unsoundness holds.
- **(b)** CVE does not apply to the observed version → clearance was correct by accident; the pipeline never computed version.
- **(c)** undetermined.

| CVE | (a) | (b) | (c) | Total |
|-----|----:|----:|----:|------:|
| CVE-2026-14456 | 15 | 7 | 0 | 22 |
| CVE-2026-42767 | 9 | 0 | 0 | 9 |
| CVE-2026-45445 | 4 | 0 | 0 | 4 |
| **Total** | **28** | **7** | **0** | **35** |

**(a) CVE-2026-14456 on 3.5.x (15 rows):** oci-httpd-2.4 ×2, oci-memcached-1.6 ×1, oci-postgres-16 ×2, oci-python-3.12 ×2, oci-ruby-3.3 ×2, subst-httpd-alpine ×2, subst-memcached-alpine ×2, subst-mosquitto ×2. Version 3.5.6 or 3.5.7 is inside `3.5.0 to <3.5.8`. Symbol `port_default_packet_handler` is file-static (manifest notes lines 72–73; B8). D02 on `.dynsym` absence remains unfalsifiable. FINDING-002 unsoundness **holds** for these 15. (The DTLS *evidence* FINDING-002 used to prove “code present” is still the wrong subsystem — B7/B8 — but the CVE *does* apply.)

**(b) CVE-2026-14456 on 3.0.x (7 rows):** oci-nginx-1.25 ×2 (3.0.11), oci-node-20 ×2 (3.0.19), oci-redis-7 ×1 (3.0.20), subst-golang-bookworm ×2 (3.0.20). No 3.0.x range exists. `NOT_AFFECTED` was the right verdict for a reason the engine never computed.

**(a) CVE-2026-42767 (9 rows):** oci-nginx-1.25 ×2 (3.0.11), oci-node-20 ×2 (3.0.19), oci-rabbitmq-3 ×2 (3.0.13), oci-redis-7 ×1 (3.0.20), subst-golang-bookworm ×2 (3.0.20). All inside `3.0.0 to <3.0.21`. `OSSL_CRMF_ENCRYPTEDVALUE_decrypt` is internal. FINDING-002 holds.

**(a) CVE-2026-45445 (4 rows):** oci-nginx-1.25 ×2 (3.0.11), subst-golang-bookworm ×2 (3.0.20). Inside `3.0.0 to <3.0.21`. `aes_ocb_cipher` is provider-internal. FINDING-002 holds.

### Corrected value

Unsound corpus clearances = **28**, not 35. Accidental-correct clearances = **7**, all CVE-2026-14456 on 3.0.x. `decisions.jsonl` not modified.

---

## B4. Reclassify the 20 KT-2 hand labels

**Status: DISCREPANCY**

Source: `corpus/groundtruth/real-100.yaml` — 20 rows with `pipeline_verdict: NOT_AFFECTED` and `human_label: UNDER_INVESTIGATION` (file header lines 4–6: “20/20 pipeline NOT_AFFECTED rows are FINDING-002 false clearances”). **File not edited.** Observed version = B2 SO string (subst-golang-bookworm: 3.0.20, not the PURL’s 3.0.15).

| id | CVE | Artifact | Observed OpenSSL | Bucket |
|----|-----|----------|------------------|--------|
| real-002 | CVE-2026-42767 | oci-redis-7 | 3.0.20 | **(a)** |
| real-008 | CVE-2026-14456 | oci-redis-7 | 3.0.20 | **(b)** |
| real-010 | CVE-2026-14456 | oci-python-3.12 | 3.5.6 | **(a)** |
| real-011 | CVE-2026-14456 | subst-mosquitto | 3.5.7 | **(a)** |
| real-013 | CVE-2026-45445 | subst-golang-bookworm | 3.0.20 | **(a)** |
| real-015 | CVE-2026-42767 | oci-node-20 | 3.0.19 | **(a)** |
| real-016 | CVE-2026-42767 | oci-nginx-1.25 | 3.0.11 | **(a)** |
| real-021 | CVE-2026-14456 | subst-httpd-alpine | 3.5.7 | **(a)** |
| real-022 | CVE-2026-42767 | oci-rabbitmq-3 | 3.0.13 (distro) | **(a)** |
| real-024 | CVE-2026-14456 | subst-httpd-alpine | 3.5.7 | **(a)** |
| real-031 | CVE-2026-14456 | oci-node-20 | 3.0.19 | **(b)** |
| real-035 | CVE-2026-14456 | oci-nginx-1.25 | 3.0.11 | **(b)** |
| real-043 | CVE-2026-14456 | oci-postgres-16 | 3.5.6 | **(a)** |
| real-055 | CVE-2026-42767 | subst-golang-bookworm | 3.0.20 | **(a)** |
| real-063 | CVE-2026-14456 | oci-python-3.12 | 3.5.6 | **(a)** |
| real-065 | CVE-2026-42767 | oci-nginx-1.25 | 3.0.11 | **(a)** |
| real-068 | CVE-2026-14456 | oci-postgres-16 | 3.5.6 | **(a)** |
| real-074 | CVE-2026-14456 | oci-ruby-3.3 | 3.5.6 | **(a)** |
| real-086 | CVE-2026-14456 | subst-golang-bookworm | 3.0.20 | **(b)** |
| real-088 | CVE-2026-14456 | oci-memcached-1.6 | 3.5.6 | **(a)** |

| CVE | (a) | (b) | (c) |
|-----|----:|----:|----:|
| CVE-2026-14456 | 9 | 4 | 0 |
| CVE-2026-42767 | 6 | 0 | 0 |
| CVE-2026-45445 | 1 | 0 | 0 |
| **Total** | **16** | **4** | **0** |

### Corrected false-clearance count

**16**, not 20. The four bucket-(b) rows are not false `NOT_AFFECTED`: the CVE does not apply to the observed version.

### Proposed amendment (report only — `real-100.yaml` not edited)

| id | Current human_label | Proposed human_label | Proposed human_notes (summary) |
|----|---------------------|----------------------|--------------------------------|
| real-008 | UNDER_INVESTIGATION | **NOT_AFFECTED** | CVE-2026-14456 has no 3.0.x range; oci-redis-7 is OpenSSL 3.0.20. Pipeline NA was correct by accident. |
| real-031 | UNDER_INVESTIGATION | **NOT_AFFECTED** | Same CVE; oci-node-20 is 3.0.19. |
| real-035 | UNDER_INVESTIGATION | **NOT_AFFECTED** | Same CVE; oci-nginx-1.25 is 3.0.11. |
| real-086 | UNDER_INVESTIGATION | **NOT_AFFECTED** | Same CVE; subst-golang-bookworm libcrypto is 3.0.20 (dpkg `3.0.20-1~deb12u2`; PURL 3.0.15 is stale). |
| real-002, 010, 011, 013, 015, 016, 021, 022, 024, 043, 055, 063, 065, 068, 074, 088 | UNDER_INVESTIGATION | UNDER_INVESTIGATION | Unchanged: version is in range; D02 on an unobservable internal symbol remains unsound. Drop DTLS wording from 14456 notes (B7). |

Header claim “20/20 pipeline NOT_AFFECTED rows are FINDING-002 false clearances” would become **16/20**. RESULTS.md / PAPER.md / cp11-metrics.json `false_not_affected: 20` are the same figure, left untouched this session.

---

## B5. The five AFFECTED rows

**Status: DISCREPANCY**

PAPER.md lines 200–202:

> `GENERAL_NAME_cmp` is exported from `libcrypto.so.3` (`T GENERAL_NAME_cmp@@OPENSSL_3.0.0`) — CVE-2023-0286 only; the five post-guard **AFFECTED** rows use this path (D04).

That sentence is false. All five post-guard `AFFECTED` rows in `decisions.jsonl`:

| # | Artifact | File:line | CVE | Finding PURL version | SO observed | Symbol that fired D04 | Finding version in range? |
|---|----------|-----------|-----|----------------------|-------------|----------------------|---------------------------|
| 1 | fw-netgear-r7000-firmware-1.0.12.216 | decisions.jsonl:6 | **CVE-2023-0286** | `openssl@1.0.2h` | 1.0.2h (`libcrypto.so.1.0.0`) | `GENERAL_NAME_cmp` in `.dynsym` (observations.json lines 2–30) | **yes** (1.0.2 to &lt;1.0.2zg) |
| 2 | oci-node-20 | :207 | **CVE-2026-45445** | libssl3 `@3.0.19-…` | distro 3.0.19 | `aes_ocb_cipher` in **symtab of `/usr/local/bin/node`** (observations.json lines 2–16), which strings as the same 3.0.19 | **yes** (3.0.0 to &lt;3.0.21) |
| 3 | oci-node-20 | :208 | **CVE-2026-45445** | openssl `@3.0.19-…` | same | same bundle | **yes** |
| 4 | oci-rabbitmq-3 | :84 | **CVE-2026-45445** | libssl3t64 `@3.0.13-…` | distro 3.0.13; **opt 3.1.8** | `aes_ocb_cipher` in **symtab of `/opt/openssl/lib/libcrypto.so{,.3}`** (observations.json lines 2–30), which strings as **3.1.8** | finding package **yes**; evidence binary **no** |
| 5 | oci-rabbitmq-3 | :85 | **CVE-2026-45445** | openssl `@3.0.13-…` | same | same bundle | same |

**They do not all rest on GENERAL_NAME_cmp / CVE-2023-0286.** One does. Four rest on `aes_ocb_cipher` / CVE-2026-45445.

**Are they false AFFECTED on version grounds?**

- **Netgear CVE-2023-0286 / 1.0.2h:** version **is** in range. D04 is not a version-false AFFECTED. (Manifest lists only 3.0.0–3.0.7, not 1.0.2h; D04 still fired because there is no version gate — B6.)
- **oci-node-20 CVE-2026-45445 / 3.0.19:** version **is** in range. Evidence came from Node’s bundled copy, which is the same 3.0.19 as distro libssl3. Not version-false.
- **oci-rabbitmq-3 CVE-2026-45445 / finding 3.0.13:** the **package named in the finding** is in range. The **binary that supplied the symbol** is `/opt/openssl` 3.1.8, which is **not** in the advisory ranges given this session. That is a wrong-binary / extra-copy defect, not “3.0.20 is outside CVE-2023-0286.” Claiming AFFECTED on ubuntu `libssl3t64` 3.0.13 is directionally consistent with the advisory for that package; the evidence bundle does not show `aes_ocb_cipher` on the distro `.so`.

**Plain statement:** the five AFFECTED rows are **not** false AFFECTED because “CVE-2023-0286 ends before 3.0.8 and the corpus is 3.0.20.” Four of five are a different CVE whose 3.0 range includes 3.0.13 and 3.0.19. The one CVE-2023-0286 row is 1.0.2h, which **is** in range. The strongest claim — post-guard pipeline emits zero correct decisions of any kind — is **not supported** by version applicability on these five rows.

A separate soundness issue (not FINDING-002, not the version-range miss): D04 `anyDefinitivePresent()` (`evaluate.go` lines 27–30) fires if the vulnerable symbol appears in **any** inventoried binary on the rootfs, including a second OpenSSL copy (`/opt/openssl`, `/usr/local/bin/node`). That is not a version gate and was not closed by the FINDING-002 observability guard.

---

## B6. Does the engine check version applicability at all

**Status: CONFIRMED**

**No such gate exists.** `internal/decide` never compares a finding’s component version to `entry.AffectedVersions` before a symbol rule fires.

`Evaluate` (`internal/decide/evaluate.go` lines 20–43) in order: `checkD03` → `anyDefinitivePresent()` (D04) → `allDefinitiveSymbolsDynsymExportVerified()` (S5b vs D02) → D01. None of those functions read `AffectedVersions`.

`buildContext` (`internal/decide/context.go` lines 76–81) loads `ctx.entry` only to take `definitiveSymbols`. `evalContext` (lines 13–28) has no version field. Grep of `internal/decide` for `AffectedVersions` hits **only** test fixtures (`fixture_test.go` copies the YAML field into a test manifest; `identity_test.go` populates it). Production decide code does not reference the field.

Version strings that *do* appear in decide are identity-mapping (`identity.go` lines 43–50, `ReasonVersionUnderivable`) and PURL match quality (`NameVersionOnly`). Those are not advisory-range checks.

The FINDING-002 guard (`evaluate.go` lines 33–38, `symbol_not_observable`) is observability-only. It does not touch version applicability.

### Corrected value

One sentence: the engine has no affected-version gate; `affected_versions` is loaded as manifest data and unused by `Evaluate`.

---

## B7. Where else the DTLS error propagated

**Status: CONFIRMED**

CVE-2026-14456 is a QUIC incoming-channel DoS, not DTLS. `grep` of published documents for `DTLS` and `CVE-2026-14456` (this session). Nothing in this list was edited.

### Describes CVE-2026-14456 as DTLS (the error)

| Location | What it says |
|----------|----------------|
| FINDING-002.md:40 | “Library: `libssl.so.3` (DTLS/QUIC live here…)” under the CVE-2026-14456 heading |
| FINDING-002.md:42–44 | `objdump … grep -ic dtls` → **691**; `nm -D … grep -ci dtls` → **13** exported DTLS symbols; `strings … grep -ci dtls` → **43** — offered as proof the vulnerable handler’s code is present |
| FINDING-002.md:47 | Retains the first `libcrypto` check as “0 DTLS references”; still frames the CVE as a DTLS-library measurement |
| PAPER.md:194 | Table cell for CVE-2026-14456: “**691** `dtls` refs; **13** exported DTLS syms; **43** DTLS strings” |
| PAPER.md:197 | “DTLS lives in `libssl.so.3`” as the correction of the wrong-library check |
| RESULTS.md:120–138 and 161–179 | Every CVE-2026-14456 real-\* write-up copies the FINDING-002 DTLS sentence (**26** `port_default_packet_handler` hits, **78** `DTLS` hits in the file) |
| corpus/groundtruth/real-100.yaml | **13** human_notes blocks (lines 131–132, 160–161, 175–176, 316–317, 359–360, 459–460, 516–517, 629–630, 910–911, 982–983, 1067–1068, 1236–1237, 1265–1266) — the same DTLS sentence. **39** `DTLS` occurrences |
| corpus/results/cp11-metrics.json | Same sentence in `kt2.false_clearances[].human_notes` / `.finding` and `disagreements[].human_notes` (**117** `DTLS`, **39** `port_default_packet_handler`) |

### Describes the CVE as `port_default_packet_handler` (symbol name; see B8)

- `manifest/components/native/openssl.yaml` lines 62–66, 72–73 (QUIC, not DTLS — the notes are the correct subsystem).
- FINDING-002.md table line 20 and section heading line 38.
- PAPER.md:194; RESULTS.md real-\* lines above; real-100.yaml / cp11-metrics.json as above.
- Evidence-bundle `manifest-slice.json` / `observations.json` under `corpus/results/*/evidence-bundle/statements/cve-2026-14456/` (copies of the manifest symbol).
- testdata (not a published result): `testdata/decide/d02-internal/case.yaml` line 24; `testdata/evidence-pack/scan/evidence-bundle/statements/cve-2026-14456/`. That fixture also lists `affected_versions: [3.0.20]` for this CVE (lines 21–22) — 3.0.20 is **not** affected.

### Not present

- `launch/` (including `launch/hn-draft.md`, `launch/paper/workshop-draft.md`, `launch/issues/`): **0** hits for `DTLS`, `port_default_packet_handler`, or `CVE-2026-14456`.
- `UPSTREAM-DRAFTS.md`: **0**.

The DTLS error is in FINDING-002 and everything that copied its human_notes. The manifest notes already say QUIC.

---

## B8. Symbol provenance for CVE-2026-14456

**Status: DISCREPANCY** (against the hypothesis that the symbol was taken from the wrong subsystem)

Manifest (`openssl.yaml` lines 62–67) names `port_default_packet_handler` with `upstream_fix_commit` `https://github.com/openssl/openssl/commit/08e7756c3900bcfd77a720e7b74e27d6e4ed01a9` and a comment that the function lives in `ssl/quic/quic_port.c`.

Advisory `https://openssl-library.org/news/secadv/20260813.txt` names three commits: `f2f1465` (4.0), `4084152` (3.6), `08e7756` (3.5). GitHub API this session:

| Commit | `quic_port.c` hunk header in the patch |
|--------|----------------------------------------|
| `08e7756c3900bcfd77a720e7b74e27d6e4ed01a9` | `static void port_default_packet_handler(QUIC_URXE *e, void *arg,` |
| `4084152e040329ca0194c4c1750b9b46d00a5b6b` | same function, later line numbers |
| `f2f1465f2d2e…` | same function, later line numbers |

All three commits are titled “QUIC server: limit number of pending QUIC channels/connections” and touch `ssl/quic/quic_port.c`, `ssl/quic/quic_impl.c`, `include/internal/quic_port.h`. The commit message: “The port default packet handler creates channel for every valid initial packet.”

OpenSSL 3.5.7 source `https://raw.githubusercontent.com/openssl/openssl/openssl-3.5.7/ssl/quic/quic_port.c`: `port_default_packet_handler` at lines 32 (forward decl), 152 (function pointer), 587 (comment), 1482 (definition). File is QUIC port code.

**The symbol is the QUIC handler the advisory’s fix commits touch.** It was not derived from DTLS. The manifest entry is **wrong about version coverage of 3.0.x only in the sense that the engine never used the list** (the list itself has no 3.0.x). It is **not** wrong about the symbol name or the subsystem.

FINDING-002 used DTLS `.text` / `.dynsym` / strings counts on a **3.0.20** `libssl.so.3` as stand-in proof that this QUIC-internal function’s code is present. On 3.0.20 there is no QUIC server (advisory: present since 3.5). That is a wrong-evidence problem, not a wrong-symbol-in-the-manifest problem.

### Corrected value

Manifest symbol `port_default_packet_handler` is the patch-touched QUIC function. DTLS measurements cannot attest it. On 3.0.x the CVE does not apply regardless of symbol observability.

---

## End matter

| Question | Corrected value |
|----------|-----------------|
| Corrected count of false `NOT_AFFECTED` in real-100 | **16** (was published as 20). Four CVE-2026-14456 rows on 3.0.x (real-008, real-031, real-035, real-086) are not false clearances. |
| Corrected count of unsound corpus clearances | **28** of 35 pre-guard D02 rows (was published as all 35). Seven CVE-2026-14456 rows on 3.0.x were NA by accident. |
| Are the five AFFECTED rows sound? | **Not version-false.** One is CVE-2023-0286 on OpenSSL **1.0.2h** (in range). Four are CVE-2026-45445 on **3.0.19** / **3.0.13** (in range for that CVE). PAPER.md’s claim that all five are `GENERAL_NAME_cmp` / CVE-2023-0286 is false. RabbitMQ D04 evidence was taken from a second copy at **3.1.8** (out of range) — a binary-binding defect, not the version-range miss that would zero out every post-guard decision. |
| Did the FINDING-002 guard touch the version defect? | **No.** S5b is observability-only (B6). Version applicability is still uncomputed. |

The abstract’s “20 of 20” and “all 35” are both overstated, but not in the symmetric “zero correct decisions” direction. The overstatement is: some of the D02 NAs were the right verdict for a reason nobody scored (CVE-2026-14456 vs 3.0.x). The five AFFECTED rows remain version-plausible for the CVEs they actually decided. Publishing the stronger bidirectional-unsoundness claim would itself be unsound.
)
