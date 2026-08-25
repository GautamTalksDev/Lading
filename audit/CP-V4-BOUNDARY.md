# CP-V4: Advisory boundary recheck on the remaining 28

**Date of measurement:** 2026-08-25  
**Mode:** READ-ONLY. This file is the only write. No `corpus-scan.sh`, `corpus-redecide.sh`, or `rederive-results.sh`.  
**Prior record:** [FINDING-003.md](../FINDING-003.md) lines 99–112 (7 of 35 out of range on CVE-2026-14456 / 3.0.x; **28** left as unsound). [audit/CP-V2-RECHECK.md](CP-V2-RECHECK.md) B2/B3.  
**Question:** FINDING-003 did not apply the exclusive 3.5 upper bound of CVE-2026-42767 and CVE-2026-45445 (`3.5.0` to `<3.5.7`) to the 3.5.6 / 3.5.7 artifacts. Does any of the remaining 28 also fall out of range? Does any of the five D04 `AFFECTED` rows?

**Advisory ranges (session prompt; same as FINDING-003.md lines 24–29, verified 2026-08-25):**

| CVE | Affected |
|-----|----------|
| CVE-2026-42767 | 3.0.0 to `<3.0.21` \| 3.4.0 to `<3.4.6` \| **3.5.0 to `<3.5.7`** \| 3.6.0 to `<3.6.3` \| 4.0.0 |
| CVE-2026-45445 | same bounds as CVE-2026-42767 |
| CVE-2026-14456 | 4.0.0 to `<4.0.2` \| 3.6.0 to `<3.6.4` \| **3.5.0 to `<3.5.8`**. No 3.0.x. |
| CVE-2023-0286 | 1.0.2 to `<1.0.2zg` \| 1.1.1 to `<1.1.1t` \| 3.0.0 to `<3.0.8` |

Exclusive upper bounds: **3.5.6 is affected** by 42767 and 45445. **3.5.7 is not.** 3.5.7 **is** affected by 14456 (`<3.5.8`).

**Observed-version method (this session):** `strings -a` on the profile-rootfs distro `libcrypto` (not `/opt/openssl`), first line matching `^OpenSSL [0-9]`. Alpine `lib/apk/db/installed` `P:libssl3` / `V:` as corroboration. Finding PURLs are not ground truth (subst-golang still asserts `3.0.15` against SO `3.0.20`; FINDING-003.md lines 131–140). Same Debian-backport limitation as FINDING-003.md lines 37–38: the token is the advisory’s upstream version, not a proof of a distro patch.

---

## D1. The 28 FINDING-003-unsound clearances

**Population.** Post-guard `reason_code=symbol_not_observable` = **35** rows (22× CVE-2026-14456, 9× CVE-2026-42767, 4× CVE-2026-45445). Command this session: walk `corpus/results/*/decisions.jsonl`. FINDING-003.md line 110: the 28 are 9× 42767 + 4× 45445 + 15× 14456 on 3.5.6/3.5.7. The excluded 7 are 14456 on 3.0.x (nginx ×2, node ×2, redis ×1, golang ×2).

**Version strings this session:**

```text
strings -a .lading/profile-rootfs/<id>/.../libcrypto.so.3 | grep -m1 -E '^OpenSSL [0-9]'
```

| Artifact | SO path (this session) | SO string |
|----------|------------------------|-----------|
| oci-httpd-2.4, oci-memcached-1.6, oci-postgres-16, oci-python-3.12, oci-ruby-3.3 | `usr/lib/x86_64-linux-gnu/libcrypto.so.3` | `OpenSSL 3.5.6 7 Apr 2026` |
| subst-httpd-alpine, subst-memcached-alpine, subst-mosquitto | `usr/lib/libcrypto.so.3` | `OpenSSL 3.5.7 9 Jun 2026` |
| oci-nginx-1.25 | same debian multiarch | `OpenSSL 3.0.11 19 Sep 2023` |
| oci-node-20 | same | `OpenSSL 3.0.19 27 Jan 2026` |
| oci-redis-7, subst-golang-bookworm | same | `OpenSSL 3.0.20 7 Apr 2026` |
| oci-rabbitmq-3 distro | same | `OpenSSL 3.0.13 30 Jan 2024` |

Alpine apk corroboration: `lib/apk/db/installed` `P:libssl3` `V:3.5.7-r0` on all three substitute-alpine artifacts (httpd `installed` around the `P:libssl3` record at line 1239; memcached line 684; mosquitto line 1075).

**The 28, grouped. `n` is `decisions.jsonl` S5b rows. In-range uses the observed SO token against the ranges above.**

| Artifact | CVE | n | `decisions.jsonl` lines | Observed | In advisory range? |
|----------|-----|--:|-------------------------|----------|--------------------|
| oci-httpd-2.4 | CVE-2026-14456 | 2 | 24–25 | 3.5.6 | **yes** (`3.5.0` to `<3.5.8`) |
| oci-memcached-1.6 | CVE-2026-14456 | 1 | 8 | 3.5.6 | **yes** |
| oci-postgres-16 | CVE-2026-14456 | 2 | 38–39 | 3.5.6 | **yes** |
| oci-python-3.12 | CVE-2026-14456 | 2 | 8–9 | 3.5.6 | **yes** |
| oci-ruby-3.3 | CVE-2026-14456 | 2 | 6–7 | 3.5.6 | **yes** |
| subst-httpd-alpine | CVE-2026-14456 | 2 | 18–19 | 3.5.7 | **yes** (`3.5.0` to `<3.5.8`; 3.5.7 is not the 14456 fixed release) |
| subst-memcached-alpine | CVE-2026-14456 | 2 | 1–2 | 3.5.7 | **yes** |
| subst-mosquitto | CVE-2026-14456 | 2 | 2–3 | 3.5.7 | **yes** |
| oci-nginx-1.25 | CVE-2026-42767 | 2 | 224–225 | 3.0.11 | **yes** (`3.0.0` to `<3.0.21`) |
| oci-node-20 | CVE-2026-42767 | 2 | 514–515 | 3.0.19 | **yes** |
| oci-rabbitmq-3 | CVE-2026-42767 | 2 | 250–251 | 3.0.13 | **yes** |
| oci-redis-7 | CVE-2026-42767 | 1 | 19 | 3.0.20 | **yes** |
| subst-golang-bookworm | CVE-2026-42767 | 2 | 292–293 | 3.0.20 | **yes** (SO; PURL `@3.0.15` is also in this 3.0 range) |
| oci-nginx-1.25 | CVE-2026-45445 | 2 | 151–152 | 3.0.11 | **yes** |
| subst-golang-bookworm | CVE-2026-45445 | 2 | 150–151 | 3.0.20 | **yes** |

Sum: 15 + 9 + 4 = **28**.

**No 42767 or 45445 S5b row sits on 3.5.6 or 3.5.7.** This session, every OpenSSL S5b on the 3.5.x artifacts is CVE-2026-14456 only:

```text
subst-httpd-alpine     CVE-2026-14456 ×2 (S5b)
subst-memcached-alpine CVE-2026-14456 ×2 (S5b)
subst-mosquitto        CVE-2026-14456 ×2 (S5b)
oci-httpd-2.4          CVE-2026-14456 ×2 S5b (+ mapping_probable_only, not in the 35)
oci-memcached-1.6      CVE-2026-14456 ×1 S5b
oci-postgres-16        CVE-2026-14456 ×2 S5b
oci-python-3.12        CVE-2026-14456 ×2 S5b
oci-ruby-3.3           CVE-2026-14456 ×2 S5b
```

The 3.5.7 exclusive bound for 42767/45445 therefore has **no corpus clearance to move**. The 3.5.7 rows that exist are 14456, still inside `<3.5.8`.

---

## D2. Count that moves; three-way split of 35

**Moves: 0.**

| Bucket | FINDING-003 | After exclusive 3.5 bound |
|--------|------------:|--------------------------:|
| Unsound on FINDING-002 (CVE applies; internal symbol) | 28 | **28** |
| Out of range (accidental NA) | 7 | **7** (still only 14456 on 3.0.x) |
| Undetermined | 0 | **0** |
| Total pre-guard D02 / current S5b | 35 | **35** |

3.5.6 is in range for 42767 and 45445, but those CVEs produced no S5b on the 3.5.6 artifacts, so that fact does not add or subtract a clearance.

---

## D3. The 20 KT-2 labelled rows

Source: `corpus/groundtruth/real-100.yaml`. This session: `yaml.safe_load` → 20 statements with `pipeline_verdict: NOT_AFFECTED`, all `human_label: UNDER_INVESTIGATION`. Overlay `amendment_2026_08_25` (file lines 9–13) already records `corrected_false_not_affected: 16` for the four 14456 / 3.0.x IDs. File not edited this session.

Observed versions = D1 SO table. Overlay IDs (real-008, 031, 035, 086) stay out of range for 14456. The other **16**:

| id | CVE | Artifact | Observed | In range after exclusive 3.5 bound? |
|----|-----|----------|----------|-------------------------------------|
| real-002 | CVE-2026-42767 | oci-redis-7 | 3.0.20 | yes |
| real-010 | CVE-2026-14456 | oci-python-3.12 | 3.5.6 | yes (`<3.5.8`) |
| real-011 | CVE-2026-14456 | subst-mosquitto | 3.5.7 | yes (`<3.5.8`) |
| real-013 | CVE-2026-45445 | subst-golang-bookworm | 3.0.20 | yes |
| real-015 | CVE-2026-42767 | oci-node-20 | 3.0.19 | yes |
| real-016 | CVE-2026-42767 | oci-nginx-1.25 | 3.0.11 | yes |
| real-021 | CVE-2026-14456 | subst-httpd-alpine | 3.5.7 | yes |
| real-022 | CVE-2026-42767 | oci-rabbitmq-3 | 3.0.13 | yes |
| real-024 | CVE-2026-14456 | subst-httpd-alpine | 3.5.7 | yes |
| real-043 | CVE-2026-14456 | oci-postgres-16 | 3.5.6 | yes |
| real-055 | CVE-2026-42767 | subst-golang-bookworm | 3.0.20 | yes |
| real-063 | CVE-2026-14456 | oci-python-3.12 | 3.5.6 | yes |
| real-065 | CVE-2026-42767 | oci-nginx-1.25 | 3.0.11 | yes |
| real-068 | CVE-2026-14456 | oci-postgres-16 | 3.5.6 | yes |
| real-074 | CVE-2026-14456 | oci-ruby-3.3 | 3.5.6 | yes |
| real-088 | CVE-2026-14456 | oci-memcached-1.6 | 3.5.6 | yes |

No remaining false-clearance row is 42767 or 45445 on 3.5.7. The 3.5.7 labels are 14456 (real-011, 021, 024).

**Corrected false-clearance count does not move: still 16 of 20.** KT-2 still FAIL.

---

## D4. Five post-guard `AFFECTED` rows

Walk of `rule_id=D04` this session: **five** rows, none on 3.5.7.

| Artifact | `decisions.jsonl` | CVE | Finding PURL version | Observed distro SO (this session) | In advisory range? |
|----------|-------------------|-----|----------------------|-----------------------------------|--------------------|
| fw-netgear-r7000-firmware-1.0.12.216 | line 6 | CVE-2023-0286 | `pkg:generic/openssl@1.0.2h` | `OpenSSL 1.0.2h  3 May 2016` at `_squash_R7000-V1.0.12.216_10.2.122.chk/usr/share/libcrypto.so.1.0.0` | **yes** — 1.0.2h is inside `1.0.2` to `<1.0.2zg` |
| oci-node-20 | lines 207–208 | CVE-2026-45445 | `@3.0.19-1~deb12u2` (libssl3 and openssl) | `OpenSSL 3.0.19 27 Jan 2026` | **yes** — `3.0.0` to `<3.0.21` |
| oci-rabbitmq-3 | lines 84–85 | CVE-2026-45445 | `@3.0.13-0ubuntu3.6` | distro `OpenSSL 3.0.13 30 Jan 2024` | **yes** for the finding package |

RabbitMQ extra copy, re-measured this session: `strings -a .lading/profile-rootfs/oci-rabbitmq-3/opt/openssl/lib/libcrypto.so.3` → `OpenSSL 3.1.8 11 Feb 2025`. 3.1.8 is **not** in CVE-2026-45445’s ranges. That is the FINDING-003 unsupported-D04 defect (evidence on the wrong binary). It is **not** a finding-version miss: the PURL and distro object are 3.0.13, which is in range.

**None of the five is out of range on the version the finding refers to.** There is no 3.5.7 `AFFECTED` row. This audit does **not** produce a false `AFFECTED`.

---

## D5. Manifest `affected_versions` vs advisory (verbatim; manifest not changed)

From `manifest/components/native/openssl.yaml`. Exact strings, not ranges (SPEC-MANIFEST). The engine does not read these lists (FINDING-003.md lines 51–78).

### CVE-2023-0286 (lines 28–37)

```yaml
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

Asserted strings the advisory does **not** list as affected: **none.** All eight sit in `3.0.0` to `<3.0.8`. The list omits 1.0.2 and 1.1.1 families the advisory includes; that is a gap, not a false assertion. Netgear 1.0.2h is not in this list.

### CVE-2026-14456 (lines 55–60)

```yaml
    affected_versions:
      - "3.5.0"
      - "3.5.6"
      - "3.5.7"
      - "3.6.0"
      - "4.0.0"
```

Asserted strings the advisory does **not** list as affected: **none.** `3.5.7` is inside `3.5.0` to `<3.5.8`.

### CVE-2026-45445 (lines 78–84)

```yaml
    affected_versions:
      - "3.0.0"
      - "3.0.11"
      - "3.0.15"
      - "3.0.19"
      - "3.0.20"
      - "3.5.6"
      - "3.5.7"
```

Asserted string the advisory does **not** list as affected: **`"3.5.7"`** (advisory 3.5 range is to `<3.5.7`). The other six are in range (`3.0.0`–`3.0.20` inside `<3.0.21`; `3.5.6` inside `<3.5.7`).

### CVE-2026-42767 (lines 102–108)

```yaml
    affected_versions:
      - "3.0.0"
      - "3.0.11"
      - "3.0.15"
      - "3.0.19"
      - "3.0.20"
      - "3.5.6"
      - "3.5.7"
```

Asserted string the advisory does **not** list as affected: **`"3.5.7"`**, same bound as 45445. CP-V2-RECHECK.md line 87 already noted this stale string and that no 42767 corpus *decision* used 3.5.7. This audit extends that to 45445 S5b and to D04: still no decision on 3.5.7 for either CVE.

The false assertion lives in the unused list. It did not emit a false `AFFECTED` and did not move a clearance.

---

## Headline numbers

None moved.

| Figure | FINDING-003 | CP-V4 |
|--------|-------------|-------|
| Unsound corpus D02 | **28 of 35** | **28 of 35** |
| Accidental NA (out of range) | **7** | **7** |
| KT-2 false clearances (overlay) | **16 of 20** | **16 of 20** |
| D04 finding-version out of range | 0 of 5 | **0 of 5** |

The exclusive `<3.5.7` bound is real, and the manifest asserts the excluded string for 42767 and 45445. The corpus never decided those two CVEs on a 3.5.7 artifact. The 3.5.7 artifacts were decided only on CVE-2026-14456, whose 3.5 bound is `<3.5.8`.
