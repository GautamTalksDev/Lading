# FINDING-002: Symbol-absence evidence cannot support `vulnerable_code_not_present` on dynamically-linked shared libraries

## Claim

D02 requires evidence that a specific function is absent from the shipped artifact. On a dynamically-linked `.so` the only observable symbol set is `.dynsym` — the export map. Functions that are internal to the library never appear there regardless of whether their code is compiled in. Absence is therefore guaranteed a priori and the verdict is unfalsifiable.

## Evidence (oci-redis-7, OpenSSL 3.0.20)

Artifact paths:

- `.lading/profile-rootfs/oci-redis-7/usr/lib/x86_64-linux-gnu/libcrypto.so.3`
- `.lading/profile-rootfs/oci-redis-7/usr/lib/x86_64-linux-gnu/libssl.so.3`

### Which library each symbol belongs to

| Symbol | Library | Role |
|--------|---------|------|
| `OSSL_CRMF_ENCRYPTEDVALUE_decrypt` | `libcrypto.so.3` | vulnerable (CVE-2026-42767) |
| `aes_ocb_cipher` | `libcrypto.so.3` | vulnerable (CVE-2026-45445) |
| `port_default_packet_handler` | `libssl.so.3` | vulnerable (CVE-2026-14456) |
| `GENERAL_NAME_cmp` | `libcrypto.so.3` | exported contrast case; vulnerable symbol of CVE-2023-0286 only |

A check against the wrong `.so` is not a negative result for that CVE.

### CVE-2026-42767 / `OSSL_CRMF_ENCRYPTEDVALUE_decrypt`

- **Library:** `libcrypto.so.3`
- **`.dynsym`:** `OSSL_CRMF_ENCRYPTEDVALUE_decrypt` absent; wider `OSSL_CRMF_*` API **is** exported (e.g. `OSSL_CRMF_CERTID_new`, `OSSL_CRMF_CERTTEMPLATE_free`, …).
- **Disassembly:** `objdump -d libcrypto.so.3 | grep -ic crmf` → **597** references in `.text`.
- **Build note:** Debian corpus builds do not use OpenSSL `no-cmp`; CRMF code is present while the named decrypt helper is not export-observable.

### CVE-2026-45445 / `aes_ocb_cipher`

- **Library:** `libcrypto.so.3`
- **`.dynsym`:** **0** exported symbols matching `aes_ocb_cipher`.
- **Disassembly:** `objdump -d libcrypto.so.3 | grep -ic ocb` → **304** references in `.text` (code ships; symbol is provider-internal).

### CVE-2026-14456 / `port_default_packet_handler`

- **Library:** `libssl.so.3` (DTLS/QUIC live here, not in `libcrypto.so.3`).
- **`.dynsym`:** `port_default_packet_handler` **not** in `.dynsym` (**0** exported).
- **Disassembly:** `objdump -d libssl.so.3 | grep -ic dtls` → **691**.
- **Exports:** `nm -D --defined-only libssl.so.3 | grep -ci dtls` → **13** exported DTLS symbols (`port_default_packet_handler` is not among them).
- **Strings:** `strings -a libssl.so.3 | grep -ci dtls` → **43**.
- **Shape:** same as CRMF and OCB — code present, symbol private, absence from `.dynsym` guaranteed.

**Correction (part of the record).** The initial check ran `objdump -d libcrypto.so.3 | grep -icE 'dtls|packet_handler'` and recorded **0** DTLS references / **98** `quic` hits. That was the wrong library: DTLS code does not live in `libcrypto.so.3`. The numbers above replace that measurement. The first observation is retained only as the reason the check was re-run, not as evidence about CVE-2026-14456.

**Contrast:** `GENERAL_NAME_cmp` **is** exported from `libcrypto.so.3` (`T GENERAL_NAME_cmp@@OPENSSL_3.0.0`) — the one OpenSSL vulnerable symbol where `.dynsym` absence would be meaningful evidence of non-presence. See Manifest attribution below: that symbol belongs to CVE-2023-0286, not to CVE-2026-14456.

## Scope

All **35** corpus `NOT_AFFECTED` clearances were D02 on these three CVEs. All are therefore unsound under the current evidence model:

| CVE | Corpus D02 clearances |
|-----|----------------------:|
| CVE-2026-14456 | 22 |
| CVE-2026-42767 | 9 |
| CVE-2026-45445 | 4 |

The real-100 KT-2 sample includes **20** of these false clearances (all pipeline `NOT_AFFECTED` rows); hand labels record **UNDER_INVESTIGATION** per this finding.

## Root cause in the manifest

`manifest/components/native/openssl.yaml` records these symbols with `confidence: definitive` and a `patch-touched-function` derivation. The derivation identifies the correct upstream function but does not check whether that function is observable in a stripped, dynamically-linked build, nor which shipped `.so` it belongs to.

The note on the CVE-2026-42767 entry states the function "is not exported on the corpus libcrypto.so.3 builds" and treats that as evidence — this is the defect, stated in the manifest by its own author.

## Manifest attribution (report only — manifest not changed)

`GENERAL_NAME_cmp` is **not** a vulnerable symbol of CVE-2026-14456. Source of truth is `manifest/components/native/openssl.yaml`:

| CVE | `vulnerable_symbols` (exactly one each) |
|-----|-----------------------------------------|
| CVE-2023-0286 | `GENERAL_NAME_cmp` (`dynsym_export_verified: true`) |
| CVE-2026-14456 | `port_default_packet_handler` |
| CVE-2026-45445 | `aes_ocb_cipher` |
| CVE-2026-42767 | `OSSL_CRMF_ENCRYPTEDVALUE_decrypt` |

No CVE entry carries two vulnerable symbols. `GENERAL_NAME_cmp` also appears in the component-level `identity_symbols` list, so evidence-bundle `observations.json` for CVE-2026-14456 / 42767 / 45445 can cite `reason: symbol:GENERAL_NAME_cmp` as the **identity hit** that bound the finding to OpenSSL. That is not a second vulnerable symbol on those CVEs.

FINDING-002 previously listed the `GENERAL_NAME_cmp` export as a contrast bullet under CVE-2026-14456. The engine guard notes the `dynsym_export_verified` flag on CVE-2023-0286 only. Both are consistent with the table above; they are not two attributions of the same vulnerable symbol.

`RESULTS.md` does not name `GENERAL_NAME_cmp`. The apparent RESULTS.md / engine mismatch is the identity-symbol citation in CVE-2026-14456 bundles plus the contrast bullet above, versus the engine note that only CVE-2023-0286 is export-verified.

## Implication

- **D02** is sound only for symbols verified present in `.dynsym` on at least one reference build (`dynsym_export_verified`). For internal functions it requires disassembly-level evidence, not symbol-table absence on the consumer binary or export map alone.
- **D01** (`component_not_present`) is unaffected by this finding — but CP-11 produced **zero** natural D01 instances. Of **55** scanned artifacts, **22** have grype matches on package name/PURL naming OpenSSL; path-agnostic `find <rootfs> -name 'libssl.so*' -o -name 'libcrypto.so*'` locates `.so` on **all 22** (**0** without). Only **19** artifacts ever bind `component=openssl` in `decisions.jsonl`. Grype package presence was correct in every testable case; only the vulnerable-code question (D02) arose.
- **Library home.** The observability guard closes the “internal symbol ⇒ guaranteed absence” hole, but the engine still searches every inventoried binary’s `.dynsym` indiscriminately. It does not record which library a vulnerable symbol is expected to live in. A `libcrypto.so.3` check cannot answer a `libssl.so.3` question; that binding belongs in the manifest (or the engine will keep measuring the wrong file).
- **Layout assumptions.** Analysis during this session assumed Debian multiarch paths (`usr/lib/*/`) when hunting absent OpenSSL libraries; that produced three false D01 candidates (including Netgear firmware) before a path-agnostic `find` cleared them. Same defect class as the initial wrong-library check for CVE-2026-14456 — the instrument and its analysis scripts both embed layout priors that must be stated, not assumed.

## Engine response (2026-08-24)

`decide` refuses D02 with `reason_code: symbol_not_observable` when a definitive vulnerable symbol lacks `dynsym_export_verified` in the manifest. See `internal/decide/evaluate.go` and `manifest/components/native/openssl.yaml` (`GENERAL_NAME_cmp` on CVE-2023-0286 only carries `dynsym_export_verified: true`).
