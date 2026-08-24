# Upstream filing drafts (S-05) — HUMAN paste only

Do **not** have an agent open these. File from your own GitHub account.

**Preconditions (met 2026-08-24):**
- S-01: prior art in `FINDING-001-PRIOR-ART.md` — mechanism already stated in [trivy#7850](https://github.com/aquasecurity/trivy/discussions/7850)
- S-02: node:20 is same Debian `SrcName` mechanism (`ANALYSIS-node20.md`); keep as headline
- S-04: only syft→trivy shows material loss; syft→grype matches direct baseline (`PAIRING-MATRIX.md`) → **single-consumer bug**, not a cross-scanner class

**S-01 vs S-05:** Prior art says prefer a **comment on #7850** over a duplicate “discovery” issue. S-05 still wants a Trivy artifact with a proposed fix. Recommended path:

1. **Trivy:** open a short issue *or* a #7850 comment that carries the Debian effect-size + proposed `upstream=` read; if you open an issue, lead with the link to #7850.
2. **Syft:** new issue is appropriate (no Syft issue filed the Trivy property gap).

After filing, paste both URLs here and into `FINDING-001.md` §9 / Status so verification passes:

```bash
grep -c "https://github.com/\(anchore/syft\|aquasecurity/trivy\)/issues/[0-9]" FINDING-001.md
# must be >= 2
```

(If Trivy is only a discussion comment on #7850, also link a Syft issue and either a second Trivy issue for SPDX wipe from `ANALYSIS-spdx.md`, or record the discussion URL in FINDING-001 and adjust the grep — discussion URLs won’t match that pattern.)

---

## A. Syft — new issue

**URL:** https://github.com/anchore/syft/issues/new

**Title:**

```
CycloneDX output does not emit source package in the form Trivy's SBOM ingestion reads
```

**Body:**

```markdown
### Summary

Syft already records the Debian/Alpine source package in CycloneDX in two places:

1. Property `syft:metadata:source` / `syft:metadata:sourceVersion`
2. PURL qualifier `upstream=`

Trivy’s SBOM ingest path reads neither. It looks for `aquasecurity:trivy:SrcName` (and `SrcVersion`). When that property is absent, Trivy silently sets `SrcName` to the binary package name, and Debian advisory matching fails for that package.

This is an interoperability gap, not a claim that Syft’s encoding is wrong. Syft encodes the fact correctly; Trivy’s consumer looks under a different key. Grype consuming the same unmodified Syft CycloneDX/SPDX matches its direct-image baseline (control).

Related Trivy discussion (same mechanism, Alpine example): https://github.com/aquasecurity/trivy/discussions/7850

### Reproduction (public image, no credentials)

```bash
# syft 1.51.0 (also reproduced on 1.22.0), trivy 0.72.0
syft scan docker-archive:nginx.tar -o cyclonedx-json=nginx.cdx.json

trivy sbom nginx.cdx.json --format json \
  | jq -r '[.Results[]?.Vulnerabilities[]?.VulnerabilityID]|unique|length'
# => 137

trivy image --input nginx.tar --format json \
  | jq -r '[.Results[]?.Vulnerabilities[]?.VulnerabilityID]|unique|length'
# => ~409

# Intervention: copy Syft’s existing source value into the property Trivy reads
jq '.components |= map(if .properties then . + {properties: (.properties + [
      {name:"aquasecurity:trivy:SrcName",
       value:((.properties[]?|select(.name=="syft:metadata:source")|.value) // .name)},
      {name:"aquasecurity:trivy:SrcVersion", value:.version}])} else . end)' \
  nginx.cdx.json > nginx-src.cdx.json

trivy sbom nginx-src.cdx.json --format json \
  | jq -r '[.Results[]?.Vulnerabilities[]?.VulnerabilityID]|unique|length'
# => ~415
```

The value was in the SBOM the whole time, e.g.:

```
syft:metadata:source=expat
pkg:deb/debian/libexpat1@…?upstream=expat
```

### Effect size (Trivy 0.72.0 × Syft CycloneDX, before → after injecting `SrcName` from `syft:metadata:source`)

| Image | Before | After | Hidden | % hidden |
|---|---:|---:|---:|---:|
| node:20-bookworm | 335 | 4007 | 3672 | 92% |
| nginx:1.25 | 137 | 415 | 278 | 67% |
| httpd:2.4 | 27 | 129 | 102 | 79% |
| debian:bookworm-slim | 25 | 87 | 62 | 71% |
| … | | | | |

(Full table available on request; 14/22 public images affected; apk/rpm controls unchanged by the intervention.)

Categorical check on `nginx:1.25`: packages with `SrcName != Name` — **0 / 149** on the Syft→Trivy SBOM path vs **114 / 149** on `trivy image`.

### Proposed fix (Syft side)

Optional interoperability property: when emitting CycloneDX for OS packages that already have `syft:metadata:source`, also emit:

```json
{"name": "aquasecurity:trivy:SrcName", "value": "<source>"},
{"name": "aquasecurity:trivy:SrcVersion", "value": "<source version or package version>"}
```

**Alternatively:** if Syft prefers not to emit another tool’s namespaced properties, it is reasonable to close this as “Trivy’s side to fix” — Trivy should read `upstream=` / `syft:metadata:source` when `SrcName` is absent. Happy either way; the gap is real for users who generate with Syft and scan with Trivy.

### Versions

- syft **1.51.0** (2026-08-10) — affected
- syft **1.22.0** — also affected
- trivy 0.72.0 (consumer used for measurement)
```

---

## B. Trivy — comment on discussion #7850 (FINDING-001 / CycloneDX SrcName)

**URL:** https://github.com/aquasecurity/trivy/discussions/7850

**Do not open a duplicate issue for this mechanism.** DmitriyLewen already explained it (Nov 2024): Trivy reads `aquasecurity:trivy:SrcName`; Syft stores source in PURL `upstream=`; Trivy falls back to binary name.

**Body (paste as comment):**

```markdown
Adding measured Debian effect-size and a causal intervention to the mechanism @DmitriyLewen already described here — **not** claiming first discovery of the gap.

We reproduced the same property mismatch on Debian images (syft 1.51.0 → CycloneDX → `trivy sbom`, trivy 0.72.0). On every Debian image tested, packages with `SrcName != Name` are **0/N** on the Syft→Trivy SBOM path while `trivy image` on the same tar recovers source for ~70–77% of packages.

**Effect size (unique VulnerabilityIDs, Syft CycloneDX → `trivy sbom`, before → after copying `syft:metadata:source` into `aquasecurity:trivy:SrcName`):**

| Image | Before | After | % hidden |
|---|---:|---:|---:|
| node:20-bookworm | 335 | 4007 | 92% |
| nginx:1.25 | 137 | 415 | 67% |
| httpd:2.4 | 27 | 129 | 79% |
| debian:bookworm-slim | 25 | 87 | 71% |

Copying the value Syft already wrote into the property name Trivy reads restores counts exactly (nginx 137 → 415). The SBOM contained `syft:metadata:source` and `upstream=` throughout; neither was read.

**Control:** the same unmodified Syft SBOM fed to Grype matches Grype’s direct-image baseline (nginx 407/407, debian 82/82) — this is a Trivy ingest convention gap, not missing Syft data.

**Proposal:** when `aquasecurity:trivy:SrcName` is absent, populate from PURL `upstream=` and/or `syft:metadata:source`, or fail loudly for dpkg/apk when source cannot be recovered. Happy to attach full 14-image table and repro script on request.

(Separate finding: Syft **SPDX** on the same images loses ~150 packages at Trivy ingest — filing as its own issue; different code path from this CycloneDX `SrcName` case.)
```

---

## C. Trivy — new issue (if you want a trackable bug)

**URL:** https://github.com/aquasecurity/trivy/issues/new

**Title:**

```
SBOM ingestion ignores PURL upstream= qualifier, silently defaulting SrcName to binary package name
```

**Body:**

```markdown
### Summary

When ingesting a third-party CycloneDX SBOM, Trivy recovers OS source-package identity only from `aquasecurity:trivy:SrcName`. It does not read:

- PURL qualifier `upstream=`
- producer property `syft:metadata:source`

If `SrcName` is absent, Trivy silently defaults `SrcName` to the binary package name. For Debian (advisories keyed by source package), that under-counts vulnerabilities with no hard error.

This mechanism was already explained on Alpine in discussion https://github.com/aquasecurity/trivy/discussions/7850 (thank you @DmitriyLewen). Opening this to track a fix proposal and to add Debian effect-size / categorical package evidence. Not claiming first discovery of the mechanism.

Both Syft and Trivy encode source correctly on their native paths; this is an interoperability gap on the Syft→Trivy SBOM path. Control: the same unmodified Syft CycloneDX fed to **Grype** matches Grype’s direct-image unique-vuln count (nginx 407/407, debian 82/82, httpd 127/127).

### Reproduction

```bash
# syft 1.51.0, trivy 0.72.0 — public nginx:1.25 docker save
syft scan docker-archive:nginx.tar -o cyclonedx-json=nginx.cdx.json

trivy sbom nginx.cdx.json --list-all-pkgs --format json --skip-db-update \
  | jq '{
      vulns: ([.Results[]?.Vulnerabilities[]?.VulnerabilityID]|unique|length),
      src_ne_name: ([.Results[]?.Packages[]?|select(.SrcName!=null and .SrcName!=.Name)]|length),
      pkgs: ([.Results[]?.Packages[]?]|length)
    }'
# example: {"vulns":137,"src_ne_name":0,"pkgs":150}

trivy image --input nginx.tar --list-all-pkgs --format json --skip-db-update \
  | jq '{
      vulns: ([.Results[]?.Vulnerabilities[]?.VulnerabilityID]|unique|length),
      src_ne_name: ([.Results[]?.Packages[]?|select(.SrcName!=null and .SrcName!=.Name)]|length),
      pkgs: ([.Results[]?.Packages[]?]|length)
    }'
# example: {"vulns":409,"src_ne_name":114,"pkgs":149}
```

**Categorical result (not sampling noise):** on every Debian image tested, the Syft→Trivy SBOM path recovers `SrcName != Name` for **zero** packages (nginx **0/149**, httpd **0/112**, debian:bookworm-slim **0/88**), while `trivy image` on the same tar recovers source for ~70–77% of packages.

Copying `syft:metadata:source` into `aquasecurity:trivy:SrcName` restores the vuln count (nginx 137 → 415). No SBOM field was missing.

### Effect size (unique VulnerabilityIDs, Syft CDX → trivy sbom, before → after SrcName injection)

| Image | Before | After | % hidden |
|---|---:|---:|---:|
| node:20-bookworm | 335 | 4007 | 92% |
| nginx:1.25 | 137 | 415 | 67% |
| httpd:2.4 | 27 | 129 | 79% |
| debian:bookworm-slim | 25 | 87 | 71% |

Pairing matrix (unmodified SBOMs): material loss only on syft→trivy; syft→grype shows none.

### Not DB staleness

Same day: Trivy DB v2 updated **2026-08-24 00:58 UTC**; Grype DB built **2026-08-23**. The tool reporting fewer findings on the SBOM path has the **newer** DB.

### Proposed fix

When decoding CycloneDX/SPDX and `aquasecurity:trivy:SrcName` is absent:

1. Prefer PURL qualifier `upstream=` (parse name[/version] as Syft emits), and/or
2. Prefer property `syft:metadata:source` / `syft:metadata:sourceVersion`

only to populate `SrcName` / `SrcVersion`. Keep existing namespaced properties as highest precedence for Trivy-generated SBOMs.

If reading third-party source fields is intentionally unsupported, a hard failure or explicit per-package warning when distro matching requires `SrcName` and none was recovered would be safer than silent under-count (today’s soft “third-party SBOM may be inaccurate” WARN is easy to miss in CI).

### Versions

- trivy **0.72.0**
- syft **1.51.0** (producer); also seen with syft 1.22.0
```

---

## D. Trivy — new issue (FINDING-SPDX; CP-C1 gate = novel)

**URL:** https://github.com/aquasecurity/trivy/issues/new

**Title:**

```
SPDX JSON ingestion from Syft SBOM retains ~1/150 OS packages (0 vulns); CycloneDX from same run retains all
```

**Body:**

```markdown
### Summary

Interoperability gap on the Syft → Trivy SPDX path (not a vulnerability report). On the **same image tar** and **same Syft version**, switching output format alone changes Trivy ingest from “mostly works” to “near-total loss”:

| Image | Format | Packages in SBOM (PURL) | Trivy packages | Trivy unique vulns |
|---|---|---:|---:|---:|
| nginx:1.25 | cyclonedx-json | 150 | 150 | 137 |
| nginx:1.25 | **spdx-json** | **151** | **1** | **0** |
| debian:bookworm-slim | cyclonedx-json | 88 | 88 | 25 |
| debian:bookworm-slim | **spdx-json** | **89** | **0** | **0** |

Syft generation is not the failure mode: SPDX files contain full `pkg:deb/debian/...` externalRefs. The loss is at **Trivy SPDX unmarshaling/ingestion**.

The sole package Trivy retains from nginx SPDX is misread as a Java artifact:

- `Target: Java`, `Type: jar`, name `libintl:libintl`, 0 vulnerabilities

Ordinary Debian entries (`adduser`, `apt`, … with valid deb PURLs) do not appear in Trivy’s result list.

Related but **separate** from CycloneDX `SrcName` / `upstream=` under-count: https://github.com/aquasecurity/trivy/discussions/7850

### Reproduction

```bash
# syft 1.51.0 (also reproduced on 1.22.0), trivy 0.72.0
syft scan docker-archive:nginx.tar -o cyclonedx-json=nginx.cdx.json
syft scan docker-archive:nginx.tar -o spdx-json=nginx.spdx.json

# Packages with PURL in SBOM
jq '[.components[]?|select(.purl!=null)]|length' nginx.cdx.json
jq '[.packages[]|.externalRefs[]?|select(.referenceType=="purl")]|length' nginx.spdx.json

trivy sbom nginx.cdx.json --format json --skip-db-update \
  | jq '{pkgs:([.Results[]?.Packages[]?]|length), vulns:([.Results[]?.Vulnerabilities[]?.VulnerabilityID]|unique|length)}'
# => pkgs ~150, vulns ~137

trivy sbom nginx.spdx.json --format json --skip-db-update \
  | jq '{pkgs:([.Results[]?.Packages[]?]|length), vulns:([.Results[]?.Vulnerabilities[]?.VulnerabilityID]|unique|length), sample:(.Results[]?.Packages[]?|{Name,Type,Class})}'
# => pkgs 1, vulns 0, sample shows jar/libintl
```

### Proposed fix

When decoding third-party SPDX JSON, classify OS packages from `externalRefs` with `referenceType: purl` and `pkg:deb` / `pkg:apk` / `pkg:rpm` locators similarly to CycloneDX component PURLs — do not route deb package names through the Java/jar path.

If full third-party SPDX OS ingest is out of scope, emit a **hard** failure or per-format warning when >90% of SPDX packages with OS PURLs are dropped (today’s generic third-party SBOM WARN is easy to miss in CI).

### Versions

- trivy **0.72.0**
- syft **1.51.0** and **1.22.0** (producer)
```

Tone: neutral; Aqua is remediating supply-chain incidents — this is an interoperability gap with a proposed fix, not pile-on.

---

## After you file (CP-C2 verification)

1. **Trivy #7850** — comment only (§B); do not duplicate CycloneDX SrcName issue.
2. **Trivy new issue** — SPDX wipe (§D); CP-C1 gate says novel.
3. **Syft new issue** — optional `SrcName` property (§A).

Then update `FINDING-001.md`:

- Status → filed upstream
- §9 checkboxes
- Embed filed URLs

Verification (must be ≥ 2 after filing):

```bash
grep -cE "https://github.com/(anchore/syft|aquasecurity/trivy)/(issues|discussions)/[0-9]+" FINDING-001.md
```

Use at least two **issue** URLs (Syft + Trivy SPDX), or Syft issue + Trivy SPDX issue; #7850 is a **discussion** URL — counts toward the regex above if pasted into FINDING-001.md, but prefer two trackable issues for maintainers.
