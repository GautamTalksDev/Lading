# FINDING-001 — Source-package attribution is lost between Syft and Trivy, hiding up to 92% of Debian vulnerabilities

**Status:** Draft. Not published. Trivy CycloneDX filing live (2026-08-24); SPDX and Syft pending.
**Date of experiment:** 2026-08-24
**Author:** Gautam Khosla
**Reproduction:** five commands, public images, no credentials required.

---

## 1. Summary

Debian security advisories are published against **source packages**. A scanner that
attributes a binary package (`libexpat1`) to its source package (`expat`) matches those
advisories. A scanner that does not, matches none of them.

Syft records the source package in its CycloneDX output twice — as
`syft:metadata:source` in component properties, and as the `upstream=` qualifier in the
PURL. Trivy's SBOM ingestion path reads neither. It looks for its own namespaced
property, `aquasecurity:trivy:SrcName`. When that property is absent, `SrcName` silently
defaults to the binary package name and Debian advisory matching fails for that package.

On `nginx:1.25`, this produces **137 vulnerabilities instead of 415** — same tool, same
vulnerability database, same day, same artifact.

Copying the value Syft already wrote into the property name Trivy reads produces
**415**, which is exactly the union of the two result sets: the **409** the direct
scan reports plus **6** nginx-package advisories that only the SBOM path surfaces.
Neither result is a superset of the other. **No data was missing from the SBOM at
any point.**

## 2. Effect size

22 public container images. Trivy 0.72.0 scanning a Syft-generated CycloneDX SBOM,
before and after injecting `aquasecurity:trivy:SrcName` / `SrcVersion` from the
`syft:metadata:source` value already present in the same document.

### Affected images

| Image | Before | After | Hidden | % hidden |
|---|---:|---:|---:|---:|
| node:20-bookworm | 335 | 4007 | 3672 | 92% |
| nginx:1.25 | 137 | 415 | 278 | 67% |
| httpd:2.4 | 27 | 129 | 102 | 79% |
| memcached:1.6 | 23 | 89 | 66 | 74% |
| redis:7 | 25 | 91 | 66 | 73% |
| debian:bookworm-slim | 25 | 87 | 62 | 71% |
| postgres:16 | 92 | 153 | 61 | 40% |
| python:3.12-slim | 30 | 86 | 56 | 65% |
| ruby:3.3-slim | 28 | 84 | 56 | 67% |
| rabbitmq:3-management | 119 | 166 | 47 | 28% |
| golang:1.22-bookworm | 0 | 19 | 19 | 100% |
| ubuntu:22.04 | 2 | 10 | 8 | 80% |
| mariadb:11 | 48 | 56 | 8 | 14% |
| ubuntu:24.04 | 2 | 6 | 4 | 67% |

14 of 22 images affected. Two images report a clean bill of health (0 findings) while
carrying 19 findings that the same tool reports when reading the image directly.

### Unaffected images — the control group

| Image | Before | After | Package model |
|---|---:|---:|---|
| alpine:3.20 | 0 | 0 | apk |
| busybox:latest | 0 | 0 | apk |
| fedora:40 | 0 | 0 | rpm |
| rockylinux:9 | 74 | 74 | rpm |
| amazonlinux:2023 | 0 | 0 | rpm |
| ubi9-minimal | 0 | 0 | rpm |
| grafana:11 | 158 | 158 | Go binaries |
| traefik:v3 | 163 | 163 | Go binaries |

The effect appears **only** where Debian's source-package advisory model applies. RPM,
APK and Go-binary images are unchanged by the intervention. A spurious correlation would
not sort itself along this line.

## 3. Mechanism

Trivy's per-package output for `libexpat1`, same image, two input paths:

| Path | Name | Version | SrcName | SrcVersion |
|---|---|---|---|---|
| SBOM | libexpat1 | 2.5.0-1 | **libexpat1** | **2.5.0-1** |
| Direct image | libexpat1 | 2.5.0 | **expat** | **2.5.0** |

Across three Debian images, packages where `SrcName != Name`:

| Image | SBOM path | Direct path |
|---|---|---|
| nginx:1.25 | **0 / 149** | 114 / 149 |
| httpd:2.4 | **0 / 112** | 85 / 112 |
| debian:bookworm-slim | **0 / 88** | 62 / 88 |

The SBOM path recovers a source package for **zero** packages on **every** image tested.
The direct path recovers one for 70–77%.

The value is present in the SBOM the entire time:

```
syft:metadata:source=expat
pkg:deb/debian/libexpat1@2.5.0-1?arch=amd64&distro=debian-12&upstream=expat
```

## 4. Reproduction

```bash
syft scan docker-archive:nginx.tar -o cyclonedx-json=nginx.cdx.json

# Baseline: SBOM path
trivy sbom nginx.cdx.json --format json \
  | jq -r '[.Results[]?.Vulnerabilities[]?.VulnerabilityID]|unique|length'
# => 137

# Same artifact, direct
trivy image --input nginx.tar --format json \
  | jq -r '[.Results[]?.Vulnerabilities[]?.VulnerabilityID]|unique|length'
# => 409

# Intervention: copy syft's source value into the property Trivy reads
jq '.components |= map(if .properties then . + {properties: (.properties + [
      {name:"aquasecurity:trivy:SrcName",
       value:((.properties[]?|select(.name=="syft:metadata:source")|.value) // .name)},
      {name:"aquasecurity:trivy:SrcVersion", value:.version}])} else . end)' \
  nginx.cdx.json > nginx-src.cdx.json

trivy sbom nginx-src.cdx.json --format json \
  | jq -r '[.Results[]?.Vulnerabilities[]?.VulnerabilityID]|unique|length'
# => 415
```

## 5. Hypotheses considered and falsified

Four explanations were proposed before this one and each was killed by a control. They
are recorded because they are the reason the surviving explanation is believable.

| # | Hypothesis | Test | Result |
|---|---|---|---|
| 1 | Vulnerability database staleness | Compared DB build timestamps | **Falsified.** Trivy's DB (2026-08-24) is *newer* than Grype's (2026-08-23). The tool reporting fewer findings has fresher data. |
| 2 | Red Hat VEX cross-suppression on unversioned PURLs | Attached RHEL VEX to a Debian SBOM in Grype | **Falsified.** Grype retained the match; 0 ignored. No cross-type suppression occurred. |
| 3 | The SBOM is lossy / drops components | Compared component counts | **Falsified.** Syft emits 3,863 components vs Trivy's 149 packages. The SBOM has *more* data; 3,711 components carry no PURL (file entries), and the 149 deb PURLs match exactly. |
| 4 | OS version metadata drift (`debian 12` vs `debian 12.5`) | Patched the SBOM's OS version to 12.5 and rescanned | **Falsified.** Count remained 137. A correlate, not a cause. |

## 6. Limitations — read before filing

1. ~~**Syft version is 16 months old.**~~ **RESOLVED 2026-08-24:** re-tested with syft 1.51.0 (released 2026-08-10, current). Still emits only `syft:metadata:source`; Trivy SBOM path still reports 137. The gap is live on current releases of both tools.
   A current syft release may already emit `aquasecurity:trivy:SrcName`, in which case
   this describes a fixed bug. **This must be checked against the latest syft before
   anything is filed or published.** It is the single largest threat to this finding.
2. **One Trivy version.** 0.72.0 only. Not tested across the Trivy release range.
3. ~~**node:20's 4007 is unexplained.**~~ **RESOLVED 2026-08-24:** see `ANALYSIS-node20.md`.
   All 3,672 newly-surfaced IDs are `pkg:deb` (npm unchanged at 27). Same Debian
   `SrcName` mechanism as nginx:1.25; magnitude dominated by `linux-libc-dev` (3,319).
   Keep as headline.
4. ~~**SPDX path is a separate anomaly.**~~ **RESOLVED 2026-08-24:** see `ANALYSIS-spdx.md`.
   Loss is at **Trivy ingestion**, not Syft generation. Syft SPDX for nginx:1.25 has
   ~151 packages with PURLs; `trivy sbom` retains 1 package (`libintl:libintl` as jar)
   and 0 vulns. Same pattern on debian:bookworm-slim (89 → 0). Reproduced on syft
   1.22.0 and 1.51.0 with trivy 0.72.0. Second Trivy finding; larger than CycloneDX
   under-count. Not fixed here.
5. **Direction of correctness is not asserted.** This documents that the two paths
   disagree and why. Whether 415 or 137 is the "right" answer for a given compliance
   purpose is a separate question involving distro triage status (`no-dsa`,
   `unimportant`), which this finding does not address.
6. **No claim is made that either tool is defective.** Both encode the source package
   correctly. This is an interoperability gap between namespaced property conventions.

## 7. Why this matters for the CRA

The EU Cyber Resilience Act mandates a machine-readable SBOM as the record of what a
manufacturer shipped, with full compliance due 11 December 2027. This finding shows that
the mandated artifact can be complete and correct while the compliance answer derived
from it is wrong by a factor of three — with no error emitted, no schema violation, and
no field missing.

Two images in this sample report zero vulnerabilities through the SBOM path and nineteen
through the direct path. A technical file asserting "no known exploitable
vulnerabilities" records neither which tools produced it nor that the pairing mattered.

## 8. Environment

| Component | Version |
|---|---|
| syft | 1.22.0 (build 2025-04-01) and 1.51.0 (build 2026-08-10) — both affected |
| trivy | 0.72.0 |
| trivy DB | v2, updated 2026-08-24 00:58 UTC |
| grype | 0.115.0 (build 2026-06-26) |
| grype DB | v6.1.9, built 2026-08-23 06:15 UTC |
| OS | Ubuntu 24.04 |

## 9. Next actions

### Upstream filing status

- **Trivy — CycloneDX Debian source-package attribution.** Filed **2026-08-24** as a
  False Detection discussion:
  https://github.com/aquasecurity/trivy/discussions/11139  
  Mechanism credited to discussion [#7850](https://github.com/aquasecurity/trivy/discussions/7850)
  (DmitriyLewen, Nov 2024) for Alpine. Our contribution is the effect size on Debian
  images, not the cause.  
  Reported: `nginx:1.25` gives **137** unique CVEs via `trivy sbom` on a Syft CycloneDX
  SBOM and **409** via `trivy image` on the same tar. **278** missed, including **13**
  CRITICAL and **63** HIGH by unique CVE ID.  
  Image digest
  `sha256:a484819eb60211f5299034ac80f6a681b06f89e65866ce91f356ed7c72af059c`.  
  Reproduced on a freshly pulled image **2026-08-24**, trivy **0.72.0**, syft **1.51.0**
  and **1.22.0**.  
  Clarification comment posted 2026-08-25:
  https://github.com/aquasecurity/trivy/discussions/11139#discussioncomment-18144443.
  States that 278 is the cardinality of image \ sbom rather than 409 minus 137,
  lists the 6 SBOM-only IDs, and records that 415 is the union of the two sets.  
  Pointer comment posted on #7850 2026-08-25:
  https://github.com/aquasecurity/trivy/discussions/7850#discussioncomment-18144530.
  Credits DmitriyLewen's original explanation on his own thread and routes readers
  to #11139.

- **Trivy — SPDX ingestion package loss.** **NOT YET FILED.** Draft at
  `launch/issues/trivy-002-spdx-ingest-package-loss.md`.

- **Syft — source-package property emission.** **NOT YET FILED.** Decide after Trivy
  responds, since the fix may belong on only one side.

### Checklist

- [x] **Re-test with current syft.** Done 2026-08-24: 1.51.0 still affected.
- [ ] Re-test across 2–3 Trivy versions.
- [x] **Explain node:20's 4007.** Done 2026-08-24: deb-only; same mechanism (`ANALYSIS-node20.md`).
- [ ] File an issue with the Syft project proposing the property mapping.
- [x] **File with Trivy** (CycloneDX / `upstream=` read path). Done 2026-08-24:
  [discussion #11139](https://github.com/aquasecurity/trivy/discussions/11139) (False
  Detection; mechanism credited to #7850).
- [ ] File Trivy SPDX ingestion issue (`launch/issues/trivy-002-spdx-ingest-package-loss.md`).
- [ ] Only then: publish.
