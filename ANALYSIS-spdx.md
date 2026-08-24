# ANALYSIS-spdx — Where does the SPDX package loss occur?

**The loss occurs at INGESTION: Syft writes a full SPDX package list with PURLs; Trivy `sbom` retains essentially none of them (nginx: 1 package / 0 vulns; debian:bookworm-slim: 0 packages / 0 vulns).**

## Evidence

Script: `scripts/spdx-anomaly.sh`  
Workdir: `.lading/spdx-anomaly/`  
Images: `corpus/downloads/oci-nginx-1.25/image.tar`, `oci-debian-bookworm-slim/image.tar`  
Measurement only — same image tar → both formats → jq counts on the SBOM file → `trivy sbom`.

### Tool versions

| Tool | Version | Build / notes |
|---|---|---|
| syft | **1.51.0** | 2026-08-10 (`GitCommit` 2293641e) |
| syft | **1.22.0** | 2025-04-01 (`GitCommit` 9ab83874) |
| trivy | **0.72.0** | DB v2 updated 2026-08-24 00:58 UTC |

### 2×2 — syft 1.51.0 (current)

| Image | Format | Packages in SBOM (with PURL) | Unique PURLs | Trivy packages | Trivy unique vulns |
|---|---|---:|---:|---:|---:|
| nginx:1.25 | cyclonedx-json | 150 / 3863 total components | 150 | 150 | 137 |
| nginx:1.25 | spdx-json | **151** / 151 | 151 | **1** | **0** |
| debian:bookworm-slim | cyclonedx-json | 88 / 3077 | 88 | 88 | 25 |
| debian:bookworm-slim | spdx-json | **89** / 89 | 89 | **0** | **0** |

### 2×2 — syft 1.22.0 (older)

| Image | Format | Packages in SBOM (with PURL) | Unique PURLs | Trivy packages | Trivy unique vulns |
|---|---|---:|---:|---:|---:|
| nginx:1.25 | cyclonedx-json | 152 / 3863 | 152 | 150 | 137 |
| nginx:1.25 | spdx-json | **153** / 153 | 153 | **1** | **0** |
| debian:bookworm-slim | cyclonedx-json | 90 / 3077 | 90 | 88 | 25 |
| debian:bookworm-slim | spdx-json | **91** / 91 | 91 | **0** | **0** |

Generation is not the failure mode: SPDX files contain ~150 (nginx) / ~90 (debian) packages with `referenceType: purl` / `pkg:deb/...` locators. CycloneDX from the same Syft run of the same tar yields comparable PURL counts and non-zero Trivy vulns.

### What Trivy keeps from nginx SPDX

For syft 1.51.0 → nginx SPDX, Trivy’s JSON has a single result:

- `Target: Java`, `Type: jar`, package name `libintl:libintl`, 0 vulnerabilities.

The SPDX document’s first packages are ordinary Debian entries (e.g. `adduser` / `apt` with `pkg:deb/debian/...` PURLs). Those do not appear in Trivy’s package list. debian:bookworm-slim SPDX yields an empty Results array.

### Implication (for later filing; not fixed here)

This is an **ingestion-side Trivy finding**, present on both syft 1.22.0 and 1.51.0. Effect size is total (or near-total) loss of OS-package vulnerability signal on the SPDX path, larger than FINDING-001’s partial CycloneDX under-count. Belongs as a second Trivy upstream item, not a Syft generation bug.
