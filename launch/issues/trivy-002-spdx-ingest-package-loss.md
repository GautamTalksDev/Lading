# Trivy issue draft — SPDX SBOM ingestion retains ~0 OS packages

**File at:** https://github.com/aquasecurity/trivy/issues/new  
**Labels (suggested):** `bug`, `sbom`, `spdx`  
**Status:** Draft — paste after review

---

## Title

`trivy sbom` on Syft SPDX-JSON SBOMs drops almost all OS packages (Debian images: ~150 SBOM packages → 0–1 Trivy packages, 0 vulnerabilities)

## Summary

Syft generates valid SPDX-JSON SBOMs with **~150** Debian packages (each with `pkg:deb/...` PURLs) from the same container image tar that yields **~150** packages and non-zero vulnerabilities when exported as **CycloneDX** and scanned with `trivy sbom`.

On the **SPDX** path, `trivy sbom` retains **one** package (mis-typed as Java/jar on nginx) or **zero** packages (debian:bookworm-slim), and reports **zero** vulnerabilities — while `trivy image` on the same tar reports dozens to hundreds.

The loss is at **Trivy ingestion**, not Syft generation: the SPDX file on disk contains the full package list with PURLs before Trivy runs.

## Environment

| Component | Version |
|-----------|---------|
| trivy | 0.72.0 |
| trivy DB | v2, updated 2026-08-24 |
| syft | 1.51.0 (also reproduced on 1.22.0) |
| OS | Ubuntu 24.04 (WSL2) |

## Steps to reproduce

Obtain a docker-archive tar (`docker pull nginx:1.25 && docker save nginx:1.25 -o nginx.tar`, or any equivalent saved tar). **Verified 2026-08-24** with a pre-saved tar and syft 1.51.0 + trivy 0.72.0 (no live Docker daemon required for re-scan).

```bash
syft scan docker-archive:nginx.tar -o cyclonedx-json=nginx.cdx.json
syft scan docker-archive:nginx.tar -o spdx-json=nginx.spdx.json

# Count packages with PURLs in each SBOM (before Trivy)
# CycloneDX: ~150 deb components with PURLs (of ~3863 total components)
# SPDX: ~151 packages, each with externalRef purl locators

# Trivy on CycloneDX (under-counts vs image — see separate SrcName issue — but non-zero)
trivy sbom nginx.cdx.json --format json | jq '[.Results[]?.Packages[]?]|length'
# observed: 150

# Trivy on SPDX
trivy sbom nginx.spdx.json --format json | jq '[.Results[]?.Packages[]?]|length'
# observed: 1

trivy sbom nginx.spdx.json --format json \
  | jq -r '[.Results[]?.Vulnerabilities[]?.VulnerabilityID]|unique|length'
# observed: 0

# Direct image baseline
trivy image --input nginx.tar --format json \
  | jq -r '[.Results[]?.Vulnerabilities[]?.VulnerabilityID]|unique|length'
# observed: 409
```

Repeat on `debian:bookworm-slim`:

| Format | Packages in SBOM (with PURL) | Trivy packages | Trivy unique vulns |
|--------|----------------------------:|---------------:|-------------------:|
| CycloneDX | 88 | 88 | 25 |
| SPDX | 89 | **0** | **0** |
| `trivy image` | — | 87 pkgs | 87 vulns |

## What Trivy keeps from nginx SPDX

Trivy JSON shows a single result:

- `Target: Java`, `Type: jar`, package `libintl:libintl`, **0** vulnerabilities.

Ordinary Debian packages at the start of the SPDX document (e.g. `adduser`, `apt` with `pkg:deb/debian/...` PURLs) do **not** appear in Trivy's package list.

## Expected behavior

SPDX SBOM ingestion should retain OS packages with valid PURL external references at parity with CycloneDX ingestion (modulo format mapping), or emit a clear error/warning when packages are skipped.

## Actual behavior

Near-total package drop on SPDX; **zero** vulnerabilities reported for images that are not clean on the direct scan path. No error emitted.

## Effect size

Reproduced on **both** syft 1.22.0 and 1.51.0 with trivy 0.72.0. **3/3** Debian images in our pairing matrix show **100%** vulnerability loss on `syft_spdx→trivy` vs `trivy image` baseline (nginx, debian-slim, httpd). CycloneDX from the same Syft run on the same tar does not show total loss (partial under-count only — see related SrcName issue).

Grype ingesting the same Syft SPDX SBOM does **not** show this wipe (`syft SPDX→grype` matches `grype image` in our matrix).

## Impact

Organizations standardizing on **SPDX** for CRA SBOM delivery may get a **clean vulnerability report** from `trivy sbom` while the same artifact scanned directly shows hundreds of findings — with no indication the SBOM format path failed.

## Suggested investigation

- SPDX externalRef / PURL locator parsing for `pkg:deb` packages
- Relationship to CycloneDX ingest path (why CDX retains packages, SPDX does not)
- Whether SPDX 2.3 vs JSON schema field mapping drops `hasFiles` / package sections

## Additional context

- Measurement script: `scripts/spdx-anomaly.sh` (workdir `.lading/spdx-anomaly/`)
- Write-up: `ANALYSIS-spdx.md` (in-repo)
- **Related but distinct:** CycloneDX Debian `SrcName` under-count — see [Trivy discussion #7850](https://github.com/aquasecurity/trivy/discussions/7850) (measurement comment, not a duplicate of this SPDX path)

---

**Reporter:** Gautam Khosla · can provide SPDX + CycloneDX fixtures from public images on request.
