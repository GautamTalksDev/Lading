# PAIRING-MATRIX — Is source-package attribution loss a class?

**FINDING-001 S-04.** Unmodified Syft SBOMs only. Same image tars for every cell.

## Tool pins

```
syft=1.51.0
trivy=0.72.0
trivy_db_updated_at=2026-08-24 00:58:29.990132025
grype=0.115.0
grype_db=Path:      /home/gautamtalksdev/.cache/grype/db/6/vulnerability.db;Schema:    v6.1.9;Built:     2026-08-24T06:22:13Z;Status:    valid;
syft_bin=/home/gautamtalksdev/bin/syft-1.51.0
trivy_bin=/home/gautamtalksdev/bin/trivy
grype_bin=/home/gautamtalksdev/bin/grype
date_utc=2026-08-24T20:59:35Z
```

## Full matrix (unique VulnerabilityIDs / src≠binary packages)

| image | model | trivy image | syft CDX→trivy | syft SPDX→trivy | grype image | syft CDX→grype | syft SPDX→grype |
|---|---|---:|---:|---:|---:|---:|---:|
| `nginx:1.25` | deb | 409 / 114 | 137 / 0 | 0 / 0 | 407 / 114 | 407 / 57 | 407 / 57 |
| `debian:bookworm-slim` | deb | 87 / 62 | 25 / 0 | 0 / 0 | 82 / 62 | 82 / 32 | 82 / 32 |
| `httpd:2.4` | deb | 129 / 85 | 27 / 0 | 0 / 0 | 127 / 44 | 127 / 44 | 127 / 44 |
| `alpine:3.20` | apk | 0 / 8 | 0 / 0 | 0 / 0 | 1 / 8 | 1 / 8 | 1 / 8 |
| `fedora:40` | rpm | 0 / 0 | 0 / 0 | 0 / 0 | 17 / 67 | 17 / 67 | 17 / 67 |

Cell format: `unique_vulns / src_ne_binary` where `src_ne_binary` is packages for which the consumer resolved a source/upstream name different from the binary name (Trivy: `SrcName`; Grype: `upstreams`).

Grype SBOM mode often omits `alertsByPackage`; there `src_ne_binary` is counted from distinct match artifacts only (may under-count inventory).

## Material loss vs same-tool direct baseline

Threshold: SBOM cell with baseline unique vulns > 0, and (cur == 0 OR absolute drop ≥ 5 OR loss ≥ 10%).

| image | model | cell | baseline | sbom | Δ | loss% | src_ne (sbom) | src_ne (baseline) |
|---|---|---|---:|---:|---:|---:|---:|---:|
| `nginx:1.25` | deb | syft_cdx→trivy | 409 | 137 | -272 | 66.5 | 0 | 114 |
| `nginx:1.25` | deb | syft_spdx→trivy | 409 | 0 | -409 | 100.0 | 0 | 114 |
| `debian:bookworm-slim` | deb | syft_cdx→trivy | 87 | 25 | -62 | 71.3 | 0 | 62 |
| `debian:bookworm-slim` | deb | syft_spdx→trivy | 87 | 0 | -87 | 100.0 | 0 | 62 |
| `httpd:2.4` | deb | syft_cdx→trivy | 129 | 27 | -102 | 79.1 | 0 | 85 |
| `httpd:2.4` | deb | syft_spdx→trivy | 129 | 0 | -129 | 100.0 | 0 | 85 |

## Correlation with distro advisory model

| advisory_model | cell | images | material_loss | mean loss% (where baseline>0) | mean src_ne_binary (sbom) | mean src_ne_binary (baseline) |
|---|---|---:|---:|---:|---:|---:|
| deb | syft_cdx→trivy | 3 | 3/3 | 72.3 | 0.0 | 87.0 |
| deb | syft_spdx→trivy | 3 | 3/3 | 100.0 | 0.0 | 87.0 |
| deb | syft_cdx→grype | 3 | 0/3 | 0.0 | 44.3 | 73.3 |
| deb | syft_spdx→grype | 3 | 0/3 | 0.0 | 44.3 | 73.3 |
| apk | syft_cdx→trivy | 1 | 0/1 | 0.0 | 0.0 | 8.0 |
| apk | syft_spdx→trivy | 1 | 0/1 | 0.0 | 0.0 | 8.0 |
| apk | syft_cdx→grype | 1 | 0/1 | 0.0 | 8.0 | 8.0 |
| apk | syft_spdx→grype | 1 | 0/1 | 0.0 | 8.0 | 8.0 |
| rpm | syft_cdx→trivy | 1 | 0/1 | 0.0 | 0.0 | 0.0 |
| rpm | syft_spdx→trivy | 1 | 0/1 | 0.0 | 0.0 | 0.0 |
| rpm | syft_cdx→grype | 1 | 0/1 | 0.0 | 67.0 | 67.0 |
| rpm | syft_spdx→grype | 1 | 0/1 | 0.0 | 67.0 | 67.0 |

## Decision gate

Cells with material loss: syft_cdx__trivy, syft_spdx__trivy

**Only syft→trivy affected (both CycloneDX under-count and SPDX near-total wipe); syft→grype does not show material loss → single-consumer bug class inside Trivy, not a cross-scanner class.** File against Trivy (two issues or one with two formats); short post; Grype remains the control that preserves upstream.

## Notes on correlation

- syft CDX→trivy on **deb** images: material_loss in 3/3; mean sbom src_ne_binary=0.0 vs baseline 87.0.
- syft CDX→trivy on **apk/rpm controls**: material_loss in 0/2; mean sbom src_ne_binary=0.0.
- **Structural signal on apk anyway:** alpine:3.20 still loses source resolution under Trivy CDX ingest (`src_ne_binary` 8 → 0) with no vuln delta (baseline unique vulns=0). Trivy fails to resolve source on apk SBOMs too; Debian is where that failure becomes a large vulnerability under-count.
- syft CDX→grype on **deb**: material_loss in 0/3 (control for whether the SBOM itself lacks source data). Same unique vuln counts as `grype_image` on every image, including SPDX — Grype reads what Syft wrote.
- **fedora:40 / trivy caveat:** `trivy image` reported 0 packages on this tar (grype saw 149). Do not interpret the rpm control’s zero Trivy vulns as proof that rpm is unaffected; use grype rows for rpm integrity of the SBOM.

