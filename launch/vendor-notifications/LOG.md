# Vendor pre-notification log

**Policy:** Any organization named in a public post receives private notice **≥14 days** before publication. No exceptions.

Record every notice here before sending.

| # | Organization | Named in | Contact / channel | Sent (UTC) | Earliest public use |
|---|--------------|----------|-------------------|------------|---------------------|
| 1 | Grafana Labs | Post 1 (oci-grafana-11 CVE volume) | security@grafana.com | _pending_ | sent + 14d |
| 2 | Docker, Inc. | Post 1 (official `library/*` images in corpus) | security@docker.com | _pending_ | sent + 14d |
| 3 | OpenWrt project | Post 1 (rootfs artifacts) | security@openwrt.org | _pending_ | sent + 14d |
| 4 | Anchore / Grype | Post 2 (Grype-class inert VEX failure mode) | See `outreach/03-grype-maintainers.md` | _pending_ | sent + 14d |
| 5 | Aqua Security / Trivy | Post 2 (Trivy-class overbroad VEX failure mode) | See `outreach/04-trivy-maintainers.md` | _pending_ | sent + 14d |

## Not notified (and why)

| Organization | Reason |
|--------------|--------|
| TP-Link, Netgear | Original GPL URLs 404; corpus rows use documented substitutes (`ARTIFACTS.yaml` notes). Posts do not claim analysis of vendor flash images. |
| Node.js Foundation, etc. | CVE counts cited only as aggregate scanner output on public OCI images; no product-defect allegation. Optional courtesy notice via Docker security contact. |

## Template

See `TEMPLATE.md`. Customize every send; do not mail-merge.

---

## Upstream filings (FINDING-001)

Bug-report and measurement threads filed with tool maintainers (distinct from pre-publication vendor notices above).

| Date (UTC) | Vendor | URL | What was reported | Status |
|------------|--------|-----|-------------------|--------|
| 2026-08-24 | Aqua Security / Trivy | https://github.com/aquasecurity/trivy/discussions/11139 | CycloneDX Debian source-package attribution: `nginx:1.25` — 137 unique CVEs (`trivy sbom` on Syft CDX) vs 409 (`trivy image`); 278 missed (13 CRITICAL, 63 HIGH). Mechanism credited to #7850; Debian effect-size contribution. Digest `sha256:a484819eb60211f5299034ac80f6a681b06f89e65866ce91f356ed7c72af059c`. trivy 0.72.0; syft 1.51.0 and 1.22.0. | Open (False Detection discussion) |
| 2026-08-25 | Aqua Security / Trivy | https://github.com/aquasecurity/trivy/discussions/7850#discussioncomment-18144530 | Pointer on #7850: credits DmitriyLewen's Alpine SrcName explanation; routes Debian effect-size measurement to #11139 (22 images; nginx 137 vs 409). | Posted |
| — | Aqua Security / Trivy | — | SPDX ingestion near-total package loss (Syft spdx-json → `trivy sbom`). Draft: `launch/issues/trivy-002-spdx-ingest-package-loss.md` | **Not yet filed** |
| — | Anchore / Syft | — | Optional `aquasecurity:trivy:SrcName` emission from existing source fields | **Not yet filed** — pending Trivy response |
