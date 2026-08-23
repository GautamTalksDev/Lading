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
