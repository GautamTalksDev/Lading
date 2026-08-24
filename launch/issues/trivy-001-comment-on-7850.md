# Comment draft — post on Trivy discussion #7850

**Post at:** https://github.com/aquasecurity/trivy/discussions/7850#discussioncomment-NEW  
**Do not** open a new issue — this thread already covers the mechanism.  
**Status:** Draft — paste after review · Repro verified 2026-08-24 (`trivy` 0.72.0, `syft` 1.51.0)

---

## Comment text (paste below the line)

---

Following up on [DmitriyLewen's answer in this thread](https://github.com/aquasecurity/trivy/discussions/7850) (Nov 2024): Trivy reads `aquasecurity:trivy:SrcName` / `SrcVersion` from CycloneDX properties; Syft records the source package in the PURL `upstream=` qualifier (and in `syft:metadata:source`); when the Trivy property is absent, Trivy falls back to the binary package name and distro advisories keyed on source packages can be missed.

**This is not a new bug report.** We measured the **effect size** of that gap on Debian-based images with current releases, plus a causal intervention and a Grype control. Sharing in case it helps prioritize ingest-path work.

### Environment

| Component | Version |
|-----------|---------|
| trivy | 0.72.0 |
| trivy DB | v2, updated 2026-08-24 |
| syft | 1.51.0 (also reproduced on 1.22.0) |

### Reproduction (nginx:1.25)

Obtain a docker-archive tar (`docker pull nginx:1.25 && docker save …`, or any equivalent saved tar). Verified 2026-08-24 without a live daemon using a pre-saved `image.tar`.

```bash
syft scan docker-archive:nginx.tar -o cyclonedx-json=nginx.cdx.json

# Baseline: Syft CycloneDX → trivy sbom
trivy sbom nginx.cdx.json --format json \
  | jq -r '[.Results[]?.Vulnerabilities[]?.VulnerabilityID]|unique|length'
# observed: 137

# Same artifact, direct scan
trivy image --input nginx.tar --format json \
  | jq -r '[.Results[]?.Vulnerabilities[]?.VulnerabilityID]|unique|length'
# observed: 409

# Syft already wrote source — e.g. syft:metadata:source=expat and upstream= on pkg:deb/...
# trivy sbom still reports SrcName=libexpat1 (binary name).

# Intervention: copy syft:metadata:source → aquasecurity:trivy:SrcName
jq '.components |= map(if .properties then . + {properties: (.properties + [
      {name:"aquasecurity:trivy:SrcName",
       value:((.properties[]?|select(.name=="syft:metadata:source")|.value) // .name)},
      {name:"aquasecurity:trivy:SrcVersion", value:.version}])} else . end)' \
  nginx.cdx.json > nginx-src.cdx.json

trivy sbom nginx-src.cdx.json --format json \
  | jq -r '[.Results[]?.Vulnerabilities[]?.VulnerabilityID]|unique|length'
# observed: 415
```

No SBOM field was missing; copying into the property name Trivy already reads restores counts on the same document.

### Effect size — 22 public images

Syft CycloneDX → `trivy sbom`, before and after `SrcName` injection from `syft:metadata:source`. **14/22** Debian-based images show material under-count.

| Image | `trivy sbom` (default) | after `SrcName` injection | hidden | % hidden |
|-------|----------------------:|--------------------------:|-------:|---------:|
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

**Control group (unchanged by injection):** alpine:3.20, busybox:latest, fedora:40, rockylinux:9, amazonlinux:2023, ubi9-minimal, grafana:11, traefik:v3 — effect aligns with Debian source-package advisories, not a blanket SBOM under-count.

**False clean bill:** `golang:1.22-bookworm` reports **0** unique vulnerabilities on the Syft CycloneDX SBOM path and **19** on `trivy image` for the same tar (injection restores **19**).

### Categorical check — packages where `SrcName ≠ Name`

On `trivy image`, Debian images recover a distinct source name for most packages. On `trivy sbom` without injection, **zero** packages do:

| Image | SBOM path (`SrcName ≠ Name`) | Direct path |
|-------|-----------------------------:|------------:|
| nginx:1.25 | **0 / 149** | 114 / 149 |
| httpd:2.4 | **0 / 112** | 85 / 112 |
| debian:bookworm-slim | **0 / 88** | 62 / 88 |

### Grype control

Scanning the **same** Syft CycloneDX SBOM with Grype retains upstream attribution and does not show this loss (`syft CDX→grype` unique-vuln counts match `grype image` on our deb images). The gap is specific to Trivy's SBOM ingest path, not absent data in the Syft document.

### Question for maintainers

Would it be in scope for the SBOM ingest path to populate `SrcName`/`SrcVersion` from fields Syft already writes — e.g. `syft:metadata:source` and/or PURL `upstream=` on `pkg:deb` components — rather than requiring a manual preprocessing step? Alternatives we would also find useful: documented preprocessing requirements, or a loud warning when `pkg:deb` components cannot recover a source package name.

We are not asserting which vulnerability count is "correct" for triage (`no-dsa`, `unimportant`, etc.) — only that the two Trivy paths disagree silently and the data to reconcile them is already in the SBOM.

**Separate failure mode:** Syft **SPDX-JSON** through `trivy sbom` shows near-total package loss on the same images (nginx: ~151 SBOM packages → 1 retained, 0 vulns). That is a different ingest path; we are filing it as a new issue, not part of this thread.

Happy to retest on other Trivy versions or attach SBOM fixtures.

— Gautam Khosla

---

## Post-flight

- [ ] Post URL logged in `launch/vendor-notifications/LOG.md`
- [ ] Do **not** open `issues/new` with this text
- [ ] Retire or rename `trivy-001-cyclonedx-debian-srcname.md` if it still reads as a new issue
