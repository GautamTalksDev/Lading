# ANALYSIS-node20 — Why 335 → 4007?

**Same mechanism as nginx:1.25 (Debian source-package attribution via restored `SrcName`); not an npm/`node_modules` effect.**

## Evidence

Script: `scripts/analyse-node20.sh`  
Artifact: `corpus/downloads/oci-node-20/image.tar` (`node:20`)  
Workdir: `.lading/node20-analysis/`  
Method: Syft CycloneDX → `trivy sbom` before/after injecting `aquasecurity:trivy:SrcName` from `syft:metadata:source` (same intervention as FINDING-001 §4). Unique `VulnerabilityID` counts.

### Unique VulnerabilityIDs

| | Count |
|---|---:|
| Before | 335 |
| After | 4007 |
| Newly surfaced (after ∖ before) | 3672 |

### PURL type → newly-surfaced VulnerabilityIDs

| PURL type | Newly-surfaced IDs |
|---|---:|
| deb | 3672 |
| npm | 0 |
| other | 0 |

Exclusive classification: **deb_only=3672**, npm_only=0, other_only=0, mixed=0.

### deb-only before/after

| | Unique VulnerabilityIDs on `pkg:deb/...` |
|---|---:|
| Before | 308 |
| After | 3980 |
| Delta | 3672 |

The entire 335→4007 jump is accounted for by deb findings. npm findings are unchanged: **27 unique IDs before, 27 after** (27 finding rows each).

### Package concentration (still deb)

Of the 3672 newly-surfaced IDs, **3319** appear on `linux-libc-dev` alone. Remaining new IDs concentrate on other Debian binaries whose source name differs from the binary name (`libpq-dev`/`libpq5`, `libexpat1`, `openssh-client`, `libc6`, …).

### SrcName recovery on the after path

| | Packages in Trivy report | `SrcName ≠ Name` |
|---|---:|---:|
| Before | 618 | 0 |
| After | 618 | 353 |

Syft SBOM component counts with `syft:metadata:source`: **357 / 413 deb**; **0 / 204 npm**. The injection only supplies a real source name where Syft already recorded one — i.e. Debian packages — which matches the vuln delta.

## Decision gate

**Same mechanism (deb-dominated) → keep node:20 as the headline.**

The npm/`node_modules` hypothesis is falsified by the PURL-type breakdown. Magnitude is large because restored Debian `SrcName` unlocks a large advisory set (dominated by `linux-libc-dev`), not because a second mechanism appears.
