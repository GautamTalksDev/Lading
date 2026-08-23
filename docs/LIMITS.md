# Coverage limits

LADING is honest about **where deterministic binary evidence stops**. These limits
are not bugs — they are the refusal surface that keeps false `not_affected`
statements out of your filing.

## Manifest coverage

The manifest is a ** curated knowledge base**, not a CVE database.

| State | Meaning | Scan behavior |
|-------|---------|---------------|
| **Definitive** | Human-reviewed symbols for the CVE | May clear via D02 if symbols absent |
| **Probable-only** | Automation-derived candidates | **Refused** (`manifest_probable_only`) |
| **No entry** | CVE/component not in manifest | **Refused** (`manifest_no_entry`) |

Current seed coverage (regenerated each release):

<!-- COVERAGE:BEGIN -->
See [`manifest/COVERAGE.md`](../manifest/COVERAGE.md) — run `lading manifest coverage` before release.
<!-- COVERAGE:END -->

If your scanner reports 400 CVEs and the manifest covers 3 components, expect a
large **refused** count. That is correct behavior.

## Stripped binaries

| Condition | Result |
|-----------|--------|
| Stripped + static-linked | **Refused** (`stripped_static_binary`) — symbols needed for D02 are not observable |
| Stripped + dynamic, insufficient `.dynsym` | **Refused** (`stripped_insufficient_dynsym`) |
| Unusable symbol tables | **Refused** (`symbol_table_unusable`) |

LADING records `stripped` and `static_linked` as authoritative facts in inventory.
It does not infer them downstream.

## Vendored and renamed components

When the SBOM PURL matches only at **name+version** but manifest identity signals
(symbols/strings) do not match any scanned binary:

- **Refused** (`identity_unverified`) — prevents silent false clears on vendored trees
- Weak PURL alone → **Refused** (`purl_match_insufficient`)

Digest-pinned PURLs in VEX output (`checksum=sha256:…`) reduce cross-artifact
mismatch; they do not fix wrong SBOM identity.

## Patched-in-place / hot-patched binaries

LADING compares **observed symbols** against **manifest-listed vulnerable symbols**
from upstream fix analysis. It does not:

- Diff your source tree
- Parse patch hunks in your private fork
- Know that you backported a fix without changing symbol names

If you ship a hot-patched binary where vulnerable symbols remain visible but are
safe by construction, LADING will not invent a justification. That triage is
outside deterministic evidence — expect **refused** or manual process.

## Scanner vs decided coverage

Scan report **coverage** = `(not_affected + affected) / cves_in`.

- High **refused** is normal on early manifest seeds
- Kill test KT-1: if real artifacts stay below 30% decided, the project stops

## Where to go next

- Add manifest entries: [MANIFEST.md](MANIFEST.md)
- Understand refusals: `lading explain <cve> --bundle …`
- Audit third-party VEX: `lading audit-vex`
