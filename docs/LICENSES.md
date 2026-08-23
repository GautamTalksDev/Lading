# Licensing

| Artifact | License | Why |
|----------|---------|-----|
| **Go source, CLI, tests** | [Apache-2.0](../LICENSE) | Patent grant matters for binary triage adopters; see [DISCLAIMER.md](../DISCLAIMER.md) |
| **SPEC-EVIDENCE.md** | [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/) | Adoptable spec — implement without reading our Go |
| **Corpus metadata + results** | [CC-BY-4.0](../corpus/DATA-LICENSE.md) | Attribution required |
| **Public Manifest** | [CC0-1.0](../manifest/LICENSE) | Maximally free for other tools to consume |
| **Contributions** | Apache-2.0 + [DCO](../CONTRIBUTING.md) | `Signed-off-by` on every commit |

Third-party firmware in `corpus/downloads/` remains under upstream licenses (see
`corpus/ARTIFACTS.yaml`).

## Apache 2.0 patent grant

Section 3 of the Apache License grants implementers a patent license on contributions.
This project does **not** implement Binarly-style binary reachability analysis, but
legal review of adjacent binary decision tooling still happens. Apache 2.0 is
deliberate: it is the difference between a spec lawyers block and one they can adopt.

## Relicensing

The [Developer Certificate of Origin](../CONTRIBUTING.md) keeps a clear rights chain
for future hosted tiers. Do not accept drive-by commits without `Signed-off-by`.

## Free forever

Nothing in the CP-12 feature set moves behind a paywall. See
[launch/revenue/FREE-FOREVER-BOUNDARY.md](../launch/revenue/FREE-FOREVER-BOUNDARY.md).
