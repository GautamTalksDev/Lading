# Candidate Manifest entries (probable only). Never loaded as definitive.

**Contributors:** `lading manifest propose <component> <cve>` → open PR with
`.github/PULL_REQUEST_TEMPLATE/manifest_entry.md`. CI runs `scripts/manifest-pr-gate.sh`.

**Maintainers:** `lading manifest promote <file> --reviewed-by ... --reviewed-at YYYY-MM-DD`
(add `manifest-reviewed` label before merging any PR that adds definitive under
`manifest/components/`).

Example golden-path candidate: `native/zlib-cve-2018-25032.yaml`.
