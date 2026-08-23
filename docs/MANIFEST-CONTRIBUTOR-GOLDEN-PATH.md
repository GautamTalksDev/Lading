# Manifest contributor golden path (CP-13)

This documents the **only** supported extension point: contributors add DATA under
`manifest/candidates/`. No plugin API. No Go changes for new CVE knowledge.

## End-to-end example (rehearsal)

The repo includes a completed contributor proposal for **zlib / CVE-2018-25032**:

| Step | Artifact |
|------|----------|
| 1. Scaffold | `lading manifest propose zlib CVE-2018-25032 ...` |
| 2. Candidate YAML | `manifest/candidates/native/zlib-cve-2018-25032.yaml` |
| 3. Build recipe | `testdata/manifest-fixtures/BUILD-zlib-1.2.11.md` |
| 4. PR template | `.github/PULL_REQUEST_TEMPLATE/manifest_entry.md` |
| 5. CI gate | `bash scripts/manifest-pr-gate.sh` |

Coverage reflects the open candidate as **zlib (candidate)** with probable=1 until
a maintainer promotes.

## Maintainer finish (definitive)

Only `lading manifest promote` may write `confidence: definitive`. CI blocks PRs
that add definitive under `manifest/components/` without the **`manifest-reviewed`**
label.

```bash
lading manifest promote manifest/candidates/native/zlib-cve-2018-25032.yaml \
  --reviewed-by gautamtalksdev --reviewed-at 2026-08-23
lading manifest coverage
bash scripts/update-readme-coverage.sh
```

## Tracking first outside contributor

When the first **external** GitHub PR merges a candidate (not this rehearsal file),
record the PR URL in the monthly coverage post
([MANIFEST-COVERAGE-MONTHLY.md](MANIFEST-COVERAGE-MONTHLY.md)) under **Merged this
month**.

Definition of Done for launch: one such PR merged and promoted to definitive.
