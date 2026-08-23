# Contributing manifest knowledge

The Lading Manifest is **data under `manifest/`**, not Go code. Full schema and
field reference: [SPEC-MANIFEST.md](../SPEC-MANIFEST.md).

## Before you add an entry

Ask:

1. **Which upstream symbol(s) prove the CVE?** Link the fix commit URL in
   `provenance.upstream_fix_commit`.
2. **Can you review it?** Automation writes `confidence: probable` to
   `manifest/candidates/` only. Production entries need human promote with
   `reviewed_by` and `reviewed_at`.
3. **Which PURLs match shipped artifacts?** Include checksum-pinned examples in
   review notes if identity is fragile (vendored/renamed builds).

## Workflow

### Contributors (DATA only — the only extension point)

```bash
# Scaffold probable candidate + local PR template (never writes definitive)
lading manifest propose zlib CVE-2018-25032 \
  --fix-commit https://github.com/madler/zlib/commit/21767c0dbc5b3b221bc1996d9a496d3aada545eb \
  --symbol deflate \
  --enclosing-function deflate --enclosing-function deflate_fast \
  --affected-version 1.2.11 \
  --verification "nm testdata/manifest-fixtures/zlib-1.2.11.so | grep deflate" \
  --build-recipe testdata/manifest-fixtures/BUILD-zlib-1.2.11.md \
  --github your-handle

# Open PR with template: .github/PULL_REQUEST_TEMPLATE/manifest_entry.md
# CI: bash scripts/manifest-pr-gate.sh
```

Maintainers promote after review (`manifest-reviewed` label required before any
PR adds `confidence: definitive` under `manifest/components/`).

### Maintainers (derive → promote)

```bash
# 1. Derive candidate symbols from upstream fix commits (Linux + CGO)
lading manifest derive --job job.yaml --out manifest/candidates/

# 2. Human review → promote to manifest/components/
lading manifest promote manifest/candidates/openssl-CVE-2023-0286.yaml \
  --reviewed-by you --reviewed-at 2026-08-23

# 3. Validate schema
bash scripts/manifest-pr-gate.sh

# 4. Regenerate coverage table (README + manifest/COVERAGE.md)
lading manifest coverage
bash scripts/update-readme-coverage.sh
```

Monthly coverage posts: [MANIFEST-COVERAGE-MONTHLY.md](MANIFEST-COVERAGE-MONTHLY.md).

## Entry checklist

- [ ] `cve` matches NVD/CVE canonical ID
- [ ] `vulnerable_symbols[].confidence: definitive` only after human review
- [ ] `provenance.upstream_fix_commit` is a real commit URL
- [ ] `provenance.derivation` is `patch-touched-function`, `advisory-named`, or `manual`
- [ ] `component.purls` cover the SBOM claims you expect in the field
- [ ] `identity_symbols` / `identity_strings` distinguish vendored renames where possible

## What not to submit

- Probable-only entries promoted without review
- Symbols guessed from advisory prose without patch linkage
- Entries whose only purpose is to inflate coverage percentages

Coverage limits: [LIMITS.md](LIMITS.md).
