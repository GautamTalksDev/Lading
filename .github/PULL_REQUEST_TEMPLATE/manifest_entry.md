---
name: Manifest entry (DATA only)
about: Propose a probable candidate CVE entry under manifest/candidates/
title: "manifest: <component> <CVE-ID>"
labels:
  - manifest-contribution
---

## Manifest entry proposal

Contributors add **DATA only** under `manifest/candidates/`. Never edit
`manifest/components/` or set `confidence: definitive` in a PR.

Scaffold locally:

```bash
lading manifest propose <component> <CVE-ID> \
  --fix-commit https://github.com/org/repo/commit/SHA \
  --symbol <vulnerable_fn> \
  --enclosing-function "<function from patch>" \
  --affected-version "1.2.3" \
  --verification "nm/objdump on fixture; symbol at ..." \
  --fixture testdata/manifest-fixtures/<component>-<version>.so \
  --github <your-handle>
```

### Upstream fix commit URL (required)

<!-- paste full https:// commit URL -->

### Enclosing / vulnerable functions (required)

<!-- list functions touched by the fix that enclose the vulnerability -->

### How you verified (required)

<!-- e.g. nm -D fixture.so | grep symbol; matched patch hunk at line N -->

### Test fixture binary OR documented build recipe (required)

<!-- path in repo, or link to BUILD.md with exact reproducible steps -->

### Candidate file

<!-- e.g. manifest/candidates/native/openssl-cve-2023-0286.yaml -->

---

## Maintainer checklist (do not fill as contributor)

- [ ] CI green (`manifest-pr-gate`)
- [ ] Provenance URL opens; patch matches listed functions
- [ ] Fixture/recipe reproduced locally
- [ ] `lading manifest promote ... --reviewed-by ... --reviewed-at ...`
- [ ] Label **`manifest-reviewed`** before merge if PR touches `manifest/components/`
- [ ] `lading manifest coverage && bash scripts/update-readme-coverage.sh`
