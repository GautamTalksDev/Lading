# Operations — schedule, cost, maintenance

At **10–15 hrs/week**, fourteen weeks to CP-12 launch (not “2–3 months of building”).
Manifest curation is **~2 hrs/week** ongoing after launch — budget explicitly.

| Weeks | Checkpoints | Output |
|-------|-------------|--------|
| 1 | CP-0, CP-1 | Repo, kill tests, CI + signed releases (3 OS) |
| 2–3 | CP-2, CP-3 | Symbol inventory, PURL canonicalization, `lading audit-vex` |
| 3–4 | CP-4 | Manifest schema, loader, spec, seed entries |
| 4–6 | CP-5, CP-6 | Derivation, decision engine, SPEC-EVIDENCE, fixtures |
| 6–7 | CP-7, CP-8 | Evidence bundles, `lading verify`, VEX emitters |
| 7–8 | CP-9, CP-10 | `lading scan`, unpacking, docs, packaging, `lading explain` |
| 9–13 | CP-11 | 40-artifact corpus, top-25 Manifest, ground truth, RESULTS.md |
| 13 | CP-12 | Launch (problem-first posts) |
| 14+ | CP-13, CP-14 | Manifest flywheel; revenue **only if inbound** |

## Monthly cost (typical)

| Item | Monthly | Note |
|------|---------|------|
| Domain | ~$1.50 | lading.dev amortised |
| Static site + CDN | $0 | Cloudflare Pages |
| CI | $0 | Public repo |
| Corpus storage | $0 → ~$5 | R2 after free tier |
| Manifest derivation | $0 | Local git clones |
| Inference | $0 | None by design |
| **Total** | **$2–8** | Under $25 ceiling |
| Entity + insurance | $0 until revenue | ~$1–2k/yr when CP-14 opens |

## Maintenance drag

~**2–4 hrs/week** permanent + **~2 hrs/week** Manifest curation. This is the
fourth maintained project — archive or hand off one of the prior three before CP-12
(per master plan).

## Kill conditions

Evaluated at CP-11; do not move goalposts. See README **Kill tests** (KT-1, KT-2,
KT-3) and [RESULTS.md](../RESULTS.md).

## Repo hardening checklist

- [ ] Maintainer 2FA + hardware key on GitHub
- [ ] Protected `main`, no force-push
- [ ] Secret scanning + dependency review enabled
- [ ] OpenSSF Scorecard workflow green (badge in README when ready)
- [ ] Releases: cosign keyless + SHA256SUMS + SLSA provenance (`.github/workflows/release.yml`)
- [ ] Minimal dependencies — `debug/elf` is stdlib; justify every `go.mod` entry

## Succession

[SUCCESSION.md](../SUCCESSION.md) — verifiability instead of trust.
