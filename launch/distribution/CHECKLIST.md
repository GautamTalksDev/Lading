# Distribution checklist (step 6)

Complete before Hacker News. Track dates in this file.

## Packaging (repo ready)

- [x] Homebrew tap — `packaging/homebrew-tap/Formula/lading.rb`
- [x] Scoop bucket — `packaging/scoop-bucket/bucket/lading.json`
- [x] `.deb` via GoReleaser — `.goreleaser.yaml` (`nfpms`)
- [x] GitHub Action — `action/action.yml` + `.github/workflows/lading-action-smoke.yml`
- [ ] **Tag release** `v0.2.0` (or first public tag) — triggers GoReleaser
- [ ] Upload corpus tarball `corpus/results/aggregate.json` + ground truth as release asset

## Registries / lists

- [ ] Homebrew tap public push to `gautamtalksdev/homebrew-tap`
- [ ] Scoop bucket PR to community bucket OR host manifest URL
- [ ] GitHub Marketplace — publish `action/action.yml` from tagged release
- [ ] PR: [cyclonedx/awesome-cyclonedx](https://github.com/CycloneDX/awesome-cyclonedx) — VEX audit + evidence bundles
- [ ] PR: awesome-sbom / awesome-cra (find canonical repos; one paragraph + link)
- [ ] OpenSSF Scorecard — enable on repo; badge in README after first green run

## Integrations (issues, not code in this phase)

- [ ] Dependency-Track — `issues/dependency-track.md`
- [ ] OSS Review Toolkit — `issues/ort-advisor.md`

## Site

- [ ] Post 1 on gautamkhosla.com (after vendor notice +14d)
- [ ] Post 2 one week later
- [ ] Link CC-BY dataset + CC0 manifest from post footers

## Hacker News (step 7 — last)

- [ ] Tuesday 9–11am US Eastern
- [ ] Use `hn-draft.md` title (finding, not product)
- [ ] Comment with reproduction only; no “we launched” language
