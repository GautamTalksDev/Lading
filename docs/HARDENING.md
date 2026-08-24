# Repository hardening

Security posture for [GautamTalksDev/Lading](https://github.com/GautamTalksDev/Lading).
This document lists **repository controls** and whether each is enabled as of the
last audit. It is written for security reviewers and procurement; it does not
claim controls that could not be verified.

**Last audited:** 2026-08-24 (local repo + public GitHub API; no maintainer session)

---

## Account controls (GitHub user / org)

These are configured in **GitHub → Settings → Password and authentication**
and **Organizations** (if applicable). They cannot be verified from the repo alone.

| Control | Status | Enabled on | Notes |
|---------|--------|------------|-------|
| Two-factor authentication (2FA) | ☐ Not verified | — | Required for all maintainers; confirm in account settings. |
| 2FA with hardware security key | ☐ Not verified | — | Manual step per [docs/OPERATIONS.md](OPERATIONS.md) checklist. |

---

## Repository controls (GitHub → Settings → Code and security / Branches)

| Control | Status | Enabled on | Notes |
|---------|--------|------------|-------|
| Branch protection on `main` (no force-push) | ☐ Not verified | — | Public API returned 401 for branch protection; confirm in **Settings → Branches**. |
| Branch protection: require status checks (CI) | ☐ Not verified | — | Should require **CI** (and other required workflows) before merge. |
| Branch protection: prevent branch deletion | ☐ Not verified | — | Enable with protection rules on `main`. |
| Secret scanning | ☐ Not verified | — | **Settings → Code security → Secret scanning**. Not visible without maintainer auth. |
| Secret scanning push protection | ☐ Not verified | — | Blocks commits that contain known secret patterns. |
| Dependabot alerts | ☐ Not verified | — | **Settings → Code security → Dependabot**. Alerts UI requires maintainer auth. |
| Dependabot version updates (`dependabot.yml`) | ☑ Configured | 2026-08-23 | [`.github/dependabot.yml`](../.github/dependabot.yml) — weekly `gomod` + `github-actions`; `Dependabot Updates` workflow is **active**. |
| Dependabot **alerts** (vulnerability notifications) | ☐ Not verified | — | Separate toggle in **Settings → Code security**; not visible without maintainer auth. |
| Dependency graph | ☑ Enabled | 2026-08-23 | `Dependency Graph` workflow present and active on the repository. |
| CodeQL code scanning | ☑ Enabled | 2026-08-23 | `CodeQL` workflow active; latest run **success** (2026-08-23). |
| OpenSSF Scorecard (GitHub Action) | ☑ Configured | 2026-08-23 | [`.github/workflows/scorecard.yml`](../.github/workflows/scorecard.yml); `publish_results: true`. Runs on 2026-08-23 **failed** (workflow-level write permissions rejected by Scorecard API). **Fix applied locally 2026-08-24** (job-level permissions); not yet on `main` — push required to re-run. |
| OpenSSF Scorecard (public badge) | ☐ Pending first successful publish | — | Badge in [README.md](../README.md); [api.scorecard.dev](https://api.scorecard.dev/projects/github.com/GautamTalksDev/Lading) returns no score until a successful publish. |

---

## CI and supply-chain workflows (in-repo, verifiable)

| Workflow | File | Purpose |
|----------|------|---------|
| CI | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) | Tests, lint, forbidden-string kill test |
| DCO | [`.github/workflows/dco.yml`](../.github/workflows/dco.yml) | Signed-off-by on commits |
| Manifest Validate | [`.github/workflows/manifest-validate.yml`](../.github/workflows/manifest-validate.yml) | Manifest schema gate |
| Release | [`.github/workflows/release.yml`](../.github/workflows/release.yml) | Signed releases (cosign, SHA256SUMS, SLSA) |
| OpenSSF Scorecard | [`.github/workflows/scorecard.yml`](../.github/workflows/scorecard.yml) | Supply-chain posture scan + badge publish |

---

## Maintainer checklist (from OPERATIONS.md)

Copy of [docs/OPERATIONS.md — Repo hardening checklist](OPERATIONS.md#repo-hardening-checklist). Update this table when each item is confirmed in GitHub Settings.

- [ ] Maintainer 2FA + hardware key on GitHub
- [ ] Protected `main`, no force-push
- [ ] Secret scanning + push protection enabled
- [ ] Dependabot alerts enabled
- [ ] OpenSSF Scorecard workflow green (badge in README when ready)
- [ ] Releases: cosign keyless + SHA256SUMS + SLSA provenance
- [ ] Minimal dependencies — `debug/elf` is stdlib; justify every `go.mod` entry

---

## How to refresh this document

After changing GitHub Settings:

1. Note the **date** each control was turned on.
2. Change ☐ to ☑ only for controls you confirmed in the GitHub UI or via `gh api` with an authenticated maintainer token.
3. Re-run OpenSSF Scorecard (push to `main` or **Actions → OpenSSF Scorecard → Run workflow**) and confirm the [README badge](../README.md) shows a numeric score.

```bash
# Maintainer-only examples (requires gh auth login)
gh api repos/GautamTalksDev/Lading/branches/main/protection
gh api repos/GautamTalksDev/Lading/dependabot/alerts --jq '.[0].state' 2>/dev/null | head -1
curl -sS "https://api.scorecard.dev/projects/github.com/GautamTalksDev/Lading" | jq .
```

---

## Evidence for buyers

- **Deterministic evidence model:** [SPEC-EVIDENCE.md](../SPEC-EVIDENCE.md), [VERIFY.md](../VERIFY.md)
- **Kill-test transparency:** [RESULTS.md](../RESULTS.md) (KT-1 NOT EVALUABLE; launch frozen — [launch/DO-NOT-PUBLISH.md](../launch/DO-NOT-PUBLISH.md))
- **Security policy:** [SECURITY.md](../SECURITY.md)
- **Succession / verifiability:** [SUCCESSION.md](../SUCCESSION.md)
