# Monthly Manifest coverage post (template)

Publish on the first Monday of each month (blog, Mastodon, or project
updates). **Coverage going up** is the success metric.

## Title

`Lading Manifest coverage — {MONTH} {YEAR}`

## Regenerate numbers

```bash
lading manifest coverage
bash scripts/update-readme-coverage.sh
```

Copy from `manifest/COVERAGE.md`:

- Manifest version line
- Summary table (components × definitive / probable / none)
- Total definitive CVE count vs prior month

## Post skeleton

```markdown
### Manifest coverage — {MONTH} {YEAR}

Manifest version: `{VERSION}`

| Metric | This month | Last month | Δ |
|--------|------------|------------|---|
| Components with ≥1 definitive CVE | | | |
| Total definitive CVE entries | | | |
| Open probable candidates | | | |

**Merged this month** (link PRs):
- …

**Still needed** (high SBOM noise, no manifest entry yet):
- …

Contributors: `lading manifest propose <component> <cve>` — DATA only, no Go changes.
Template: `.github/PULL_REQUEST_TEMPLATE/manifest_entry.md`
```

## Archive

Save each published post under `docs/manifest/coverage-posts/YYYY-MM.md` after
publishing (optional but keeps history for month-over-month Δ).
