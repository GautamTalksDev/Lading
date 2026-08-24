# LADING

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/GautamTalksDev/Lading/badge)](https://scorecard.dev/viewer/?uri=github.com/GautamTalksDev/Lading)

**Deterministic compliance evidence for binary vulnerability triage.**

You do not need to trust the maintainer. [`lading verify`](VERIFY.md) re-derives every
historical claim **offline** from a content-addressed evidence bundle — no network, no
installed Manifest tree required. If maintenance stops, past bundles remain checkable.
See [SUCCESSION.md](SUCCESSION.md).

LADING produces **evidence**, not legal conclusions. The manufacturer remains solely
responsible for statements in their CRA technical file. [DISCLAIMER.md](DISCLAIMER.md)

Scanner-reported CVEs against SBOMs still need justified triage for customer
questionnaires and VEX filings. LADING turns binary facts + manifest knowledge into
re-derivable bundles — or an explicit refusal when evidence is insufficient.

---

## What LADING cannot do

Read this first.

- **Not legal advice.** Evidence for your technical file only. [DISCLAIMER.md](DISCLAIMER.md)
- **Not a scanner.** It does not find CVEs; it triages findings you already have.
- **Not a universal clearance machine.** Insufficient evidence → **refused**, not a guess.
- **Never emits prove-a-negative VEX justifications:**
  - `vulnerable_code_not_in_execute_path`
  - `vulnerable_code_cannot_be_controlled_by_adversary`
  - `inline_mitigations_already_exist`
- **Cannot see through stripped static binaries**, unreviewed manifest gaps, or SBOM
  identity mistakes. See [docs/LIMITS.md](docs/LIMITS.md).

If you need every scanner CVE marked “not affected,” use a different tool.

---

## The problem

Your scanner reports **400 CVEs** against an SBOM. Maybe **390 are irrelevant** to the
binary you actually ship — but **someone must justify each one** for CRA, customer
questionnaires, and VEX filings. Spreadsheet triage does not scale; hand-wavy VEX
invites audit failure.

LADING turns **binary facts + curated manifest knowledge + scanner findings** into
**re-derivable evidence bundles** and standard VEX documents — or an explicit refusal.

---

## What LADING proves (exactly two justifications)

When LADING clears a CVE (`NOT_AFFECTED`), it emits **only**:

| Justification | Meaning |
|---------------|---------|
| `component_not_present` | SBOM names a component; scanned binaries do not match manifest identity |
| `vulnerable_code_not_present` | Manifest ties the CVE to upstream symbols; those symbols are not in your binaries |

Each clearance includes a **content-addressed evidence bundle** and optional OpenVEX /
CycloneDX / CSAF output with digest-pinned product identity.

Positive finding: `AFFECTED` when a manifest-listed vulnerable symbol is observed.

Details: [docs/EVIDENCE.md](docs/EVIDENCE.md) · [SPEC-EVIDENCE.md](SPEC-EVIDENCE.md)

---

## What LADING refuses to prove (and why)

When evidence is insufficient, verdict = **`UNDER_INVESTIGATION`** (shown as **Refused**
in scan output). Common reasons:

| Reason | Why |
|--------|-----|
| No manifest entry | No reviewed symbol↔CVE mapping to check |
| Probable-only symbols | Automation output cannot drive clearance |
| Stripped static binary | Symbols needed for proof are not observable |
| Weak / unverified PURL match | Prevents false clears on vendored or renamed builds |

LADING **will not** substitute the three forbidden prove-a-negative justifications above.
That is intentional: those claims cannot be established from deterministic inventory alone.

More: [docs/LIMITS.md](docs/LIMITS.md)

---

## Current manifest coverage

<!-- Regenerate: lading manifest coverage && bash scripts/update-readme-coverage.sh -->

**Manifest version:** `0.2.0+a1b2d83ed93321d5a416c884996aebf869878d33234dbf57c3f0012e41e79040`

| Component | Ecosystem | Definitive CVEs | Probable-only | None |
|-----------|-----------|-----------------|---------------|------|
| busybox | native | 1 | 0 | 0 |
| bzip2 | native | 1 | 0 | 0 |
| c-ares | native | 1 | 0 | 0 |
| curl | native | 1 | 0 | 0 |
| freetype | native | 1 | 0 | 0 |
| gnutls | native | 1 | 0 | 0 |
| krb5 | native | 1 | 0 | 0 |
| libarchive | native | 1 | 0 | 0 |
| libexpat | native | 1 | 0 | 0 |
| libgcrypt | native | 1 | 0 | 0 |
| libjpeg-turbo | native | 1 | 0 | 0 |
| libpng | native | 1 | 0 | 0 |
| libssh2 | native | 1 | 0 | 0 |
| libtasn1 | native | 1 | 0 | 0 |
| libuv | native | 1 | 0 | 0 |
| libwebp | native | 1 | 0 | 0 |
| libxml2 | native | 1 | 0 | 0 |
| libxslt | native | 1 | 0 | 0 |
| mbedtls | native | 1 | 0 | 0 |
| nghttp2 | native | 1 | 0 | 0 |
| openssh | native | 1 | 0 | 0 |
| openssl | native | 1 | 0 | 0 |
| pcre2 | native | 1 | 0 | 0 |
| sqlite3 | native | 1 | 0 | 0 |
| zlib | native | 1 | 0 | 0 |
| zlib (candidate) | native | 0 | 1 | 0 |

Full detail: [`manifest/COVERAGE.md`](manifest/COVERAGE.md) · Contribute: [docs/MANIFEST.md](docs/MANIFEST.md)

---

## 60-second quickstart

### Install

```bash
# Homebrew (tap)
brew install gautamtalksdev/tap/lading

# Scoop (Windows)
scoop bucket add lading https://github.com/gautamtalksdev/scoop-lading
scoop install lading

# Debian/Ubuntu (.deb from GitHub Releases)
sudo dpkg -i lading_*_linux_amd64.deb

# Or build from source (Go 1.23+)
go install github.com/gautamtalksdev/lading/cmd/lading@latest
```

### Scan

```bash
lading scan ./my-app/ \
  --findings grype.json \
  --out ./lading-out
```

### Explain (for compliance reviewers)

```bash
lading explain CVE-2023-0286 --bundle ./lading-out/evidence-bundle
```

### Verify (without trusting the operator)

```bash
lading verify ./my-app/ ./lading-out/vex.openvex.json ./lading-out/evidence-bundle
```

---

## Verification: check our claims without trusting us

1. **`lading verify`** — air-gapped re-derivation from artifact + VEX + bundle (no `manifest/` tree, no network). [VERIFY.md](VERIFY.md)
2. **`lading explain <cve>`** — human-readable rule, symbols, manifest provenance URLs
3. **Bundle tamper detection** — any edit breaks `MANIFEST.sha` / `BUNDLE.id`
4. **Optional cosign** — `lading sign` on VEX files after review (never automatic)
5. **Forbidden-string kill test** — CI greps for prove-a-negative justifications in source

CRA mapping (factual, not legal advice): [docs/CRA.md](docs/CRA.md)

---

## Kill tests

| ID | Gate | Status |
|----|------|--------|
| KT-1 | <30% decided coverage on 5 real artifacts → project stops | NOT EVALUABLE |
| KT-2 | One wrong `not_affected` in 100 hand-verified cases → unsound | PASS (synthetic fixtures only) |
| KT-3 | No inbound commercial interest by month 8 → no business | |
| CP-14 | 3 unprompted inbound → revenue gate opens ([launch/revenue/CP-14-GATE.md](launch/revenue/CP-14-GATE.md)); product build waits for 2× paid same ask | |

---

## Documentation

| Doc | Audience |
|-----|----------|
| [docs/EVIDENCE.md](docs/EVIDENCE.md) | Rules, verdicts, bundles |
| [docs/MANIFEST.md](docs/MANIFEST.md) | Contributing manifest entries |
| [docs/LIMITS.md](docs/LIMITS.md) | Coverage boundaries (read before filing) |
| [docs/CRA.md](docs/CRA.md) | CRA Annex I artifact mapping |
| [docs/LICENSES.md](docs/LICENSES.md) | Code, corpus, Manifest, spec licenses |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Schedule, cost, repo hardening |
| [docs/RESEARCH.md](docs/RESEARCH.md) | Spec, standards, paper, disclosure tracks |
| [docs/DISTRIBUTION.md](docs/DISTRIBUTION.md) | Findings-first outreach sequencing |
| [SUCCESSION.md](SUCCESSION.md) | Maintainer succession (verifiability) |
| [VERIFY.md](VERIFY.md) | Auditor verification guide |

---

## License

Apache-2.0 · [LICENSE](LICENSE) · DCO required · [CONTRIBUTING.md](CONTRIBUTING.md)
