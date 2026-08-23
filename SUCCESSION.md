# Succession plan

If the primary maintainer is unavailable, the project continues without trusting
any single person:

1. **Code & releases** — Apache-2.0 source on GitHub; tagged releases with cosign
   signatures, `SHA256SUMS`, and SLSA provenance (see `.github/workflows/release.yml`).
   Any contributor can fork and ship patches.

2. **Historical claims** — `lading verify` re-derives verdicts from evidence bundles
   offline. Past bundles do not require the Manifest tree or this repository to stay
   online.

3. **Manifest** — Public entries are **CC0** (`manifest/LICENSE`). A fork or foundation
   can continue `manifest/components/` review under the same contribution rules
   (CODEOWNERS + `manifest-reviewed` label). Signing keys for release artifacts rotate
   through GitHub Actions; cosign keyless attestations remain verifiable from Sigstore
   logs.

4. **Signing keys** — Release signing uses GitHub OIDC / cosign keyless on tag push.
   Maintainer-held keys (if any for manual `lading sign` demos) are documented in a
   private runbook, not in git. Successor: revoke old keys, publish new cosign identity
   in README release section.

5. **Contact** — Open a public GitHub Discussion titled “Maintainer succession” or
   email the security contact in [SECURITY.md](../SECURITY.md) if the repo is
   compromised or abandoned.

This paragraph exists because 2026 procurement guidance flags single-maintainer risk.
The engineering answer is **verifiability**, not headcount.
