# CP-S3: Why Signed-Releases scores 0

**Date:** 2026-08-25  
**Mode:** READ-ONLY investigation. This file is the only write. No release created, no workflow or `.goreleaser.yaml` change.  
**Question:** `cosign verify-blob` returns Verified OK for the `v0.0.1-test` signature asset, but OpenSSF Scorecard scores Signed-Releases **0**. Which side is wrong, and why?

---

## Verdict

Neither side is cryptographically wrong. Scorecard does **not** verify signatures. At the Scorecard binary that produced this score (`v5.0.0` / `ea7e27ed`), it only looks for asset names ending in a fixed suffix list that **does not include `.sigstore.json`**. The release ships `SHA256SUMS.sigstore.json`, which fails that suffix check even though cosign verifies it. Cosign is right that the blob is signed. Scorecard is right relative to its own filename heuristic at that commit. The 0 is a **naming mismatch**, not a missing signature, not a prerelease skip, and not a minimum-release-count rule.

---

## a. Releases and assets

Command:

```bash
curl -sS -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/GautamTalksDev/Lading/releases" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('count',len(d));
[print(r['tag_name'],'prerelease=',r['prerelease'],'assets=',[a['name'] for a in r['assets']]) for r in d]"
```

Output:

```text
count 1
v0.0.1-test prerelease= True assets= ['lading_0.0.1-test_darwin_amd64.tar.gz', 'lading_0.0.1-test_darwin_arm64.tar.gz', 'lading_0.0.1-test_linux_amd64.tar.gz', 'lading_0.0.1-test_linux_arm64.tar.gz', 'lading_0.0.1-test_windows_amd64.zip', 'SHA256SUMS', 'SHA256SUMS.sigstore.json']
```

Exact asset filenames on release id `375869765` (`https://github.com/GautamTalksDev/Lading/releases/tag/v0.0.1-test`):

| Filename | Notes |
|----------|-------|
| `lading_0.0.1-test_darwin_amd64.tar.gz` | binary archive |
| `lading_0.0.1-test_darwin_arm64.tar.gz` | binary archive |
| `lading_0.0.1-test_linux_amd64.tar.gz` | binary archive |
| `lading_0.0.1-test_linux_arm64.tar.gz` | binary archive |
| `lading_0.0.1-test_windows_amd64.zip` | binary archive |
| `SHA256SUMS` | checksum file |
| `SHA256SUMS.sigstore.json` | cosign keyless bundle for `SHA256SUMS` |

Only one release exists. It is marked `prerelease: true`.

---

## b. What Signed-Releases looks for

### Scorecard version that scored this repo

Command:

```bash
curl -sS "https://api.scorecard.dev/projects/github.com/GautamTalksDev/Lading" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['scorecard']);
c=[x for x in d['checks'] if x['name']=='Signed-Releases'][0]; print(json.dumps(c,indent=2))"
```

Output:

```text
{'version': 'v5.0.0', 'commit': 'ea7e27ed41b76ab879c862fa0ca4cc9c61764ee4'}
{
  "name": "Signed-Releases",
  "score": 0,
  "reason": "Project has not signed or included provenance with any releases.",
  "details": [
    "Warn: release artifact v0.0.1-test not signed: https://api.github.com/repos/GautamTalksDev/Lading/releases/375869765",
    "Warn: release artifact v0.0.1-test does not have provenance: https://api.github.com/repos/GautamTalksDev/Lading/releases/375869765"
  ],
  ...
}
```

### Documented patterns at that commit

Command:

```bash
curl -sS "https://raw.githubusercontent.com/ossf/scorecard/ea7e27ed41b76ab879c862fa0ca4cc9c61764ee4/docs/checks.md" \
  | sed -n '/## Signed-Releases/,/^## /p' | head -n 30
```

Relevant lines from that output:

```text
This check looks for the following filenames in the project's last five
release assets:
*.minisig, *.asc (pgp), *.sig, *.sign, *.sigstore, *.intoto.jsonl.

If a signature is found ... score of 8 ...
If a SLSA provenance file ... (*.intoto.jsonl), the maximum score of 10 ...

This check looks for the 30 most recent releases associated with an artifact.
It ignores the source code-only releases that are created automatically by GitHub.

Note: The check does not verify the signatures.
```

### Actual probe code at that commit

Command:

```bash
curl -sS "https://raw.githubusercontent.com/ossf/scorecard/ea7e27ed41b76ab879c862fa0ca4cc9c61764ee4/probes/releasesAreSigned/impl.go" \
  | grep signatureExtensions
```

Output:

```text
var signatureExtensions = []string{".asc", ".minisig", ".sig", ".sign", ".sigstore"}
```

Provenance probe at the same commit only accepts `.intoto.jsonl`:

```bash
curl -sS "https://raw.githubusercontent.com/ossf/scorecard/ea7e27ed41b76ab879c862fa0ca4cc9c61764ee4/probes/releasesHaveProvenance/impl.go" \
  | grep provenanceExtensions
```

(Observed earlier this session: `var provenanceExtensions = []string{".intoto.jsonl"}`.)

Lookback is **5** releases with assets (`releaseLookBack = 5`). There is **no** special-case skip for GitHub `prerelease: true` in the Signed-Releases probe/evaluation sources at `ea7e27ed` (grep for `prerelease` / `PreRelease` / `draft` returned no matches). Scorecard’s own warn lines name `v0.0.1-test`, so the prerelease was evaluated, not skipped.

### Later Scorecard main (not what scored us)

Command:

```bash
curl -sS "https://raw.githubusercontent.com/ossf/scorecard/main/probes/releasesAreSigned/impl.go" \
  | grep signatureExtensions
```

Output:

```text
var signatureExtensions = []string{".asc", ".minisig", ".sig", ".sign", ".sigstore", ".sigstore.json"}
```

`.sigstore.json` was added on main in commit `dff50e97a6fa` (2025-07-29, PR #4728: “Update Signed-Releases to support .sigstore.json signatures”). That is **after** `v5.0.0` / `ea7e27ed`.

---

## c. Which explanation accounts for the 0

| Hypothesis | Ruled in / out | Evidence |
|------------|----------------|----------|
| Only release is a prerelease and is skipped | **Out** | Scorecard warn names `v0.0.1-test`; `prerelease` string absent from Signed-Releases probe code at `ea7e27ed`. |
| Signature file naming does not match expected pattern | **In** | Asset is `SHA256SUMS.sigstore.json`. At `ea7e27ed`, suffixes are `.asc/.minisig/.sig/.sign/.sigstore`. `SHA256SUMS.sigstore.json`.endswith(`.sigstore`) is **False**. |
| Check requires a minimum number of releases | **Out** | Evaluation scores over the releases it finds; one signed release would score 8. Zero true outcomes → min score with the observed reason string. |
| Something else (crypto invalid) | **Out for the signature claim** | cosign verifies the bundle (below). Scorecard docs: “does not verify the signatures.” |
| Provenance also fails | **Separate, also true** | No asset ends with `.intoto.jsonl`. Release workflow uses `actions/attest-build-provenance` against `dist/SHA256SUMS`, which does not attach a `.intoto.jsonl` release asset. That alone would block a 10, but the **signed** half is already False for naming. |

### Suffix simulation (this session)

```text
asset: SHA256SUMS.sigstore.json
  endswith('.asc') = False
  endswith('.minisig') = False
  endswith('.sig') = False
  endswith('.sign') = False
  endswith('.sigstore') = False
main also has .sigstore.json: True
```

### Cosign is not lying

```bash
cd /tmp/cps3-assets   # assets downloaded from the release
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp 'https://github.com/GautamTalksDev/Lading/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS
```

Output:

```text
Verified OK
```

Bundle shape (this session): JSON keys `base64Signature`, `cert`, `rekorBundle` — produced by GoReleaser’s cosign sign-blob path:

```yaml
# .goreleaser.yaml (read-only citation)
signs:
  - cmd: cosign
    signature: "${artifact}.sigstore.json"
    ...
    artifacts: checksum
```

So the repository intentionally emits `SHA256SUMS.sigstore.json`, which is a valid cosign bundle and a known Scorecard blind spot on `v5.0.0`.

---

## d. Fixable how? (no action taken)

**Not structural for “one test tag.”** A single release is enough for a non-zero Signed-Releases score if Scorecard recognises a signature asset. Being a prerelease did not cause the skip.

**Fixable by naming / packaging choices** (decision deferred; not done here), for example:

1. Emit or also attach a signature asset whose name ends in one of the `v5.0.0` suffixes (e.g. `.sigstore`), or
2. Wait for / upgrade to a Scorecard build that includes `.sigstore.json` (already on Scorecard `main` after #4728), then re-run, or
3. Separately, for the provenance half of the score (8→10), attach a `*.intoto.jsonl` release asset; GitHub attestations alone do not satisfy the filename probe.

A “real” non-prerelease tag by itself would **not** fix the 0 while the only signature asset remains `*.sigstore.json` under Scorecard `v5.0.0`.

**Stop here.** No release created to raise the score.

---

## Definition of done

```bash
git status --porcelain
# expected: only audit/CP-S3-NOTES.md
```
