# Independent verification guide

This guide is for an auditor who does **not** trust the operator. You need only:

- The `lading` binary (or `go run ./cmd/lading`)
- The shipped **artifact** (binary or directory)
- The **VEX JSON** (`vex.json`)
- The **evidence bundle** directory

You do **not** need the repository `manifest/` tree, network access, or any external API.

## Air-gapped guarantee

`lading verify` performs **zero network requests**. It reads local files only and
re-derives verdicts from:

1. Fresh SHA-256 hashes of the artifact and named binaries
2. A from-scratch inventory scan (`internal/inventory`)
3. The **manifest slice embedded in the bundle** (`manifest-slice.json`)

If your `manifest/` directory is deleted, renamed, or replaced, verification still
works as long as the bundle is intact.

Confirm the guarantee:

```bash
lading verify --help
# Documents: AIR-GAPPED GUARANTEE … ZERO network requests
```

Optional: run under a network namespace with egress blocked — verify should still exit 0 on a good bundle.

## Bundle layout

```
evidence-bundle/
  BUNDLE.id              # sha256 hex of MANIFEST.sha (content-addressed ID)
  MANIFEST.sha           # sha256 + relative path of every statement file
  statements/
    <id>/
      statement.json     # CVE, PURL, verdict, rule_id
      inputs.json        # artifact + per-binary hashes and flags
      observations.json  # exact symbols consulted
      manifest-slice.json
      versions.json
```

Tampering any file breaks `MANIFEST.sha` verification.

## Verify

```bash
lading verify /path/to/artifact /path/to/vex.json /path/to/evidence-bundle
```

Exit code **0** only when every statement reports `VERIFIED`.

Per-statement statuses:

| Status | Meaning |
|--------|---------|
| `VERIFIED` | Hashes OK, re-derived decision matches bundle and VEX |
| `MISMATCH` | Re-derivation OK but VEX disagrees (or bundle statement inconsistent) |
| `UNVERIFIABLE` | Tampered bundle/artifact, scan failure, or corrupt inputs |

## VEX format

Supported: `lading-vex-v1` (recommended for audits) and a subset of OpenVEX.

Example `lading-vex-v1`:

```json
{
  "format": "lading-vex-v1",
  "statements": [{
    "vulnerability": "CVE-2023-0286",
    "product_purl": "pkg:generic/openssl@3.0.7",
    "status": "not_affected",
    "justification": "vulnerable_code_not_present"
  }]
}
```

## What to check manually

1. `BUNDLE.id` matches `sha256(MANIFEST.sha)`.
2. `versions.json` records `spec_version: evidence-v1` and `decide_version: evidence-v1`.
3. `manifest-slice.json` provenance URLs are real upstream fix commits.
4. `observations.json` lists the exact symbols the rule consulted.

See also [SPEC-EVIDENCE.md](SPEC-EVIDENCE.md) for decision rules D01–D04.
