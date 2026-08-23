# LADING GitHub Action

Composite action: **scan → verify → upload** evidence and VEX.

## Usage

```yaml
- uses: gautamtalksdev/lading/action@v0
  with:
    artifact-path: ./dist/my-app
    findings-path: ./grype.json
    manifest-path: manifest
    output-dir: lading-out
```

### On release (upload assets)

```yaml
- uses: gautamtalksdev/lading/action@v0
  with:
    artifact-path: ./artifact
    findings-path: ./grype.json
    upload-release-assets: "true"
```

Requires `permissions: contents: write` on the job.

## Outputs

| Output | Description |
|--------|-------------|
| `bundle-path` | `evidence-bundle/` directory |
| `vex-openvex-path` | `vex.openvex.json` |
| `scan-json` | Scan summary JSON |

## What it does

1. Installs `lading` via `go install`
2. Runs `lading scan` with `--json` summary
3. Runs `lading verify` (air-gapped re-derivation)
4. Uploads workflow artifacts (bundle + all VEX formats + refusals)
5. Optionally attaches files to the GitHub Release

## Local testing

See [`.github/workflows/lading-action-smoke.yml`](../.github/workflows/lading-action-smoke.yml).
