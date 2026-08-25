# Lading Manifest Specification

This document is the contributor guide for adding knowledge to LADING.
You do **not** need to read Go code to add a component entry.

The Manifest is **data**, not code. All component knowledge lives under
`manifest/`. The loader validates every file against
`manifest/schema/entry.schema.json` and **refuses to load** on any error
(fail closed).

## Layout

```
manifest/
  VERSION                          # semver of this Manifest release (e.g. 0.1.0)
  schema/
    entry.schema.json              # normative JSON Schema
  components/
    <ecosystem>/
      <name>.yaml                  # one file per component
```

`Manifest.Version()` returns `semver+contentHash`. The content hash covers
`VERSION` and every component file. Changing any data file changes the hash.
Evidence bundles record this version string.

## Component file shape

Each YAML file has two top-level keys: `component` and `entries`.

```yaml
component:
  name: zlib
  ecosystem: native
  purls:
    - pkg:generic/zlib
  identity_symbols:
    - inflate
    - deflate
  identity_strings:
    - "inflate (?:1\\.2\\.\\d+)"

entries:
  - cve: CVE-2022-37434
    affected_versions:
      - "1.2.12"
    vulnerable_symbols:
      - name: inflate
        confidence: definitive
        provenance:
          upstream_fix_commit: https://github.com/madler/zlib/commit/<sha>
          derivation: patch-touched-function
          reviewed_by: your-handle
          reviewed_at: "2026-08-22"
    notes: Short free-text note.
    manifest_version: "0.1.0"
```

### `component` fields

| Field | Required | Meaning |
|-------|----------|---------|
| `name` | yes | Short name; should match the directory name |
| `ecosystem` | yes | Bucket (`native`, etc.) |
| `purls` | yes (≥1) | Canonical PURLs this entry covers |
| `identity_symbols` | yes (≥1) | Normalized symbols indicating the component is present |
| `identity_strings` | no | Rodata regexes indicating component / version |
| `provenance_status` | no (default: `unverified`) | `verified` or `unverified`. Components whose `upstream_fix_commit` URLs have been machine-checked (HTTP 200) are `verified`. **Only verified components may produce D01/D02 verdicts.** Unverified components are retained for refusal narrowing but cannot clear findings. |

### `entries[]` fields

| Field | Required | Meaning |
|-------|----------|---------|
| `cve` | yes | `CVE-YYYY-NNNN` (4+ digit sequence) |
| `affected_versions` | yes (≥1) | **Exact** version strings only — **no ranges in v1** |
| `vulnerable_symbols` | yes (≥1) | Symbols that evidence the vulnerability |
| `notes` | no | Free text |
| `manifest_version` | yes | Semver of the Manifest when the entry was written |

### `vulnerable_symbols[]` fields

| Field | Required | Meaning |
|-------|----------|---------|
| `name` | yes | Normalized symbol name |
| `confidence` | yes | `definitive` or `probable` |
| `dynsym_export_verified` | no (default: `false`) | Asserts the symbol was verified present in `.dynsym` on a reference build. D02 refuses with `reason_code: symbol_not_observable` when this field is absent or false. See FINDING-002. |
| `provenance` | yes | See below — **must include a fix-commit URL** |

**Export observability.** D02 (`vulnerable_code_not_present`) is sound only when the named function is observable in `.dynsym`. Internal (file-static or hidden) functions are absent from the export map whether or not their code shipped; treating that absence as evidence is unfalsifiable (FINDING-002). Set `dynsym_export_verified: true` only after confirming the symbol on a reference build. The engine does not infer this flag.

### `provenance` fields (hard rules)

| Field | Required | Meaning |
|-------|----------|---------|
| `upstream_fix_commit` | **yes** | `http(s)` URL of the upstream fix commit |
| `derivation` | yes | `patch-touched-function` \| `advisory-named` \| `manual` |
| `reviewed_by` | yes | Reviewer handle |
| `reviewed_at` | yes | ISO date `YYYY-MM-DD` |

**An entry with no provenance URL is invalid and fails schema validation.**

## Confidence semantics

- `definitive` — may be used by the decision engine to support `not_affected`
  when the rest of the evidence bundle is complete.
- `probable` — loaded for reporting / triage hints only. The decision engine
  must **never** emit `not_affected` from a probable symbol.

If any vulnerable symbol on an entry is `probable`, the entry as a whole must
not drive `not_affected`.

## How to add a component entry

1. Create `manifest/components/<ecosystem>/<name>.yaml`.
2. List PURLs and identity symbols you can defend from real binaries.
3. For each CVE:
   - List **exact** affected version strings (no ranges).
   - Name the vulnerable symbol(s).
   - Open the upstream fix commit in a browser, read the diff, and paste the
     commit URL into `provenance.upstream_fix_commit`.
   - Set `derivation` to `patch-touched-function` if the commit clearly
     touches that function; otherwise `advisory-named` or `manual`.
   - Set `confidence: definitive` only when you personally reviewed the
     commit. Use `probable` when uncertain — it will not produce
     `not_affected`.
4. Set `manifest_version` to the current value in `manifest/VERSION`.
5. Run:

   ```bash
   go test ./internal/manifest/ -count=1
   ```

   The loader must succeed. If validation fails, fix the YAML — do not
   weaken the schema.

6. Bump `manifest/VERSION` when cutting a Manifest release. Tag the release;
   the content hash from `Manifest.Version()` goes into every evidence bundle.

## Manifest derive and promote

Operators may semi-automate candidate construction on Linux:

```bash
lading manifest derive --job path/to/job.yaml
lading manifest promote manifest/candidates/native/foo.yaml \
  --reviewed-by your-handle --reviewed-at YYYY-MM-DD
lading manifest coverage
```

`derive` always writes `confidence: probable` under `manifest/candidates/`.
It never writes `manifest/components/` and never sets `definitive`.
`promote` is the only path to `definitive` and refuses without
`--reviewed-by` / `--reviewed-at`.

See also `internal/manifestderive` and `manifest/COVERAGE.md`.

## What not to do

- Do not invent symbols you have not seen in a patch or advisory.
- Do not use version ranges in v1 (`>=1.2.0`, `1.2.x`, etc.).
- Do not omit `upstream_fix_commit` “to fill in later” — the loader will reject the file.
- Do not mark `probable` as good enough for `not_affected`.

## Seed corpus (v0.1.0)

Three hand-built entries with fix commits that were opened and read:

| Component | CVE | Fix commit |
|-----------|-----|------------|
| zlib | CVE-2022-37434 | https://github.com/madler/zlib/commit/eff308af425b67093bab25f80f1ae950166bece1 |
| libexpat | CVE-2022-25315 | https://github.com/libexpat/libexpat/commit/eb0362808b4f9f1e2345a0cf203b8cc196d776d9 |
| openssl | CVE-2023-0286 | https://github.com/openssl/openssl/commit/2f7530077e0ef79d98718138716bc51ca0cad658 |

Three correct entries beat three hundred guessed ones.
