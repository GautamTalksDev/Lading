#!/usr/bin/env bash
# Verify every catalogued artifact with a non-null sha256 matches on-disk bytes.
# Files: SHA-256 of contents. Directories: RP-6 / SHA256Dir algorithm
# (sorted relpath\0 + fileHex\0). Exit 0 only when all hashed path-backed
# entries match and class:firmware count >= 10.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CATALOG="${ROOT}/corpus/ARTIFACTS.yaml"

if [[ ! -f "${CATALOG}" ]]; then
  echo "verify-corpus-hashes: missing ${CATALOG}" >&2
  exit 1
fi

python3 - "${ROOT}" "${CATALOG}" <<'PY'
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import yaml


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_dir(root: Path) -> str:
    """Match internal/scan.SHA256Dir / RP-6 cataloger."""
    files = sorted(p for p in root.rglob("*") if p.is_file())
    h = hashlib.sha256()
    for fp in files:
        rel = fp.relative_to(root).as_posix().encode()
        h.update(rel + b"\0")
        h.update(sha256_file(fp).encode() + b"\0")
    return h.hexdigest()


def sha256_path(path: Path) -> str:
    if path.is_dir():
        return sha256_dir(path)
    if path.is_file():
        return sha256_file(path)
    raise FileNotFoundError(str(path))


root = Path(sys.argv[1])
catalog = Path(sys.argv[2])
doc = yaml.safe_load(catalog.read_text(encoding="utf-8"))
artifacts = doc.get("artifacts") or []

errors: list[str] = []
checked = 0
skipped = 0

for a in artifacts:
    id_ = a.get("id", "<missing-id>")
    sha = a.get("sha256")
    if sha is None:
        skipped += 1
        continue
    if not isinstance(sha, str) or len(sha) != 64:
        errors.append(f"{id_}: invalid sha256 catalogue value {sha!r}")
        continue

    path_s = a.get("path") or ""
    if not path_s:
        # OCI refs / URL-only rows may lack a local path.
        skipped += 1
        continue

    path = Path(path_s)
    if not path.is_absolute():
        path = root / path
    if not path.exists():
        errors.append(f"{id_}: absent path {path}")
        continue

    try:
        got = sha256_path(path)
    except OSError as e:
        errors.append(f"{id_}: hash error {path}: {e}")
        continue
    checked += 1
    if got != sha.lower():
        errors.append(f"{id_}: hash mismatch expected={sha} got={got} path={path}")

fw = sum(1 for a in artifacts if a.get("class") == "firmware")
print(
    f"verify-corpus-hashes: checked={checked} skipped_null_or_no_path={skipped} "
    f"firmware_class={fw} errors={len(errors)}"
)
for e in errors:
    print(f"  FAIL {e}", file=sys.stderr)
if errors:
    sys.exit(1)
if fw < 10:
    print(f"verify-corpus-hashes: firmware class count {fw} < 10", file=sys.stderr)
    sys.exit(1)
sys.exit(0)
PY
