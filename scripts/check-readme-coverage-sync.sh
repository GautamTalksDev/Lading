#!/usr/bin/env bash
# Ensure README coverage table matches manifest/COVERAGE.md (generated, not hand-edited).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COVERAGE="${ROOT}/manifest/COVERAGE.md"

if [[ ! -f "${COVERAGE}" ]]; then
  echo "missing ${COVERAGE} — run: lading manifest coverage" >&2
  exit 1
fi

python3 - "${ROOT}" <<'PY'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
readme = (root / "README.md").read_text()
coverage = (root / "manifest/COVERAGE.md").read_text()

rows = []
for line in coverage.splitlines():
    if line.startswith("|") and "Component" not in line and "---" not in line:
        cols = [c.strip() for c in line.strip("|").split("|")]
        if len(cols) >= 5:
            rows.append(cols)

version_m = re.search(r"Manifest version: `([^`]+)`", coverage)
if not version_m:
    raise SystemExit("COVERAGE.md missing Manifest version line")
version = version_m.group(1)

expected_rows = []
for r in rows:
    expected_rows.append(f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} |")

block_m = re.search(
    r"<!-- Regenerate: lading manifest coverage.*?Full detail:",
    readme,
    re.S,
)
if not block_m:
    raise SystemExit("README coverage markers not found")

block = block_m.group(0)
if f"**Manifest version:** `{version}`" not in block:
    raise SystemExit("README manifest version out of sync with COVERAGE.md")

for row in expected_rows:
    if row not in block:
        raise SystemExit(f"README missing coverage row: {row}")

print("ok: README coverage table matches manifest/COVERAGE.md")
PY
