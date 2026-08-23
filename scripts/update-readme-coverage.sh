#!/usr/bin/env bash
# Copy manifest coverage table into README.md between markers.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
README="${ROOT}/README.md"
COVERAGE="${ROOT}/manifest/COVERAGE.md"

if [[ ! -f "${COVERAGE}" ]]; then
  echo "run: lading manifest coverage" >&2
  exit 1
fi

VERSION="$(grep -m1 'Manifest version:' "${COVERAGE}" | sed 's/.*`\([^`]*\)`.*/\1/')"

python3 <<PY
from pathlib import Path
import re

readme = Path("${README}").read_text()
coverage = Path("${COVERAGE}").read_text()

# Extract summary table (lines starting with |, skip header separator)
rows = []
for line in coverage.splitlines():
    if line.startswith("|") and "Component" not in line and "---" not in line:
        cols = [c.strip() for c in line.strip("|").split("|")]
        if len(cols) >= 5:
            rows.append(cols)

table = "| Component | Ecosystem | Definitive CVEs | Probable-only | None |\n"
table += "|-----------|-----------|-----------------|---------------|------|\n"
for r in rows:
    table += f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} |\n"

block = f"""<!-- Regenerate: lading manifest coverage && bash scripts/update-readme-coverage.sh -->

**Manifest version:** \`${VERSION}\`

{table.rstrip()}

Full detail:"""

pattern = r"<!-- Regenerate: lading manifest coverage.*?Full detail:"
new_readme, n = re.subn(pattern, block, readme, count=1, flags=re.S)
if n != 1:
    raise SystemExit("README coverage markers not found")

Path("${README}").write_text(new_readme)
print("updated README coverage table")
PY
