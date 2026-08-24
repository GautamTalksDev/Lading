#!/usr/bin/env bash
# Assert every inventory fixture listed in testdata/inventory/Makefile is
# tracked by git. Derives the list from the Makefile FIXTURES variable — do
# not hardcode paths here so a new fixture is covered automatically.
#
# Usage:
#   bash .github/scripts/check-fixtures.sh           # tracking only
#   bash .github/scripts/check-fixtures.sh --hash     # tracking + FIXTURES.sha
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

CHECK_HASH=0
if [[ "${1:-}" == "--hash" ]]; then
  CHECK_HASH=1
fi

# Derive fixture paths from Makefile FIXTURES= … (no hardcoding; no make required).
list_fixtures() {
  python3 - <<'PY'
from pathlib import Path
import re
mk = Path("testdata/inventory/Makefile").read_text(encoding="utf-8")
# Capture the FIXTURES := \ … block until a blank line or non-continuation.
m = re.search(r"^FIXTURES\s*:=\s*((?:\\\n|.*\n)*?)(?=^\S|\Z)", mk, re.M)
if not m:
    raise SystemExit("check-fixtures: FIXTURES block not found in Makefile")
block = m.group(1)
paths = []
for line in block.splitlines():
    line = line.strip().rstrip("\\").strip()
    if not line or line.startswith("#"):
        continue
    # $(BIN)/name → testdata/inventory/bin/name
    line = line.replace("$(BIN)/", "testdata/inventory/bin/")
    line = line.replace("$(ROOT)/bin/", "testdata/inventory/bin/")
    if "/bin/" not in line:
        raise SystemExit(f"check-fixtures: unexpected FIXTURES entry: {line!r}")
    paths.append(line)
if not paths:
    raise SystemExit("check-fixtures: empty FIXTURES list")
print("\n".join(paths))
PY
}

FIXTURES=()
while IFS= read -r line || [[ -n "${line}" ]]; do
  [[ -z "${line}" ]] && continue
  FIXTURES+=("${line}")
done < <(list_fixtures)

if [[ "${#FIXTURES[@]}" -eq 0 ]]; then
  echo "check-fixtures: empty fixture list from Makefile" >&2
  exit 1
fi

file_sha256() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${f}" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${f}" | awk '{print $1}'
  else
    python3 -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "${f}"
  fi
}

fail=0
for rel in "${FIXTURES[@]}"; do
  if ! git ls-files --error-unmatch "${rel}" >/dev/null 2>&1; then
    echo "check-fixtures: NOT TRACKED by git: ${rel}" >&2
    fail=1
    continue
  fi
  if [[ ! -f "${rel}" ]]; then
    echo "check-fixtures: missing on disk: ${rel}" >&2
    fail=1
  fi
done

if [[ "${fail}" -ne 0 ]]; then
  echo "check-fixtures: FAIL — commit the fixtures under testdata/inventory/bin/ (see Makefile FIXTURES)" >&2
  exit 1
fi

if [[ "${CHECK_HASH}" -eq 1 ]]; then
  SHA_FILE="testdata/inventory/FIXTURES.sha"
  if [[ ! -f "${SHA_FILE}" ]]; then
    echo "check-fixtures: missing ${SHA_FILE}" >&2
    exit 1
  fi
  while read -r expect path || [[ -n "${expect:-}" ]]; do
    [[ -z "${expect}" || "${expect}" =~ ^# ]] && continue
    path="${path#./}"
    if [[ ! -f "${path}" ]]; then
      echo "check-fixtures: FIXTURES.sha lists missing file: ${path}" >&2
      fail=1
      continue
    fi
    got="$(file_sha256 "${path}")"
    if [[ "${got}" != "${expect}" ]]; then
      echo "check-fixtures: hash mismatch ${path}" >&2
      echo "  expected ${expect}" >&2
      echo "  got      ${got}" >&2
      fail=1
    fi
  done < "${SHA_FILE}"

  # Every Makefile fixture must appear in FIXTURES.sha (and vice versa is covered above).
  while IFS= read -r rel || [[ -n "${rel}" ]]; do
    [[ -z "${rel}" ]] && continue
    if ! grep -q " ${rel}\$" "${SHA_FILE}" && ! grep -q " ${rel}$" "${SHA_FILE}"; then
      echo "check-fixtures: Makefile fixture missing from FIXTURES.sha: ${rel}" >&2
      fail=1
    fi
  done < <(printf '%s\n' "${FIXTURES[@]}")

  if [[ "${fail}" -ne 0 ]]; then
    echo "check-fixtures: FAIL — fixture hash mismatch (regenerate: make -C testdata/inventory fixtures.sha)" >&2
    exit 1
  fi
  echo "check-fixtures: OK (tracked + hashes match, ${#FIXTURES[@]} fixtures)"
else
  echo "check-fixtures: OK (tracked, ${#FIXTURES[@]} fixtures)"
fi
exit 0
