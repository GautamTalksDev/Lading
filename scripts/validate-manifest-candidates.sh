#!/usr/bin/env bash
# Validate contributor candidate YAML under manifest/candidates/.
# Candidates must stay probable-only and must not carry reviewed_* attestation.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAND_ROOT="${ROOT}/manifest/candidates"

if [[ ! -d "${CAND_ROOT}" ]]; then
  echo "ok: no manifest/candidates/ directory"
  exit 0
fi

mapfile -t files < <(
  find "${CAND_ROOT}" -type f \( -name '*.yaml' -o -name '*.yml' \) | sort
)

if [[ ${#files[@]} -eq 0 ]]; then
  echo "ok: no candidate files"
  exit 0
fi

fail=0
for f in "${files[@]}"; do
  rel="${f#"${ROOT}/"}"
  if grep -Eq '^[[:space:]]*confidence:[[:space:]]*definitive' "${f}"; then
    echo "${rel}: candidates must not use confidence: definitive" >&2
    fail=1
  fi
  if grep -Eq '^[[:space:]]*reviewed_by:' "${f}"; then
    echo "${rel}: candidates must not set reviewed_by (promote adds attestation)" >&2
    fail=1
  fi
  if grep -Eq '^[[:space:]]*reviewed_at:' "${f}"; then
    echo "${rel}: candidates must not set reviewed_at" >&2
    fail=1
  fi
  if ! grep -Eq '^[[:space:]]*upstream_fix_commit:[[:space:]]*https://' "${f}"; then
    echo "${rel}: missing upstream_fix_commit https:// URL" >&2
    fail=1
  fi
  if ! grep -Eq '^[[:space:]]*confidence:[[:space:]]*probable' "${f}"; then
    echo "${rel}: expected at least one confidence: probable symbol" >&2
    fail=1
  fi
  echo "ok candidate ${rel}"
done

if [[ "${fail}" -ne 0 ]]; then
  exit 1
fi
echo "ok: ${#files[@]} candidate file(s) validated"
