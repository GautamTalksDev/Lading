#!/usr/bin/env bash
# Validate every promoted component YAML against the Lading Manifest schema.
# Candidates under manifest/candidates/ are intentionally excluded (probable-only,
# may omit reviewed_* until promote).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA="${ROOT}/manifest/schema/entry.schema.json"

if [[ ! -f "${SCHEMA}" ]]; then
  echo "missing schema: ${SCHEMA}" >&2
  exit 1
fi

mapfile -t files < <(
  find "${ROOT}/manifest/components" \
    -type f \
    \( -name '*.yaml' -o -name '*.yml' -o -name '*.json' \) \
    | sort
)

if [[ ${#files[@]} -eq 0 ]]; then
  echo "no component files to validate under manifest/components/"
  exit 1
fi

for f in "${files[@]}"; do
  echo "validating ${f#"${ROOT}/"}"
  check-jsonschema --schemafile "${SCHEMA}" "${f}"
done

echo "ok: ${#files[@]} file(s) validated"
