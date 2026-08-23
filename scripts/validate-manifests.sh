#!/usr/bin/env bash
# Validate every YAML/JSON manifest data file against the Lading Manifest schema.
# Schema files under manifest/schema/ are excluded.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA="${ROOT}/manifest/schema/lading-manifest.schema.json"

if [[ ! -f "${SCHEMA}" ]]; then
  echo "missing schema: ${SCHEMA}" >&2
  exit 1
fi

mapfile -t files < <(
  find "${ROOT}/manifest" \
    -type f \
    \( -name '*.yaml' -o -name '*.yml' -o -name '*.json' \) \
    ! -path "${ROOT}/manifest/schema/*" \
    | sort
)

if [[ ${#files[@]} -eq 0 ]]; then
  echo "no manifest data files to validate (schema present)"
  exit 0
fi

for f in "${files[@]}"; do
  echo "validating ${f#"${ROOT}/"}"
  check-jsonschema --schemafile "${SCHEMA}" "${f}"
done

echo "ok: ${#files[@]} file(s) validated"
