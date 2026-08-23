#!/usr/bin/env bash
# Validate vexout emitters against vendored official JSON schemas (requires check-jsonschema).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v check-jsonschema >/dev/null 2>&1; then
  echo "check-jsonschema required (pip install check-jsonschema)" >&2
  exit 1
fi

cd "${ROOT}"
go test ./internal/vexout/ -run TestEmit_SchemaValidation -count=1
echo "ok: OpenVEX, CycloneDX 1.6, and CSAF 2.0 outputs validated"
