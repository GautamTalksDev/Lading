#!/usr/bin/env bash
# CP-13 manifest contribution CI gate (schema, candidates, URLs, definitive label).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

bash scripts/validate-manifests.sh
bash scripts/validate-manifest-candidates.sh
bash scripts/check-provenance-urls.sh
bash scripts/check-manifest-definitive-label.sh
bash scripts/check-readme-coverage-sync.sh

echo "manifest PR gate: ok"
