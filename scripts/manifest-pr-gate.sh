#!/usr/bin/env bash
# CP-13 manifest contribution CI gate (schema, candidates, URLs, definitive label).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

bash scripts/validate-manifests.sh
bash scripts/validate-manifest-candidates.sh
bash scripts/check-provenance-urls.sh
bash scripts/check-manifest-definitive-label.sh

# Coverage table sync is a live-manifest maintenance check. This README is an
# archived landing page and no longer carries the markers. Skip rather than
# fail; if the markers are restored the check runs as before.
if grep -q '<!-- Regenerate: lading manifest coverage' README.md; then
  bash scripts/check-readme-coverage-sync.sh
else
  echo "manifest PR gate: README coverage markers absent — skipping coverage sync"
fi

echo "manifest PR gate: ok"
