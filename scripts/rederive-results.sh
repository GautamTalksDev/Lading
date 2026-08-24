#!/usr/bin/env bash
# Re-derive CP-11 figures from on-disk corpus outputs and validate RESULTS.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

echo "[rederive] refusal-stage histogram…" >&2
bash scripts/refusal-stages.sh

echo "[rederive] aggregate scan summaries…" >&2
python3 scripts/corpus-aggregate.py

echo "[rederive] compute kill-test metrics…" >&2
python3 scripts/compute-cp11-metrics.py

echo "[rederive] render RESULTS.md §KT-2…" >&2
python3 scripts/render-results-kt2.py

echo "[rederive] validate RESULTS.md…" >&2
python3 scripts/validate-results-md.py

echo "[rederive] OK" >&2
