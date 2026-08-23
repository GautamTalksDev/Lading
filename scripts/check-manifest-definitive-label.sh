#!/usr/bin/env bash
# Fail PRs that add confidence: definitive under manifest/components/ without
# the manifest-reviewed maintainer label.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

if [[ "${GITHUB_EVENT_NAME:-}" != "pull_request" ]]; then
  echo "skip: not a pull_request event"
  exit 0
fi

base="${GITHUB_BASE_REF:-main}"
git fetch origin "${base}" --depth=1 2>/dev/null || true

added_definitive=0
while IFS= read -r f; do
  [[ -z "${f}" ]] && continue
  if git diff "origin/${base}...HEAD" -- "${f}" | grep -Eq '^\+.*confidence:[[:space:]]*definitive'; then
    echo "detected new definitive in ${f}"
    added_definitive=1
  fi
done < <(git diff --name-only "origin/${base}...HEAD" -- manifest/components/ || true)

if [[ "${added_definitive}" -eq 0 ]]; then
  echo "ok: PR does not add confidence: definitive under manifest/components/"
  exit 0
fi

if [[ ! -f "${GITHUB_EVENT_PATH:-}" ]]; then
  echo "ERROR: definitive added but GITHUB_EVENT_PATH unavailable for label check" >&2
  exit 1
fi

if jq -e '.pull_request.labels[] | select(.name == "manifest-reviewed")' "${GITHUB_EVENT_PATH}" >/dev/null; then
  echo "ok: manifest-reviewed label present"
  exit 0
fi

echo "ERROR: PR adds confidence: definitive under manifest/components/ without manifest-reviewed label" >&2
echo "Maintainer: review binary evidence, promote locally, add label, then merge." >&2
exit 1
