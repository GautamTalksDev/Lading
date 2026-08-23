#!/usr/bin/env bash
# HEAD-check upstream_fix_commit URLs in changed manifest YAML (or all components on push).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

collect_files() {
  if [[ "${GITHUB_EVENT_NAME:-local}" == "pull_request" ]]; then
    local base="${GITHUB_BASE_REF:-main}"
    git fetch origin "${base}" --depth=1 2>/dev/null || true
    git diff --name-only "origin/${base}...HEAD" -- 'manifest/**' \
      | grep -E '\.(yaml|yml)$' || true
  elif [[ "${GITHUB_EVENT_NAME:-local}" == "push" ]]; then
    find manifest/components -type f \( -name '*.yaml' -o -name '*.yml' \) | sort
  else
    # Local / workflow_dispatch: validate all promoted components.
    find manifest/components -type f \( -name '*.yaml' -o -name '*.yml' \) | sort
  fi
}

mapfile -t files < <(collect_files)

if [[ ${#files[@]} -eq 0 ]]; then
  echo "ok: no manifest YAML changes to check"
  exit 0
fi

fail=0
for f in "${files[@]}"; do
  [[ -f "${f}" ]] || continue
  while IFS= read -r url; do
    url="${url#"${url%%[![:space:]]*}"}"
    url="${url%"${url##*[![:space:]]}"}"
    [[ -z "${url}" ]] && continue
    if [[ "${url}" == *example.com* ]]; then
      echo "skip test URL ${url}"
      continue
    fi
    echo "HEAD ${url}"
    if ! curl -fsI --max-time 25 --retry 2 --retry-delay 2 "${url}" >/dev/null; then
      echo "${f}: unreachable upstream_fix_commit ${url}" >&2
      fail=1
    fi
  done < <(grep -E '^[[:space:]]*upstream_fix_commit:[[:space:]]*https://' "${f}" \
    | sed -E 's/^[[:space:]]*upstream_fix_commit:[[:space:]]*//' \
    | sed -E 's/[[:space:]]+#.*$//')
done

if [[ "${fail}" -ne 0 ]]; then
  exit 1
fi
echo "ok: provenance URLs reachable"
