#!/usr/bin/env bash
# Download CP-11 corpus artifacts listed in corpus/ARTIFACTS.yaml.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DL="${ROOT}/corpus/downloads"
mkdir -p "${DL}"

log() { echo "[corpus-download] $*" >&2; }

download_url() {
  local id="$1" url="$2"
  local dir="${DL}/${id}"
  mkdir -p "${dir}"
  local out="${dir}/$(basename "${url}")"
  if [[ -f "${out}" ]]; then
    log "skip ${id} (exists)"
    return 0
  fi
  log "fetch ${id} <- ${url}"
  if ! curl -fsSL --retry 3 --connect-timeout 60 -o "${out}" "${url}"; then
    log "FAILED ${id} (curl error — continuing)"
    rm -f "${out}"
    return 0
  fi
}

pull_image() {
  local id="$1" ref="$2"
  local dir="${DL}/${id}"
  mkdir -p "${dir}"
  echo "${ref}" > "${dir}/image.ref"
  if [[ -f "${dir}/image.tar" ]]; then
    log "skip ${id} tar (exists)"
    return 0
  fi
  log "pull ${id} <- ${ref}"
  podman pull "${ref}"
  podman save -o "${dir}/image.tar" "${ref}"
}

while IFS= read -r line; do
  kind="${line%% *}"
  rest="${line#* }"
  id="${rest%% *}"
  val="${rest#* }"
  case "${kind}" in
    REF) pull_image "${id}" "${val}" ;;
    URL) download_url "${id}" "${val}" ;;
    PATH) log "local ${id} -> ${val}" ;;
  esac
done < <(python3 - <<PY
import yaml, os
root = "${ROOT}"
with open(os.path.join(root, "corpus/ARTIFACTS.yaml")) as f:
    doc = yaml.safe_load(f)
for a in doc["artifacts"]:
    if "ref" in a:
        print(f"REF {a['id']} {a['ref']}")
    elif "url" in a:
        print(f"URL {a['id']} {a['url']}")
    elif "path" in a:
        print(f"PATH {a['id']} {a['path']}")
PY
)

log "done"
