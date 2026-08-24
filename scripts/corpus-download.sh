#!/usr/bin/env bash
# Download CP-11 corpus artifacts listed in corpus/ARTIFACTS.yaml.
# Principle 1: on HTTP/pull failure leave the target directory EMPTY, write a
# failure record, never substitute, never continue silently. Exit non-zero if
# any required artifact failed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DL="${ROOT}/corpus/downloads"
mkdir -p "${DL}"

log() { echo "[corpus-download] $*" >&2; }

FAILURES=0

write_failure() {
  local id="$1" reason="$2" detail="$3"
  local dir="${DL}/${id}"
  mkdir -p "${dir}"
  # Leave directory empty of payload bytes — only the failure record remains.
  find "${dir}" -mindepth 1 -maxdepth 1 ! -name 'download-failure.json' -exec rm -rf {} +
  python3 - "${dir}/download-failure.json" "${id}" "${reason}" "${detail}" <<'PY'
import json, sys, datetime
path, id_, reason, detail = sys.argv[1:5]
doc = {
    "id": id_,
    "event": "download-failure",
    "reason": reason,
    "detail": detail,
    "recorded_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
  log "FAILURE recorded ${id}: ${reason}"
  FAILURES=$((FAILURES + 1))
}

download_url() {
  local id="$1" url="$2"
  local dir="${DL}/${id}"
  mkdir -p "${dir}"
  local out="${dir}/$(basename "${url}")"
  if [[ -f "${out}" ]]; then
    log "skip ${id} (exists)"
    rm -f "${dir}/download-failure.json"
    return 0
  fi
  log "fetch ${id} <- ${url}"
  local tmp="${out}.partial"
  rm -f "${tmp}"
  if ! curl -fsSL --retry 3 --connect-timeout 60 -o "${tmp}" "${url}"; then
    rm -f "${tmp}"
    write_failure "${id}" "http-failure" "${url}"
    return 0
  fi
  mv "${tmp}" "${out}"
  rm -f "${dir}/download-failure.json"
}

pull_image() {
  local id="$1" ref="$2"
  local dir="${DL}/${id}"
  mkdir -p "${dir}"
  if [[ -f "${dir}/image.tar" ]]; then
    log "skip ${id} tar (exists)"
    echo "${ref}" > "${dir}/image.ref"
    rm -f "${dir}/download-failure.json"
    return 0
  fi
  log "pull ${id} <- ${ref}"
  if ! podman pull "${ref}"; then
    write_failure "${id}" "pull-failure" "${ref}"
    return 0
  fi
  local tmp="${dir}/image.tar.partial"
  rm -f "${tmp}"
  if ! podman save -o "${tmp}" "${ref}"; then
    rm -f "${tmp}"
    write_failure "${id}" "save-failure" "${ref}"
    return 0
  fi
  mv "${tmp}" "${dir}/image.tar"
  echo "${ref}" > "${dir}/image.ref"
  rm -f "${dir}/download-failure.json"
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
    SKIP_UNHASHED)
      write_failure "${id}" "artifact-unhashed" "catalogue sha256 is null; refusing to fetch a substitute"
      ;;
  esac
done < <(python3 - <<PY
import yaml, os
root = "${ROOT}"
with open(os.path.join(root, "corpus/ARTIFACTS.yaml")) as f:
    doc = yaml.safe_load(f)
for a in doc["artifacts"]:
    # Never download stand-ins for unhashed rows — refuse closed.
    if a.get("sha256") is None:
        print(f"SKIP_UNHASHED {a['id']} -")
        continue
    if a.get("class") == "benchmark":
        print(f"PATH {a['id']} {a.get('path','')}")
        continue
    if "ref" in a:
        print(f"REF {a['id']} {a['ref']}")
    elif "url" in a:
        print(f"URL {a['id']} {a['url']}")
    elif "path" in a:
        print(f"PATH {a['id']} {a['path']}")
PY
)

if [[ "${FAILURES}" -gt 0 ]]; then
  log "done WITH FAILURES: ${FAILURES} artifact(s) failed — exit 1"
  exit 1
fi
log "done"
exit 0
