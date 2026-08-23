#!/usr/bin/env bash
# Run grype + lading scan for each downloaded corpus artifact.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DL="${ROOT}/corpus/downloads"
OUT="${ROOT}/corpus/results"
LADING="${LADING:-${ROOT}/bin/lading}"
MANIFEST="${ROOT}/manifest"

if [[ ! -x "${LADING}" ]]; then
  (cd "${ROOT}" && go build -o bin/lading ./cmd/lading)
  LADING="${ROOT}/bin/lading"
fi

mkdir -p "${OUT}"
log() { echo "[corpus-scan] $*" >&2; }

scan_dir() {
  local id="$1" dir="$2"
  local rdir="${OUT}/${id}"
  mkdir -p "${rdir}"
  if [[ -s "${rdir}/scan-summary.json" ]]; then
    log "skip ${id} (already scanned)"
    return 0
  fi
  log "grype ${id}"
  if [[ -f "${dir}" ]]; then
    grype "${dir}" -o json > "${rdir}/grype.json" 2>"${rdir}/grype.stderr" || true
  else
    grype "dir:${dir}" -o json > "${rdir}/grype.json" 2>"${rdir}/grype.stderr" || true
  fi
  if [[ ! -s "${rdir}/grype.json" ]]; then
    echo '{"matches":[]}' > "${rdir}/grype.json"
  fi
  log "lading scan ${id}"
  "${LADING}" scan "${dir}" \
    --findings "${rdir}/grype.json" \
    --manifest "${MANIFEST}" \
    --out "${rdir}" \
    --json > "${rdir}/scan-summary.json" 2>"${rdir}/scan.stderr" || true
  cp -f "${rdir}/scan-summary.json" "${rdir}/scan-summary.retcode-$?.json" 2>/dev/null || true
}

scan_image() {
  local id="$1" ref="$2"
  local rdir="${OUT}/${id}"
  mkdir -p "${rdir}"
  if [[ -s "${rdir}/scan-summary.json" ]]; then
    log "skip ${id} (already scanned)"
    return 0
  fi
  log "grype ${id} (image)"
  grype "${ref}" -o json > "${rdir}/grype.json" 2>"${rdir}/grype.stderr" || true
  if [[ ! -s "${rdir}/grype.json" ]]; then
    echo '{"matches":[]}' > "${rdir}/grype.json"
  fi
  log "lading scan --image ${id}"
  "${LADING}" scan --image "${ref}" \
    --findings "${rdir}/grype.json" \
    --manifest "${MANIFEST}" \
    --out "${rdir}" \
    --json > "${rdir}/scan-summary.json" 2>"${rdir}/scan.stderr" || true
}

extract_tarball() {
  local id="$1" archive="$2"
  local dir="${DL}/${id}/rootfs"
  if [[ -d "${dir}" && -n "$(ls -A "${dir}" 2>/dev/null)" ]]; then
    echo "${dir}"
    return 0
  fi
  mkdir -p "${dir}"
  case "${archive}" in
    *.tar.gz|*.tgz) tar -xzf "${archive}" -C "${dir}" ;;
    *.tar.xz) tar -xJf "${archive}" -C "${dir}" ;;
    *.tar) tar -xf "${archive}" -C "${dir}" ;;
    *.zip) unzip -q -o "${archive}" -d "${dir}" ;;
    *.bz2) bunzip2 -kf "${archive}"; mv "${archive%.bz2}" "${dir}/root.bin" 2>/dev/null || cp "${archive%.bz2}" "${dir}/root.bin" ;;
    *.img.gz|*.bin) gunzip -kf "${archive}" 2>/dev/null || true; cp "${archive}" "${dir}/" ;;
    *) log "unknown archive ${archive}"; return 1 ;;
  esac
  echo "${dir}"
}

while IFS= read -r line; do
  kind="${line%% *}"
  id="${line#* }"
  id="${id%% *}"
  case "${kind}" in
    REF)
      if [[ ! -f "${DL}/${id}/image.ref" ]]; then
        log "skip ${id}: no image.ref (pull failed?)"
        continue
      fi
      ref="$(cat "${DL}/${id}/image.ref")"
      scan_image "${id}" "${ref}"
      ;;
    URL)
      dir="${DL}/${id}"
      if [[ ! -d "${dir}" ]]; then
        log "skip ${id}: download dir missing"
        continue
      fi
      archive="$(find "${dir}" -maxdepth 1 -type f ! -name '*.ref' ! -name '*.img' | head -1)"
      if [[ -z "${archive}" ]]; then
        archive="$(find "${dir}" -maxdepth 1 -type f ! -name '*.ref' | head -1)"
      fi
      if [[ -z "${archive}" ]]; then
        log "skip ${id}: no archive"
        continue
      fi
      case "${archive}" in
        *.tar.gz|*.tar.xz|*.tar|*.zip|*.img.gz|*.bin)
          rootfs="$(extract_tarball "${id}" "${archive}")"
          scan_dir "${id}" "${rootfs}"
          ;;
        *.bz2)
          out="${dir}/$(basename "${archive%.bz2}")"
          if [[ ! -f "${out}" ]]; then
            bunzip2 -kf "${archive}"
          fi
          scan_dir "${id}" "${out}"
          ;;
        *.ext4|*.elf)
          scan_dir "${id}" "${archive}"
          ;;
        *)
          chmod +x "${archive}" 2>/dev/null || true
          scan_dir "${id}" "${archive}"
          ;;
      esac
      ;;
    PATH)
      scan_dir "${id}" "${ROOT}/${line#* }"
      ;;
  esac
done < <(python3 - <<PY
import yaml, os
root = "${ROOT}"
with open(os.path.join(root, "corpus/ARTIFACTS.yaml")) as f:
    doc = yaml.safe_load(f)
for a in doc["artifacts"]:
    if a.get("class") == "benchmark":
        continue
    if "ref" in a:
        print(f"REF {a['id']}")
    elif "url" in a:
        print(f"URL {a['id']}")
    elif "path" in a:
        print(f"PATH {a['id']} {a['path']}")
PY
)

log "aggregate -> corpus/results/aggregate.json"
python3 "${ROOT}/scripts/corpus-aggregate.py"
log "done"
