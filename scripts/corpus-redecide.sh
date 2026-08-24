#!/usr/bin/env bash
# Re-run lading decide on existing grype.json using profile-rootfs (or downloads
# rootfs / image.tar) without re-grype. Writes decisions.jsonl + scan-summary.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/corpus/results"
LADING="${LADING:-${ROOT}/bin/lading}"
MANIFEST="${ROOT}/manifest"

if [[ ! -x "${LADING}" ]]; then
  (cd "${ROOT}" && go build -o bin/lading ./cmd/lading)
  LADING="${ROOT}/bin/lading"
fi

resolve_tree() {
  local id="$1"
  if [[ -d "${ROOT}/.lading/profile-rootfs/${id}" && -n "$(ls -A "${ROOT}/.lading/profile-rootfs/${id}" 2>/dev/null)" ]]; then
    echo "${ROOT}/.lading/profile-rootfs/${id}"
    return 0
  fi
  if [[ -d "${ROOT}/corpus/downloads/${id}/rootfs" && -n "$(ls -A "${ROOT}/corpus/downloads/${id}/rootfs" 2>/dev/null)" ]]; then
    echo "${ROOT}/corpus/downloads/${id}/rootfs"
    return 0
  fi
  if [[ -f "${ROOT}/corpus/downloads/${id}/image.tar" ]]; then
    echo "${ROOT}/corpus/downloads/${id}/image.tar"
    return 0
  fi
  return 1
}

ids=("$@")
if [[ ${#ids[@]} -eq 0 ]]; then
  while IFS= read -r d; do
    ids+=("$(basename "$d")")
  done < <(find "${OUT}" -mindepth 1 -maxdepth 1 -type d | sort)
fi

for id in "${ids[@]}"; do
  rdir="${OUT}/${id}"
  [[ -f "${rdir}/grype.json" ]] || { echo "[redecide] skip ${id}: no grype.json"; continue; }
  tree="$(resolve_tree "${id}" || true)"
  if [[ -z "${tree}" ]]; then
    echo "[redecide] skip ${id}: no scan tree"
    continue
  fi
  echo "[redecide] ${id} <- ${tree}" >&2
  set +e
  "${LADING}" scan "${tree}" \
    --findings "${rdir}/grype.json" \
    --manifest "${MANIFEST}" \
    --out "${rdir}" \
    --no-vex \
    --json > "${rdir}/scan-summary.json" 2>"${rdir}/scan.stderr"
  rc=$?
  set -e
  if [[ "${rc}" -ne 0 && "${rc}" -ne 1 ]]; then
    echo "[redecide] WARN ${id} rc=${rc}" >&2
    continue
  fi
  python3 - "${rdir}/scan-summary.json" "${id}" <<'PY'
import json,sys
p,id_=sys.argv[1:3]
s=json.load(open(p))
print(f"[redecide] {id_}: cves={s.get('cves_in')} na={s.get('not_affected')} aff={s.get('affected')} ref={s.get('refused')} cov={s.get('coverage_percent')}")
PY
done

python3 "${ROOT}/scripts/corpus-aggregate.py"
echo "[redecide] done" >&2
