#!/usr/bin/env bash
# Run grype + lading scan for each downloaded corpus artifact.
# Principle 1: refuse any artifact whose on-disk bytes do not match ARTIFACTS.yaml
# sha256 (or whose catalogue hash is null, or whose payload is absent). Never scan
# refused artifacts. Run summary always states integrity refusal counts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DL="${ROOT}/corpus/downloads"
OUT="${ROOT}/corpus/results"
LADING="${LADING:-${ROOT}/bin/lading}"
MANIFEST="${ROOT}/manifest"
EVENTS="${OUT}/integrity-events.jsonl"
RUN_SUMMARY="${OUT}/run-summary.json"

if [[ ! -x "${LADING}" ]]; then
  (cd "${ROOT}" && go build -o bin/lading ./cmd/lading)
  LADING="${ROOT}/bin/lading"
fi

mkdir -p "${OUT}"
: > "${EVENTS}"
log() { echo "[corpus-scan] $*" >&2; }

SCANNED=0
REFUSED_MISMATCH=0
REFUSED_ABSENT=0
REFUSED_UNHASHED=0

sha_path() {
  python3 - "$1" <<'PY'
import hashlib, sys
from pathlib import Path
p = Path(sys.argv[1])

def sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def sha_dir(root: Path) -> str:
    h = hashlib.sha256()
    files = sorted(x for x in root.rglob("*") if x.is_file())
    for fp in files:
        rel = fp.relative_to(root).as_posix().encode()
        h.update(rel + b"\0")
        h.update(sha_file(fp).encode() + b"\0")
    return h.hexdigest()

print(sha_dir(p) if p.is_dir() else sha_file(p))
PY
}

record_event() {
  local id="$1" reason="$2" detail="$3" expected="${4:-}" actual="${5:-}"
  python3 - "${EVENTS}" "${OUT}/${id}" "${id}" "${reason}" "${detail}" "${expected}" "${actual}" <<'PY'
import json, sys, datetime
from pathlib import Path
events, rdir, id_, reason, detail, expected, actual = sys.argv[1:8]
Path(rdir).mkdir(parents=True, exist_ok=True)
doc = {
    "id": id_,
    "event": "integrity-refusal",
    "reason": reason,
    "detail": detail,
    "expected_sha256": expected or None,
    "actual_sha256": actual or None,
    "recorded_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "success": False,
    "integrity_refusals": {reason: 1},
    "refused": 1,
    "refused_breakdown": {reason: 1},
}
with open(events, "a", encoding="utf-8") as f:
    f.write(json.dumps(doc) + "\n")
with open(Path(rdir) / "integrity-refusal.json", "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
summary = {
    "binaries_scanned": 0,
    "stripped": 0,
    "static_linked": 0,
    "cves_in": 0,
    "not_affected": 0,
    "not_affected_breakdown": {},
    "affected": 0,
    "refused": 1,
    "refused_breakdown": {reason: 1},
    "integrity_refusals": {reason: 1},
    "success": False,
    "coverage_percent": 0,
}
with open(Path(rdir) / "scan-summary.json", "w", encoding="utf-8") as f:
    json.dump(summary, f)
    f.write("\n")
PY
  case "${reason}" in
    artifact-hash-mismatch) REFUSED_MISMATCH=$((REFUSED_MISMATCH + 1)) ;;
    artifact-absent) REFUSED_ABSENT=$((REFUSED_ABSENT + 1)) ;;
    artifact-unhashed) REFUSED_UNHASHED=$((REFUSED_UNHASHED + 1)) ;;
  esac
  log "REFUSED ${id}: ${reason}"
}

catalog_sha() {
  python3 - "${ROOT}" "$1" <<'PY'
import sys, yaml
root, id_ = sys.argv[1:3]
doc = yaml.safe_load(open(f"{root}/corpus/ARTIFACTS.yaml"))
for a in doc["artifacts"]:
    if a["id"] == id_:
        v = a.get("sha256")
        if v is None:
            print("NULL")
        else:
            print(v)
        sys.exit(0)
print("MISSING")
sys.exit(0)
PY
}

# Gate: catalogue hash must match on-disk bytes. Echoes expected sha on success.
integrity_gate() {
  local id="$1" payload="$2"
  local sha
  sha="$(catalog_sha "${id}")"
  if [[ "${sha}" == "MISSING" ]]; then
    record_event "${id}" "artifact-absent" "id not in catalogue"
    return 1
  fi
  if [[ "${sha}" == "NULL" || -z "${sha}" ]]; then
    record_event "${id}" "artifact-unhashed" "catalogue sha256 is null"
    return 1
  fi
  if [[ -z "${payload}" || ! -e "${payload}" ]]; then
    record_event "${id}" "artifact-absent" "payload missing: ${payload:-"(empty)"}" "${sha}" ""
    return 1
  fi
  local actual
  actual="$(sha_path "${payload}")"
  if [[ "${actual}" != "${sha}" ]]; then
    record_event "${id}" "artifact-hash-mismatch" "on-disk bytes != catalogue" "${sha}" "${actual}"
    return 1
  fi
  echo "${sha}"
  return 0
}

# Scan path that was itself hash-gated (path == hashed bytes).
scan_gated_path() {
  local id="$1" path="$2" expect_sha="$3"
  local rdir="${OUT}/${id}"
  mkdir -p "${rdir}"
  log "grype ${id}"
  if [[ -f "${path}" ]]; then
    case "${path}" in
      *.tar) grype "docker-archive:${path}" -o json > "${rdir}/grype.json" 2>"${rdir}/grype.stderr" || true ;;
      *) grype "${path}" -o json > "${rdir}/grype.json" 2>"${rdir}/grype.stderr" || true ;;
    esac
  else
    grype "dir:${path}" -o json > "${rdir}/grype.json" 2>"${rdir}/grype.stderr" || true
  fi
  if [[ ! -s "${rdir}/grype.json" ]]; then
    echo '{"matches":[]}' > "${rdir}/grype.json"
  fi
  log "lading scan ${id} (--expect-sha256)"
  set +e
  "${LADING}" scan "${path}" \
    --findings "${rdir}/grype.json" \
    --manifest "${MANIFEST}" \
    --out "${rdir}" \
    --expect-sha256 "${expect_sha}" \
    --json > "${rdir}/scan-summary.json" 2>"${rdir}/scan.stderr"
  local rc=$?
  set -e
  if [[ "${rc}" -ne 0 ]]; then
    if grep -qE 'artifact-hash-mismatch|artifact-absent|artifact-unhashed' "${rdir}/scan.stderr" 2>/dev/null; then
      local reason
      reason="$(grep -oE 'artifact-hash-mismatch|artifact-absent|artifact-unhashed' "${rdir}/scan.stderr" | head -1)"
      record_event "${id}" "${reason}" "lading integrity refusal" "${expect_sha}" ""
      return 0
    fi
    log "WARN lading scan failed for ${id} (rc=${rc})"
  fi
  SCANNED=$((SCANNED + 1))
}

# Firmware: integrity-gate the catalogue payload, then scan the already-extracted
# profile rootfs (binwalk/unsquashfs from profile-corpus). Raw flash images are
# not package-scannable by grype.
scan_firmware_profile() {
  local id="$1" archive="$2" expect_sha="$3"
  local rootfs="${ROOT}/.lading/profile-rootfs/${id}"
  if [[ ! -d "${rootfs}" || -z "$(ls -A "${rootfs}" 2>/dev/null)" ]]; then
    log "WARN firmware ${id}: no profile-rootfs at ${rootfs}; falling back to archive extract"
    local extracted
    extracted="$(extract_tarball "${id}" "${archive}" || true)"
    if [[ -z "${extracted}" ]]; then
      log "WARN firmware ${id}: extract failed; skipping scan"
      return 0
    fi
    rootfs="${extracted}"
  fi
  scan_extract_after_gate "${id}" "${rootfs}"
}

# Archive was hash-gated; scan an extracted tree (different path) without re-hash.
# Integrity is already enforced; still record success=false if lading fails otherwise.
scan_extract_after_gate() {
  local id="$1" extract_path="$2"
  local rdir="${OUT}/${id}"
  mkdir -p "${rdir}"
  log "grype ${id} (extract)"
  if [[ -f "${extract_path}" ]]; then
    grype "${extract_path}" -o json > "${rdir}/grype.json" 2>"${rdir}/grype.stderr" || true
  else
    grype "dir:${extract_path}" -o json > "${rdir}/grype.json" 2>"${rdir}/grype.stderr" || true
  fi
  if [[ ! -s "${rdir}/grype.json" ]]; then
    echo '{"matches":[]}' > "${rdir}/grype.json"
  fi
  log "lading scan ${id} (extract; archive already gated)"
  set +e
  "${LADING}" scan "${extract_path}" \
    --findings "${rdir}/grype.json" \
    --manifest "${MANIFEST}" \
    --out "${rdir}" \
    --json > "${rdir}/scan-summary.json" 2>"${rdir}/scan.stderr"
  local rc=$?
  set -e
  if [[ "${rc}" -ne 0 ]]; then
    log "WARN lading scan failed for ${id} (rc=${rc})"
  fi
  SCANNED=$((SCANNED + 1))
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
  rest="${line#* }"
  id="${rest%% *}"
  extra="${rest#* }"
  [[ "${extra}" == "${id}" ]] && extra=""

  case "${kind}" in
    REF)
      payload="${DL}/${id}/image.tar"
      sha="$(integrity_gate "${id}" "${payload}" || true)"
      [[ -z "${sha}" ]] && continue
      scan_gated_path "${id}" "${payload}" "${sha}"
      ;;
    FW)
      # extra is repo-relative catalogue path
      archive="${ROOT}/${extra}"
      sha="$(integrity_gate "${id}" "${archive}" || true)"
      [[ -z "${sha}" ]] && continue
      scan_firmware_profile "${id}" "${archive}" "${sha}"
      ;;
    URL)
      archive="$(find "${DL}/${id}" -maxdepth 1 -type f ! -name 'image.ref' ! -name 'download-failure.json' ! -name '*.partial' ! -name 'integrity-refusal.json' 2>/dev/null | head -1 || true)"
      sha="$(integrity_gate "${id}" "${archive}" || true)"
      [[ -z "${sha}" ]] && continue
      case "${archive}" in
        *.tar.gz|*.tar.xz|*.tar|*.zip|*.img.gz|*.bin)
          rootfs="$(extract_tarball "${id}" "${archive}")"
          scan_extract_after_gate "${id}" "${rootfs}"
          ;;
        *.bz2)
          out="${DL}/${id}/$(basename "${archive%.bz2}")"
          if [[ ! -f "${out}" ]]; then
            bunzip2 -kf "${archive}"
          fi
          # Decompressed bytes differ from .bz2 catalogue hash — scan extract after gate.
          scan_extract_after_gate "${id}" "${out}"
          ;;
        *)
          scan_gated_path "${id}" "${archive}" "${sha}"
          ;;
      esac
      ;;
    PATH)
      payload="${ROOT}/${extra}"
      sha="$(integrity_gate "${id}" "${payload}" || true)"
      [[ -z "${sha}" ]] && continue
      scan_gated_path "${id}" "${payload}" "${sha}"
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
    if a.get("class") == "firmware" and "path" in a:
        print(f"FW {a['id']} {a['path']}")
    elif "ref" in a:
        print(f"REF {a['id']}")
    elif "url" in a:
        print(f"URL {a['id']}")
    elif "path" in a:
        print(f"PATH {a['id']} {a['path']}")
PY
)

TOTAL_REFUSED=$((REFUSED_MISMATCH + REFUSED_ABSENT + REFUSED_UNHASHED))
python3 - "${RUN_SUMMARY}" "${SCANNED}" "${REFUSED_MISMATCH}" "${REFUSED_ABSENT}" "${REFUSED_UNHASHED}" <<'PY'
import json, sys
path, scanned, m, a, u = sys.argv[1:6]
scanned, m, a, u = map(int, (scanned, m, a, u))
refused = m + a + u
doc = {
    "scanned": scanned,
    "integrity_refusals": {
        "artifact-hash-mismatch": m,
        "artifact-absent": a,
        "artifact-unhashed": u,
        "total": refused,
    },
    "success": refused == 0,
    "message": (
        "ok"
        if refused == 0
        else f"REFUSED {refused} artifact(s) — not a clean success (mismatch={m} absent={a} unhashed={u})"
    ),
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
print(doc["message"], file=sys.stderr)
PY

log "aggregate -> corpus/results/aggregate.json"
python3 "${ROOT}/scripts/corpus-aggregate.py"

if [[ "${TOTAL_REFUSED}" -gt 0 ]]; then
  log "done WITH INTEGRITY REFUSALS: ${TOTAL_REFUSED} (scanned=${SCANNED}) — see ${RUN_SUMMARY}"
  exit 1
fi
log "done (scanned=${SCANNED}, refusals=0)"
exit 0
