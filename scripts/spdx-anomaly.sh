#!/usr/bin/env bash
# Measure SPDX anomaly: syft spdx-json → trivy sbom yields ~1 package / 0 vulns
# while cyclonedx-json from the same image yields many packages (FINDING-001 S-03).
# Measurement only — does not modify tools or SBOMs beyond generation.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${WORKDIR:-${ROOT}/.lading/spdx-anomaly}"
TRIVY="${TRIVY:-$(command -v trivy)}"
JQ="${JQ:-$(command -v jq)}"

# Prefer explicit binaries; default to both 1.51.0 and 1.22.0 when present.
# Deduplicate by reported Version: so PATH syft is not double-counted.
SYFT_BINARIES=()
declare -A SYFT_SEEN_VER=()
if [[ -n "${SYFT_BINARIES_CSV:-}" ]]; then
  IFS=',' read -r -a SYFT_BINARIES <<< "${SYFT_BINARIES_CSV}"
else
  for cand in \
    "${ROOT}/.lading/tools/syft-1.51.0" \
    "${ROOT}/.lading/tools/syft-1.22.0" \
    "$(command -v syft || true)"
  do
    [[ -n "${cand}" && -x "${cand}" ]] || continue
    ver="$("${cand}" version 2>/dev/null | awk '/^Version:/{print $2; exit}')"
    [[ -n "${ver}" ]] || ver="unknown-${cand}"
    [[ -n "${SYFT_SEEN_VER[${ver}]:-}" ]] && continue
    SYFT_SEEN_VER["${ver}"]=1
    SYFT_BINARIES+=("${cand}")
  done
fi

IMAGES=(
  "nginx-1.25|${ROOT}/corpus/downloads/oci-nginx-1.25/image.tar"
  "debian-bookworm-slim|${ROOT}/corpus/downloads/oci-debian-bookworm-slim/image.tar"
)

log() { echo "[spdx-anomaly] $*" >&2; }
die() { echo "[spdx-anomaly] ERROR: $*" >&2; exit 1; }

command -v jq >/dev/null || die "jq required"
[[ -x "${TRIVY}" ]] || die "trivy not found"
[[ "${#SYFT_BINARIES[@]}" -ge 1 ]] || die "no syft binary found"

mkdir -p "${WORKDIR}"
TRIVY_VER="$("${TRIVY}" version 2>/dev/null | awk '/^Version:/ {print $2; exit}')"
log "trivy ${TRIVY_VER}"
log "syft binaries: ${SYFT_BINARIES[*]}"

# Count packages / PURLs inside the SBOM file (before Trivy).
# CDX: components with a non-empty purl (and total components).
# SPDX: packages with a PACKAGE-MANAGER purl externalRef (and total packages).
count_sbom() {
  local format="$1" file="$2"
  case "${format}" in
    cyclonedx-json)
      jq -c '{
        total: ([.components[]?] | length),
        with_purl: ([.components[]? | select((.purl // "") != "")] | length),
        purls: ([.components[]? | select((.purl // "") != "") | .purl] | unique | length)
      }' "${file}"
      ;;
    spdx-json)
      jq -c '{
        total: ([.packages[]?] | length),
        with_purl: ([
          .packages[]?
          | select(
              any(.externalRefs[]?;
                .referenceType == "purl"
                or .referenceCategory == "PACKAGE-MANAGER"
              )
            )
          ] | length),
        purls: ([
          .packages[]?
          | .externalRefs[]?
          | select(.referenceType == "purl")
          | .referenceLocator
        ] | unique | length)
      }' "${file}"
      ;;
    *) die "unknown format ${format}" ;;
  esac
}

# Unique VulnerabilityIDs + package count as Trivy sees them after ingest.
trivy_scan_stats() {
  local sbom="$1" out="$2"
  if [[ ! -s "${out}" ]]; then
    "${TRIVY}" sbom "${sbom}" --format json --skip-db-update --quiet > "${out}"
  fi
  jq -c '{
    unique_vulns: ([.Results[]?.Vulnerabilities[]?.VulnerabilityID] | unique | length),
    packages: ([.Results[]?.Packages[]?] | length),
    vuln_rows: ([.Results[]?.Vulnerabilities[]?] | length)
  }' "${out}"
}

RESULTS_JSON="${WORKDIR}/results.json"
echo '[]' > "${RESULTS_JSON}"

for syft_bin in "${SYFT_BINARIES[@]}"; do
  syft_ver="$("${syft_bin}" version 2>/dev/null | awk '/^Version:/{print $2; exit}')"
  [[ -n "${syft_ver}" ]] || syft_ver="unknown"
  ver_tag="${syft_ver//./_}"
  log "=== syft ${syft_ver} (${syft_bin}) ==="

  for entry in "${IMAGES[@]}"; do
    IFS='|' read -r name tar <<<"${entry}"
    [[ -s "${tar}" ]] || die "missing image tar: ${tar}"
    img_dir="${WORKDIR}/syft-${ver_tag}/${name}"
    mkdir -p "${img_dir}"

    for fmt in cyclonedx-json spdx-json; do
      ext="cdx.json"
      [[ "${fmt}" == "spdx-json" ]] && ext="spdx.json"
      sbom="${img_dir}/${name}.${ext}"
      scan="${img_dir}/${name}.${ext}.trivy.json"

      if [[ ! -s "${sbom}" ]]; then
        log "syft ${syft_ver} ${name} → ${fmt}"
        "${syft_bin}" scan "docker-archive:${tar}" -o "${fmt}=${sbom}"
      else
        log "reuse ${sbom}"
      fi

      sbom_counts="$(count_sbom "${fmt}" "${sbom}")"
      trivy_counts="$(trivy_scan_stats "${sbom}" "${scan}")"

      # Append row
      jq --arg image "${name}" \
         --arg format "${fmt}" \
         --arg syft "${syft_ver}" \
         --arg trivy "${TRIVY_VER}" \
         --argjson sbom "${sbom_counts}" \
         --argjson trivy_s "${trivy_counts}" \
         '. + [{
            image: $image,
            format: $format,
            syft: $syft,
            trivy: $trivy,
            sbom_total: $sbom.total,
            sbom_with_purl: $sbom.with_purl,
            sbom_unique_purls: $sbom.purls,
            trivy_packages: $trivy_s.packages,
            trivy_unique_vulns: $trivy_s.unique_vulns
          }]' "${RESULTS_JSON}" > "${RESULTS_JSON}.tmp"
      mv "${RESULTS_JSON}.tmp" "${RESULTS_JSON}"
    done
  done
done

# Human-readable 2x2 tables per syft version
{
  echo "=== SPDX anomaly measurement (FINDING-001 S-03) ==="
  echo "workdir: ${WORKDIR}"
  echo "trivy: ${TRIVY_VER}"
  echo
  jq -r '
    group_by(.syft)[]
    | (.[0].syft) as $syft
    | "--- syft \($syft) ---",
      (
        group_by(.image)[]
        | (.[0].image) as $img
        | "",
          "image: \($img)",
          "format              sbom_total  sbom_with_purl  unique_purls  trivy_pkgs  trivy_vulns",
          (
            sort_by(.format)[]
            | "\(.format)\t\(.sbom_total)\t\(.sbom_with_purl)\t\(.sbom_unique_purls)\t\(.trivy_packages)\t\(.trivy_unique_vulns)"
          )
      ),
      ""
  ' "${RESULTS_JSON}"
} | tee "${WORKDIR}/summary.txt"

log "wrote ${RESULTS_JSON}"
exit 0
