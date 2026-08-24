#!/usr/bin/env bash
# Analyse why node:20-bookworm jumps 335 → 4007 when aquasecurity:trivy:SrcName
# is injected into a Syft CycloneDX SBOM (FINDING-001 S-02).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${WORKDIR:-${ROOT}/.lading/node20-analysis}"
IMAGE_TAR="${IMAGE_TAR:-${ROOT}/corpus/downloads/oci-node-20/image.tar}"
SYFT="${SYFT:-$(command -v syft)}"
TRIVY="${TRIVY:-$(command -v trivy)}"
JQ="${JQ:-$(command -v jq)}"

log() { echo "[analyse-node20] $*" >&2; }

die() { echo "[analyse-node20] ERROR: $*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }

need jq
[[ -x "${SYFT}" ]] || die "syft not found"
[[ -x "${TRIVY}" ]] || die "trivy not found"
[[ -s "${IMAGE_TAR}" ]] || die "image tar missing: ${IMAGE_TAR}"

mkdir -p "${WORKDIR}"
cd "${WORKDIR}"

SBOM="node20.cdx.json"
SBOM_SRC="node20-src.cdx.json"
BEFORE="trivy-before.json"
AFTER="trivy-after.json"
SUMMARY="summary.txt"

# --- 1. SBOM + before/after scans ------------------------------------------------
if [[ ! -s "${SBOM}" ]]; then
  log "syft CycloneDX from docker-archive (this can take several minutes)"
  "${SYFT}" scan "docker-archive:${IMAGE_TAR}" -o "cyclonedx-json=${SBOM}"
else
  log "reusing existing ${WORKDIR}/${SBOM}"
fi

if [[ ! -s "${SBOM_SRC}" ]]; then
  log "inject aquasecurity:trivy:SrcName / SrcVersion from syft:metadata:source"
  # Same intervention as FINDING-001 §4.
  jq '.components |= map(
        if .properties then
          . + {properties: (.properties + [
            {name:"aquasecurity:trivy:SrcName",
             value:((.properties[]?|select(.name=="syft:metadata:source")|.value) // .name)},
            {name:"aquasecurity:trivy:SrcVersion", value:.version}
          ])}
        else . end
      )' "${SBOM}" > "${SBOM_SRC}"
else
  log "reusing existing ${WORKDIR}/${SBOM_SRC}"
fi

# Freeze DB so before/after share the same vulnerability database snapshot.
TRIVY_FLAGS=(--format json --skip-db-update --quiet)

if [[ ! -s "${BEFORE}" ]]; then
  log "trivy sbom (before)"
  "${TRIVY}" sbom "${SBOM}" "${TRIVY_FLAGS[@]}" > "${BEFORE}"
else
  log "reusing existing ${WORKDIR}/${BEFORE}"
fi

if [[ ! -s "${AFTER}" ]]; then
  log "trivy sbom (after SrcName injection)"
  "${TRIVY}" sbom "${SBOM_SRC}" "${TRIVY_FLAGS[@]}" > "${AFTER}"
else
  log "reusing existing ${WORKDIR}/${AFTER}"
fi

# --- 2–5. Diff + PURL-type tables ------------------------------------------------
log "analysing unique VulnerabilityIDs and PURL types"
"${JQ}" -n \
  --slurpfile before "${BEFORE}" \
  --slurpfile after "${AFTER}" \
  '
  def vulns:
    [.Results[]? | .Vulnerabilities[]? // empty];

  def id_set:
    [vulns[].VulnerabilityID] | unique;

  def purl_type($purl):
    if ($purl == null or $purl == "") then "unknown"
    elif ($purl | startswith("pkg:")) then ($purl | split("/")[0] | split(":")[1])
    else "unknown"
    end;

  def findings:
    [vulns[] | {
      id: .VulnerabilityID,
      purl: (.PkgIdentifier.PURL // .PkgID // ""),
      type: purl_type(.PkgIdentifier.PURL // "")
    }];

  ($before[0] | id_set) as $before_ids
  | ($after[0] | id_set) as $after_ids
  | ($after_ids - $before_ids) as $new_ids
  | ($before_ids | length) as $n_before
  | ($after_ids | length) as $n_after
  | ($new_ids | length) as $n_new

  # For each newly-surfaced VulnerabilityID, collect PURL types of packages
  # it is reported against in the after scan.
  | ($after[0] | findings) as $after_findings
  | [
      $new_ids[] as $id
      | ($after_findings | map(select(.id == $id)) | map(.type) | unique) as $types
      | {id: $id, types: $types}
    ] as $new_meta

  # Count: each newly-surfaced vuln ID contributes +1 to each of its PURL types
  # (a multi-type ID would increment more than one bucket; track that separately).
  | (
      reduce $new_meta[] as $m ({};
        reduce $m.types[] as $t (.; .[$t] = ((.[$t] // 0) + 1))
      )
    ) as $by_type

  | ($new_meta | map(select((.types | length) > 1)) | length) as $n_multi

  # deb-only before/after unique VulnerabilityID counts
  | (
      [$before[0] | findings[] | select(.type == "deb") | .id] | unique | length
    ) as $deb_before
  | (
      [$after[0] | findings[] | select(.type == "deb") | .id] | unique | length
    ) as $deb_after

  # Also: unique IDs whose ONLY type is npm / deb / other (exclusive classification)
  | (
      reduce $new_meta[] as $m ({deb_only:0, npm_only:0, other_only:0, mixed:0};
        if ($m.types | length) > 1 then .mixed += 1
        elif $m.types == ["deb"] then .deb_only += 1
        elif $m.types == ["npm"] then .npm_only += 1
        else .other_only += 1
        end
      )
    ) as $exclusive

  | {
      unique_vuln_ids: {before: $n_before, after: $n_after, newly_surfaced: $n_new},
      newly_surfaced_by_purl_type: $by_type,
      newly_surfaced_exclusive: $exclusive,
      newly_surfaced_multi_type: $n_multi,
      deb_unique_vuln_ids: {before: $deb_before, after: $deb_after, delta: ($deb_after - $deb_before)}
    }
  ' > analysis.json

# Human-readable summary to stdout (and file)
{
  echo "=== FINDING-001 S-02: node:20-bookworm SrcName injection ==="
  echo "workdir: ${WORKDIR}"
  echo
  echo "Unique VulnerabilityIDs (all PURL types):"
  jq -r '"  before: \(.unique_vuln_ids.before)\n  after:  \(.unique_vuln_ids.after)\n  newly-surfaced (after \\ before): \(.unique_vuln_ids.newly_surfaced)"' analysis.json
  echo
  echo "PURL type -> count of newly-surfaced VulnerabilityIDs"
  echo "(an ID reported on multiple types increments each type):"
  jq -r '.newly_surfaced_by_purl_type | to_entries | sort_by(-.value)[] | "  \(.key)\t\(.value)"' analysis.json
  echo
  echo "Exclusive classification of newly-surfaced IDs:"
  jq -r '.newly_surfaced_exclusive | to_entries[] | "  \(.key)\t\(.value)"' analysis.json
  echo "  multi_type_ids	$(jq -r '.newly_surfaced_multi_type' analysis.json)"
  echo
  echo "deb-type packages only — unique VulnerabilityIDs:"
  jq -r '"  before: \(.deb_unique_vuln_ids.before)\n  after:  \(.deb_unique_vuln_ids.after)\n  delta:  \(.deb_unique_vuln_ids.delta)"' analysis.json
} | tee "${SUMMARY}"

log "wrote ${WORKDIR}/analysis.json and ${SUMMARY}"
exit 0
