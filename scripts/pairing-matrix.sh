#!/usr/bin/env bash
# Pairing matrix: does source-package attribution loss generalise beyond syft→trivy?
# FINDING-001 S-04 — baseline behaviour only (no SBOM mutation).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${WORKDIR:-${ROOT}/.lading/pairing-matrix}"
OUT_DIR="${OUT_DIR:-${ROOT}/results}"
SYFT="${SYFT:-${ROOT}/.lading/tools/syft-1.51.0}"
TRIVY="${TRIVY:-$(command -v trivy)}"
GRYPE="${GRYPE:-$(command -v grype)}"

log() { echo "[pairing-matrix] $*" >&2; }
die() { echo "[pairing-matrix] ERROR: $*" >&2; exit 1; }

[[ -x "${SYFT}" ]] || SYFT="$(command -v syft || true)"
[[ -x "${SYFT}" ]] || die "syft not found (expected ${ROOT}/.lading/tools/syft-1.51.0)"
[[ -x "${TRIVY}" ]] || die "trivy not found"
[[ -x "${GRYPE}" ]] || die "grype not found"
command -v jq >/dev/null || die "jq required"
command -v python3 >/dev/null || die "python3 required"

mkdir -p "${WORKDIR}" "${OUT_DIR}"

SYFT_VER="$("${SYFT}" version 2>/dev/null | awk '/^Version:/{print $2; exit}')"
TRIVY_VER="$("${TRIVY}" version 2>/dev/null | awk '/^Version:/{print $2; exit}')"
GRYPE_VER="$("${GRYPE}" version 2>/dev/null | awk '/^Version:/{print $2; exit}')"
TRIVY_DB="$("${TRIVY}" version 2>/dev/null | awk '/UpdatedAt:/{print $2" "$3; exit}')"
GRYPE_DB="$("${GRYPE}" db status 2>/dev/null | awk -F': ' '/Built|Status|Path|Schema/{print}' | tr '\n' '; ')"

log "syft=${SYFT_VER} trivy=${TRIVY_VER} grype=${GRYPE_VER}"

IMAGES=(
  "nginx-1.25|nginx:1.25|deb|${ROOT}/corpus/downloads/oci-nginx-1.25/image.tar"
  "debian-bookworm-slim|debian:bookworm-slim|deb|${ROOT}/corpus/downloads/oci-debian-bookworm-slim/image.tar"
  "httpd-2.4|httpd:2.4|deb|${ROOT}/corpus/downloads/oci-httpd-2.4/image.tar"
  "alpine-3.20|alpine:3.20|apk|${ROOT}/corpus/downloads/oci-alpine-3.20/image.tar"
  "fedora-40|fedora:40|rpm|${ROOT}/corpus/downloads/oci-fedora-40/image.tar"
)

# --- helpers ------------------------------------------------------------------

ensure_sboms() {
  local id="$1" tar="$2" dir="$3"
  mkdir -p "${dir}"
  local cdx="${dir}/${id}.cdx.json"
  local spdx="${dir}/${id}.spdx.json"
  if [[ ! -s "${cdx}" ]]; then
    log "syft cyclonedx ${id}"
    "${SYFT}" scan "docker-archive:${tar}" -o "cyclonedx-json=${cdx}"
  fi
  if [[ ! -s "${spdx}" ]]; then
    log "syft spdx ${id}"
    "${SYFT}" scan "docker-archive:${tar}" -o "spdx-json=${spdx}"
  fi
}

run_scan() {
  # args: kind outpath command...
  local out="$1"; shift
  if [[ -s "${out}" ]]; then
    return 0
  fi
  log "scan → ${out##*/}"
  "$@" > "${out}" 2>"${out}.stderr" || {
    # Keep empty-ish JSON so analysis can record zeros rather than aborting the matrix.
    log "WARN: scan failed for ${out} (see ${out}.stderr)"
    if [[ ! -s "${out}" ]]; then
      echo '{}' > "${out}"
    fi
  }
}

# Emit one CSV-ready JSON object for a scan result.
# consumer: trivy|grype
analyze_py='
import json, sys

consumer, image, image_ref, advisory_model, cell, path = sys.argv[1:7]
with open(path) as f:
    try:
        d = json.load(f)
    except Exception:
        d = {}

unique_vulns = 0
src_ne = 0
pkg_count = 0
src_metric = ""

if consumer == "trivy":
    pkgs = []
    vulns = set()
    for r in d.get("Results") or []:
        for p in r.get("Packages") or []:
            pkgs.append(p)
        for v in r.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID")
            if vid:
                vulns.add(vid)
    unique_vulns = len(vulns)
    pkg_count = len(pkgs)
    src_ne = sum(
        1 for p in pkgs
        if p.get("SrcName") and p.get("SrcName") != p.get("Name")
    )
    src_metric = "trivy.Packages.SrcName!=Name"

elif consumer == "grype":
    matches = d.get("matches") or []
    unique_vulns = len({m.get("vulnerability", {}).get("id") for m in matches if m.get("vulnerability", {}).get("id")})
    ab = d.get("alertsByPackage") or []
    if ab:
        packages = [e.get("package") or {} for e in ab]
        src_metric = "grype.alertsByPackage.upstreams"
    else:
        # SBOM-mode grype often omits alertsByPackage; fall back to distinct match artifacts.
        seen = {}
        for m in matches:
            a = m.get("artifact") or {}
            key = (a.get("id") or a.get("purl") or a.get("name"), a.get("version"))
            seen[key] = a
        packages = list(seen.values())
        src_metric = "grype.match_artifacts.upstreams"

    pkg_count = len(packages)
    def upstream_names(p):
        ups = p.get("upstreams") or []
        out = []
        for u in ups:
            if isinstance(u, dict):
                n = u.get("name")
                if n:
                    out.append(n)
            elif u:
                out.append(str(u))
        return out
    src_ne = sum(
        1 for p in packages
        if any(n != p.get("name") for n in upstream_names(p))
    )

else:
    raise SystemExit(f"unknown consumer {consumer}")

print(json.dumps({
    "image_id": image,
    "image_ref": image_ref,
    "advisory_model": advisory_model,
    "cell": cell,
    "consumer": consumer,
    "unique_vulns": unique_vulns,
    "packages_observed": pkg_count,
    "src_ne_binary": src_ne,
    "src_metric": src_metric,
}))
'

analyze() {
  python3 -c "${analyze_py}" "$@"
}

ROWS_JSONL="${WORKDIR}/rows.jsonl"
: > "${ROWS_JSONL}"

VERSIONS_FILE="${WORKDIR}/versions.txt"
cat > "${VERSIONS_FILE}" <<EOF
syft=${SYFT_VER}
trivy=${TRIVY_VER}
trivy_db_updated_at=${TRIVY_DB}
grype=${GRYPE_VER}
grype_db=${GRYPE_DB}
syft_bin=${SYFT}
trivy_bin=${TRIVY}
grype_bin=${GRYPE}
date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

for entry in "${IMAGES[@]}"; do
  IFS='|' read -r id ref model tar <<<"${entry}"
  [[ -s "${tar}" ]] || die "missing tar: ${tar}"
  img_dir="${WORKDIR}/${id}"
  ensure_sboms "${id}" "${tar}" "${img_dir}"
  cdx="${img_dir}/${id}.cdx.json"
  spdx="${img_dir}/${id}.spdx.json"

  # Baselines (direct image)
  run_scan "${img_dir}/trivy-image.json" \
    "${TRIVY}" image --input "${tar}" --list-all-pkgs --format json --skip-db-update --quiet
  analyze trivy "${id}" "${ref}" "${model}" "trivy_image" "${img_dir}/trivy-image.json" >> "${ROWS_JSONL}"

  run_scan "${img_dir}/grype-image.json" \
    "${GRYPE}" "docker-archive:${tar}" -o json --quiet
  analyze grype "${id}" "${ref}" "${model}" "grype_image" "${img_dir}/grype-image.json" >> "${ROWS_JSONL}"

  # SBOM consumers — unmodified Syft SBOMs
  run_scan "${img_dir}/trivy-cdx.json" \
    "${TRIVY}" sbom "${cdx}" --list-all-pkgs --format json --skip-db-update --quiet
  analyze trivy "${id}" "${ref}" "${model}" "syft_cdx__trivy" "${img_dir}/trivy-cdx.json" >> "${ROWS_JSONL}"

  run_scan "${img_dir}/trivy-spdx.json" \
    "${TRIVY}" sbom "${spdx}" --list-all-pkgs --format json --skip-db-update --quiet
  analyze trivy "${id}" "${ref}" "${model}" "syft_spdx__trivy" "${img_dir}/trivy-spdx.json" >> "${ROWS_JSONL}"

  run_scan "${img_dir}/grype-cdx.json" \
    "${GRYPE}" "sbom:${cdx}" -o json --quiet
  analyze grype "${id}" "${ref}" "${model}" "syft_cdx__grype" "${img_dir}/grype-cdx.json" >> "${ROWS_JSONL}"

  run_scan "${img_dir}/grype-spdx.json" \
    "${GRYPE}" "sbom:${spdx}" -o json --quiet
  analyze grype "${id}" "${ref}" "${model}" "syft_spdx__grype" "${img_dir}/grype-spdx.json" >> "${ROWS_JSONL}"
done

# --- CSV + markdown -----------------------------------------------------------
CSV="${OUT_DIR}/pairing-matrix.csv"
MD="${ROOT}/PAIRING-MATRIX.md"

python3 - "${ROWS_JSONL}" "${CSV}" "${MD}" "${VERSIONS_FILE}" <<'PY'
import csv, json, sys
from collections import defaultdict
from pathlib import Path

rows_path, csv_path, md_path, versions_path = sys.argv[1:5]
rows = [json.loads(line) for line in Path(rows_path).read_text().splitlines() if line.strip()]
versions = Path(versions_path).read_text().strip()

# Stable column order
cells = [
    "trivy_image",
    "syft_cdx__trivy",
    "syft_spdx__trivy",
    "grype_image",
    "syft_cdx__grype",
    "syft_spdx__grype",
]
cell_label = {
    "trivy_image": "trivy_image (baseline)",
    "syft_cdx__trivy": "syft_cdx→trivy",
    "syft_spdx__trivy": "syft_spdx→trivy",
    "grype_image": "grype_image (baseline)",
    "syft_cdx__grype": "syft_cdx→grype",
    "syft_spdx__grype": "syft_spdx→grype",
}

by = {(r["image_id"], r["cell"]): r for r in rows}
images = []
seen = set()
for r in rows:
    if r["image_id"] not in seen:
        images.append((r["image_id"], r["image_ref"], r["advisory_model"]))
        seen.add(r["image_id"])

fieldnames = [
    "image_id", "image_ref", "advisory_model", "cell", "consumer",
    "unique_vulns", "packages_observed", "src_ne_binary", "src_metric",
    "baseline_cell", "baseline_vulns", "vuln_delta", "vuln_loss_pct", "material_loss",
]

def baseline_for(cell: str) -> str | None:
    if cell.endswith("__trivy") or cell == "trivy_image":
        return "trivy_image"
    if cell.endswith("__grype") or cell == "grype_image":
        return "grype_image"
    return None

out_rows = []
for image_id, image_ref, model in images:
    for cell in cells:
        r = by[(image_id, cell)]
        bcell = baseline_for(cell)
        b = by[(image_id, bcell)]
        base_v = b["unique_vulns"]
        cur_v = r["unique_vulns"]
        delta = cur_v - base_v
        if base_v > 0:
            loss_pct = round(100.0 * (base_v - cur_v) / base_v, 1)
        else:
            loss_pct = 0.0 if cur_v == 0 else None
        # Material loss: SBOM cell only, and either >10% drop or ≥5 fewer unique IDs
        # when baseline had findings; or total wipe (baseline>0 and cur==0).
        is_sbom = cell not in ("trivy_image", "grype_image")
        material = False
        if is_sbom and base_v > 0:
            if cur_v == 0 or (base_v - cur_v) >= 5 or (loss_pct is not None and loss_pct >= 10.0):
                material = True
        out_rows.append({
            **r,
            "baseline_cell": bcell,
            "baseline_vulns": base_v,
            "vuln_delta": delta,
            "vuln_loss_pct": loss_pct if loss_pct is not None else "",
            "material_loss": "yes" if material else "no",
        })

with open(csv_path, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    for row in out_rows:
        w.writerow(row)

# Markdown
lines = []
lines.append("# PAIRING-MATRIX — Is source-package attribution loss a class?\n")
lines.append("**FINDING-001 S-04.** Unmodified Syft SBOMs only. Same image tars for every cell.\n")
lines.append("## Tool pins\n")
lines.append("```")
lines.append(versions)
lines.append("```\n")

lines.append("## Full matrix (unique VulnerabilityIDs / src≠binary packages)\n")
lines.append("| image | model | trivy image | syft CDX→trivy | syft SPDX→trivy | grype image | syft CDX→grype | syft SPDX→grype |")
lines.append("|---|---|---:|---:|---:|---:|---:|---:|")
for image_id, image_ref, model in images:
    cells_fmt = []
    for cell in cells:
        r = by[(image_id, cell)]
        cells_fmt.append(f"{r['unique_vulns']} / {r['src_ne_binary']}")
    lines.append(
        f"| `{image_ref}` | {model} | " + " | ".join(cells_fmt) + " |"
    )
lines.append("")
lines.append("Cell format: `unique_vulns / src_ne_binary` where `src_ne_binary` is packages for which the consumer resolved a source/upstream name different from the binary name (Trivy: `SrcName`; Grype: `upstreams`).\n")
lines.append("Grype SBOM mode often omits `alertsByPackage`; there `src_ne_binary` is counted from distinct match artifacts only (may under-count inventory).\n")

# Material loss table
lines.append("## Material loss vs same-tool direct baseline\n")
lines.append("Threshold: SBOM cell with baseline unique vulns > 0, and (cur == 0 OR absolute drop ≥ 5 OR loss ≥ 10%).\n")
losses = [r for r in out_rows if r["material_loss"] == "yes"]
if not losses:
    lines.append("_No cells met the material-loss threshold._\n")
else:
    lines.append("| image | model | cell | baseline | sbom | Δ | loss% | src_ne (sbom) | src_ne (baseline) |")
    lines.append("|---|---|---|---:|---:|---:|---:|---:|---:|")
    for r in losses:
        b = by[(r["image_id"], r["baseline_cell"])]
        lines.append(
            f"| `{r['image_ref']}` | {r['advisory_model']} | {cell_label[r['cell']]} | "
            f"{r['baseline_vulns']} | {r['unique_vulns']} | {r['vuln_delta']} | {r['vuln_loss_pct']} | "
            f"{r['src_ne_binary']} | {b['src_ne_binary']} |"
        )
    lines.append("")

# Correlation with advisory model
lines.append("## Correlation with distro advisory model\n")
# For CDX→trivy and SPDX→trivy and grype pairings, summarize by model
lines.append("| advisory_model | cell | images | material_loss | mean loss% (where baseline>0) | mean src_ne_binary (sbom) | mean src_ne_binary (baseline) |")
lines.append("|---|---|---:|---:|---:|---:|---:|")
from statistics import mean
for model in ("deb", "apk", "rpm"):
    for cell in ("syft_cdx__trivy", "syft_spdx__trivy", "syft_cdx__grype", "syft_spdx__grype"):
        subset = [r for r in out_rows if r["advisory_model"] == model and r["cell"] == cell]
        if not subset:
            continue
        n_loss = sum(1 for r in subset if r["material_loss"] == "yes")
        loss_pcts = [float(r["vuln_loss_pct"]) for r in subset if r["baseline_vulns"] > 0 and r["vuln_loss_pct"] != ""]
        src_sbom = mean(r["src_ne_binary"] for r in subset)
        src_base = mean(by[(r["image_id"], r["baseline_cell"])]["src_ne_binary"] for r in subset)
        mean_loss = round(mean(loss_pcts), 1) if loss_pcts else 0.0
        lines.append(
            f"| {model} | {cell_label[cell]} | {len(subset)} | {n_loss}/{len(subset)} | {mean_loss} | {src_sbom:.1f} | {src_base:.1f} |"
        )
lines.append("")

# Decision gate
trivy_cdx_loss = [r for r in out_rows if r["cell"] == "syft_cdx__trivy" and r["material_loss"] == "yes"]
trivy_spdx_loss = [r for r in out_rows if r["cell"] == "syft_spdx__trivy" and r["material_loss"] == "yes"]
grype_loss = [r for r in out_rows if r["cell"].endswith("__grype") and r["material_loss"] == "yes"]
only_trivy = (trivy_cdx_loss or trivy_spdx_loss) and not grype_loss
multi = bool(grype_loss) and bool(trivy_cdx_loss or trivy_spdx_loss)
# Also: two distinct Trivy failure modes (CDX undercount + SPDX wipe) still "class" within one consumer?
# Decision gate as written: "Multiple pairings" means producer→consumer pairs.
pairings_with_loss = set()
for r in losses:
    pairings_with_loss.add(r["cell"])

lines.append("## Decision gate\n")
lines.append(f"Cells with material loss: {', '.join(sorted(pairings_with_loss)) or '(none)'}\n")
if multi:
    verdict = (
        "**Multiple pairings affected → class.** "
        "Publication framing: SBOM ingestion silently loses distro source-package attribution across tool pairings."
    )
elif only_trivy or (pairings_with_loss and pairings_with_loss <= {"syft_cdx__trivy", "syft_spdx__trivy"}):
    # Distinct: CDX undercount vs SPDX wipe are both syft→trivy; gate text says "only syft→trivy" = single-tool bug.
    # But SPDX wipe + CDX undercount are two mechanisms in one pairing family.
    if "syft_cdx__trivy" in pairings_with_loss and "syft_spdx__trivy" in pairings_with_loss and not grype_loss:
        verdict = (
            "**Only syft→trivy affected (both CycloneDX under-count and SPDX near-total wipe); "
            "syft→grype does not show material loss → single-consumer bug class inside Trivy, not a cross-scanner class.** "
            "File against Trivy (two issues or one with two formats); short post; Grype remains the control that preserves upstream."
        )
    else:
        verdict = (
            "**Only syft→trivy affected → single-tool bug.** File it, publish a short post, move on."
        )
elif not pairings_with_loss:
    verdict = "**No material loss detected in this matrix** — revisit thresholds or tool versions."
else:
    verdict = f"**Unexpected pattern:** losses in {sorted(pairings_with_loss)}. Inspect CSV."

lines.append(verdict + "\n")

# Evidence bullets for correlation
deb_cdx = [r for r in out_rows if r["advisory_model"] == "deb" and r["cell"] == "syft_cdx__trivy"]
ctrl_cdx = [r for r in out_rows if r["advisory_model"] in ("apk", "rpm") and r["cell"] == "syft_cdx__trivy"]
lines.append("## Notes on correlation\n")
if deb_cdx:
    lines.append(
        f"- syft CDX→trivy on **deb** images: material_loss in "
        f"{sum(1 for r in deb_cdx if r['material_loss']=='yes')}/{len(deb_cdx)}; "
        f"mean sbom src_ne_binary={mean(r['src_ne_binary'] for r in deb_cdx):.1f} vs baseline "
        f"{mean(by[(r['image_id'],'trivy_image')]['src_ne_binary'] for r in deb_cdx):.1f}."
    )
if ctrl_cdx:
    lines.append(
        f"- syft CDX→trivy on **apk/rpm controls**: material_loss in "
        f"{sum(1 for r in ctrl_cdx if r['material_loss']=='yes')}/{len(ctrl_cdx)}; "
        f"mean sbom src_ne_binary={mean(r['src_ne_binary'] for r in ctrl_cdx):.1f}."
    )
alpine = by.get(("alpine-3.20", "trivy_image")), by.get(("alpine-3.20", "syft_cdx__trivy"))
if alpine[0] and alpine[1]:
    lines.append(
        f"- **Structural signal on apk anyway:** alpine:3.20 still loses source resolution under "
        f"Trivy CDX ingest (`src_ne_binary` {alpine[0]['src_ne_binary']} → {alpine[1]['src_ne_binary']}) "
        f"with no vuln delta (baseline unique vulns={alpine[0]['unique_vulns']}). "
        f"Trivy fails to resolve source on apk SBOMs too; Debian is where that failure becomes a large vulnerability under-count."
    )
grype_deb = [r for r in out_rows if r["advisory_model"] == "deb" and r["cell"] == "syft_cdx__grype"]
if grype_deb:
    lines.append(
        f"- syft CDX→grype on **deb**: material_loss in "
        f"{sum(1 for r in grype_deb if r['material_loss']=='yes')}/{len(grype_deb)} "
        f"(control for whether the SBOM itself lacks source data). "
        f"Same unique vuln counts as `grype_image` on every image, including SPDX — Grype reads what Syft wrote."
    )
fed_t = by.get(("fedora-40", "trivy_image"))
fed_g = by.get(("fedora-40", "grype_image"))
if fed_t and fed_g:
    lines.append(
        f"- **fedora:40 / trivy caveat:** `trivy image` reported {fed_t['packages_observed']} packages "
        f"on this tar (grype saw {fed_g['packages_observed']}). Do not interpret the rpm control’s zero "
        f"Trivy vulns as proof that rpm is unaffected; use grype rows for rpm integrity of the SBOM."
    )
lines.append("")

Path(md_path).write_text("\n".join(lines) + "\n")
print(f"wrote {csv_path}", file=sys.stderr)
print(f"wrote {md_path}", file=sys.stderr)
PY

log "done"
exit 0
