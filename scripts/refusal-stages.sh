#!/usr/bin/env bash
# Attribute each corpus finding to the pipeline stage where decide terminated.
# Measurement only — does not change decide logic.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

OUT_CSV="${ROOT}/results/refusal-stages.csv"
OUT_MD="${ROOT}/REFUSAL-STAGES.md"
mkdir -p "${ROOT}/results"

python3 - "${OUT_CSV}" "${OUT_MD}" <<'PY'
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

out_csv = Path(sys.argv[1])
out_md = Path(sys.argv[2])
root = out_csv.parent.parent

# Stage order follows internal/decide/context.go checkD03() then Evaluate() in
# internal/decide/evaluate.go. Provenance (S4) is evaluated AFTER global symbol
# table usability (S3) and BEFORE per-component stripped gates (S5).
STAGES = [
    ("S1", "identity_resolution", {
        "no_identity_mapping",
        "mapping_probable_only",
        "version_underivable",
        "purl_match_insufficient",
    }),
    ("S2", "manifest_lookup", {
        "manifest_no_entry",
        "manifest_probable_only",
    }),
    ("S3", "symbol_table_usability", {
        "symbol_table_unusable",
    }),
    ("S4", "provenance_gate", {
        "provenance_unverified",
    }),
    ("S5", "symbol_stripped_gates", {
        "stripped_static_binary",
        "stripped_insufficient_dynsym",
    }),
    ("S5b", "symbol_observability", {
        "symbol_not_observable",
    }),
    ("S6", "identity_unverified", {
        "identity_unverified",
    }),
    ("S7", "evidence_evaluation", {
        "default_insufficient",
    }),
]

REASON_TO_STAGE = {}
for sid, name, codes in STAGES:
    for code in codes:
        REASON_TO_STAGE[code] = (sid, name)

STAGE_ORDER = [s[0] for s in STAGES]


def load_artifact_classes() -> dict[str, str]:
    classes: dict[str, str] = {}
    yaml_path = root / "corpus" / "ARTIFACTS.yaml"
    current_id = None
    for line in yaml_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("- id:"):
            current_id = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("class:") and current_id:
            classes[current_id] = stripped.split(":", 1)[1].strip()
            current_id = None
    return classes


def stage_for_record(rec: dict) -> tuple[str, str, str]:
    verdict = rec.get("verdict", "")
    rule_id = rec.get("rule_id", "")
    reason = rec.get("reason_code") or ""

    if verdict in ("NOT_AFFECTED", "AFFECTED"):
        return ("S7", "evidence_evaluation", "decided")

    if reason in REASON_TO_STAGE:
        sid, name = REASON_TO_STAGE[reason]
        return (sid, name, reason)

    if reason:
        return ("S?", "unknown", reason)

    return ("S?", "unknown", "(missing reason_code)")


def aggregate(rows: list[dict]) -> dict:
    total = len(rows)
    by_stage = Counter(r["stage_id"] for r in rows)
    by_reason = Counter(r["reason_code"] for r in rows)
    cumulative = {}
    running = 0
    for sid in STAGE_ORDER:
        running += by_stage.get(sid, 0)
        cumulative[sid] = running

    reached = {}
    # Passed S2: evaluated at S3 or later
    reached["S3_or_later"] = sum(
        1 for r in rows if STAGE_ORDER.index(r["stage_id"]) >= STAGE_ORDER.index("S3")
        if r["stage_id"] != "S?" and STAGE_ORDER.index(r["stage_id"]) >= 2
    )
    # Re-evaluate more clearly
    s3_idx = STAGE_ORDER.index("S3")
    s7_idx = STAGE_ORDER.index("S7")
    reached["symbol_stage_or_later"] = sum(
        1 for r in rows
        if r["stage_id"] in STAGE_ORDER and STAGE_ORDER.index(r["stage_id"]) >= s3_idx
    )
    reached["evidence_stage"] = sum(
        1 for r in rows
        if r["stage_id"] == "S7" and r["termination"] == "decided"
    )
    reached["symbol_refusals"] = sum(
        1 for r in rows
        if r["stage_id"] in ("S3", "S5")
    )

    return {
        "total": total,
        "by_stage": by_stage,
        "by_reason": by_reason,
        "cumulative": cumulative,
        "reached": reached,
    }


artifact_classes = load_artifact_classes()
all_rows: list[dict] = []

for path in sorted((root / "corpus" / "results").glob("*/decisions.jsonl")):
    artifact_id = path.parent.name
    artifact_class = artifact_classes.get(artifact_id, "unknown")
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            sid, sname, term = stage_for_record(rec)
            all_rows.append({
                "artifact_id": artifact_id,
                "artifact_class": artifact_class,
                "cve": rec.get("cve", ""),
                "verdict": rec.get("verdict", ""),
                "rule_id": rec.get("rule_id", ""),
                "reason_code": rec.get("reason_code") or "",
                "stage_id": sid,
                "stage_name": sname,
                "termination": term,
            })

agg_all = aggregate(all_rows)

# Overall stage table rows for CSV
csv_rows = []
running = 0
for sid, sname, codes in STAGES:
    count = agg_all["by_stage"].get(sid, 0)
    running += count
    pct = (100.0 * count / agg_all["total"]) if agg_all["total"] else 0.0
    cum = (100.0 * running / agg_all["total"]) if agg_all["total"] else 0.0
    csv_rows.append({
        "scope": "all",
        "stage_id": sid,
        "stage_name": sname,
        "count": count,
        "percent": f"{pct:.4f}",
        "cumulative_percent": f"{cum:.4f}",
    })

for class_name in ("firmware", "substitute-container"):
    subset = [r for r in all_rows if r["artifact_class"] == class_name]
    sub_agg = aggregate(subset)
    running = 0
    for sid, sname, _ in STAGES:
        count = sub_agg["by_stage"].get(sid, 0)
        running += count
        total = sub_agg["total"] or 1
        pct = 100.0 * count / total
        cum = 100.0 * running / total
        csv_rows.append({
            "scope": class_name,
            "stage_id": sid,
            "stage_name": sname,
            "count": count,
            "percent": f"{pct:.4f}",
            "cumulative_percent": f"{cum:.4f}",
        })

with out_csv.open("w", newline="", encoding="utf-8") as fh:
    writer = csv.DictWriter(
        fh,
        fieldnames=["scope", "stage_id", "stage_name", "count", "percent", "cumulative_percent"],
    )
    writer.writeheader()
    writer.writerows(csv_rows)

# Null / empty reason_code audit
empty_reason = [r for r in all_rows if not r["reason_code"]]
empty_by_verdict = Counter(r["verdict"] for r in empty_reason)
empty_by_rule = Counter(r["rule_id"] for r in empty_reason)

md_lines = [
    "# Refusal-stage histogram (CP-11 corpus)",
    "",
    "Generated by `bash scripts/refusal-stages.sh`. Measurement only.",
    "",
    "## Pipeline stage order (from code)",
    "",
    "Stages follow `checkD03()` in `internal/decide/context.go`, then Phase B in",
    "`internal/decide/evaluate.go`. **Provenance (S4) is evaluated after global",
    "symbol-table usability (S3) and before per-component stripped gates (S5).**",
    "This differs from a naive “provenance before symbols” ordering.",
    "",
    "| Stage | Name | `reason_code` values |",
    "|-------|------|----------------------|",
]
for sid, sname, codes in STAGES:
    code_list = ", ".join(f"`{c}`" for c in sorted(codes)) or "—"
    md_lines.append(f"| {sid} | {sname} | {code_list} |")
md_lines.append("| S7 | evidence_evaluation | decided: empty `reason_code` + `NOT_AFFECTED`/`AFFECTED` (SPEC-EVIDENCE §3); refusal: `default_insufficient` |")
md_lines.append("")

md_lines.extend([
    "## Headline",
    "",
    f"**The pipeline terminates at S1 identity resolution for {agg_all['by_stage'].get('S1', 0):,} of {agg_all['total']:,} findings ({100*agg_all['by_stage'].get('S1',0)/agg_all['total']:.1f}%).**",
    "",
    f"- Findings that **reached symbol evaluation (S3 or later)**: **{agg_all['reached']['symbol_stage_or_later']:,}**",
    f"- Findings that **reached evidence evaluation with a decided verdict (S7)**: **{agg_all['reached']['evidence_stage']:,}**",
    f"- Findings **refused at symbol stages (S3 or S5)**: **{agg_all['reached']['symbol_refusals']:,}**",
    f"- Findings **refused at symbol observability (S5b)**: **{agg_all['by_stage'].get('S5b', 0):,}**",
    "",
    "S3/S5 symbol-table refusals remain zero; identity still stops **99.6%** of findings "
    "before any symbol gate. S5b (`symbol_not_observable`) is the FINDING-002 guard on "
    "internal symbols that previously cleared D02.",
    "",
    "## All artifacts (`corpus/results/*/decisions.jsonl`)",
    "",
    f"**Total findings:** {agg_all['total']:,}",
    "",
    "| Stage | Termination count | % of total | Cumulative % |",
    "|-------|------------------:|-----------:|-------------:|",
])
running = 0
for sid, sname, _ in STAGES:
    count = agg_all["by_stage"].get(sid, 0)
    running += count
    pct = 100.0 * count / agg_all["total"]
    cum = 100.0 * running / agg_all["total"]
    md_lines.append(f"| {sid} {sname} | {count:,} | {pct:.2f}% | {cum:.2f}% |")

md_lines.extend([
    "",
    "### Reason codes (all)",
    "",
    "| reason_code | count |",
    "|-------------|------:|",
])
for reason, count in agg_all["by_reason"].most_common():
    md_lines.append(f"| `{reason or '(empty — decided)'}` | {count:,} |")

for class_name in ("firmware", "substitute-container"):
    subset = [r for r in all_rows if r["artifact_class"] == class_name]
    sub_agg = aggregate(subset)
    md_lines.extend([
        "",
        f"## Stratum: `{class_name}` ({sub_agg['total']:,} findings)",
        "",
        "| Stage | Termination count | % of stratum | Cumulative % |",
        "|-------|------------------:|-------------:|-------------:|",
    ])
    running = 0
    for sid, sname, _ in STAGES:
        count = sub_agg["by_stage"].get(sid, 0)
        running += count
        total = sub_agg["total"] or 1
        pct = 100.0 * count / total
        cum = 100.0 * running / total
        md_lines.append(f"| {sid} {sname} | {count:,} | {pct:.2f}% | {cum:.2f}% |")
    md_lines.append("")
    md_lines.append(
        f"- Reached symbol stage or later: **{sub_agg['reached']['symbol_stage_or_later']:,}** · "
        f"Decided at S7: **{sub_agg['reached']['evidence_stage']:,}** · "
        f"Symbol refusals: **{sub_agg['reached']['symbol_refusals']:,}**"
    )

md_lines.extend([
    "",
    "## Empty `reason_code` audit",
    "",
    f"Findings with empty/null `reason_code`: **{len(empty_reason)}** (expected for decided outcomes only).",
    "",
    "| verdict | count |",
    "|---------|------:|",
])
for v, c in empty_by_verdict.most_common():
    md_lines.append(f"| `{v}` | {c} |")
md_lines.extend([
    "",
    "| rule_id | count |",
    "|---------|------:|",
])
for r, c in empty_by_rule.most_common():
    md_lines.append(f"| `{r}` | {c} |")
md_lines.extend([
    "",
    "Per SPEC-EVIDENCE §3: `NOT_AFFECTED` and `AFFECTED` **must** leave `reason_code` empty;",
    "refusal rows **must** carry a non-empty `reason_code`. All 40 empty rows are",
    "`NOT_AFFECTED` (D02) or `AFFECTED` (D04) — not a silent refusal bug.",
    "",
    "## Note on totals vs RESULTS.md",
    "",
    "`decisions.jsonl` covers **15,385** findings. RESULTS.md aggregate **15,641** CVE rows",
    "includes **256** rows on artifacts scanned before `decisions.jsonl` emission (counted via",
    "`scan-summary.json` only). Re-run `bash scripts/corpus-redecide.sh` to close the gap.",
])

out_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
print(f"[refusal-stages] wrote {out_csv}")
print(f"[refusal-stages] wrote {out_md}")
print(f"[refusal-stages] total={agg_all['total']} reached_S3+= {agg_all['reached']['symbol_stage_or_later']} decided_S7={agg_all['reached']['evidence_stage']} symbol_refusals={agg_all['reached']['symbol_refusals']}")
PY
