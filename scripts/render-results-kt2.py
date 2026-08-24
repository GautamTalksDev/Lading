#!/usr/bin/env python3
"""Render RESULTS.md §3 (KT-2) from corpus/results/cp11-metrics.json."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
METRICS = ROOT / "corpus" / "results" / "cp11-metrics.json"
RESULTS = ROOT / "RESULTS.md"

SECTION_START = "## 3. KT-2 — Ground truth soundness"
SECTION_END = "## 4. Refusal breakdown (reason codes)"


def fmt_pct(x: float | None) -> str:
    if x is None:
        return "—"
    return f"{x:.3f}"


def render_kt2(kt2: dict) -> str:
    lines = [
        SECTION_START,
        "",
        "**Evidence set:** `corpus/groundtruth/real-100.yaml` (100 real pipeline statements; synthetic `statements.yaml` is unit-test only).",
        "",
        "**Frozen pipeline snapshot (pre-guard):** Each row's `pipeline_verdict` is copied from the S-15 "
        "`decisions.jsonl` emitted **before** the FINDING-002 `symbol_not_observable` guard. KT-2 scores "
        "whether those clearances were **sound when emitted** — not whether the post-fix engine would "
        "re-emit them. Rescoring `real-100.yaml` against the guarded instrument would test a different "
        "pipeline in response to the finding and void the pre-registered kill test. The guard is reported "
        "separately under §2 (post-guard re-decide: **0** `NOT_AFFECTED`, **5** `AFFECTED`, **0.032%** decided).",
        "",
    ]

    if not kt2.get("evaluable"):
        empty = kt2.get("empty_labels", 100)
        total = kt2.get("label_count", 100)
        lines.extend([
            f"**Hand labels:** **{empty}/{total} `human_label` fields empty** — KT-2 cannot be scored until CP-B1 completes.",
            "",
            "| Metric | Value |",
            "|--------|------:|",
            "| Precision per reason code | *pending labels* |",
            "| Recall per reason code | *pending labels* |",
            "| Pipeline–human agreement | *pending labels* |",
            "| **False `not_affected`** | *pending labels* |",
            "",
            "**KT-2: NOT EVALUABLE** — zero hand labels present; the pre-registered zero-false-`not_affected` bar has not been tested on real corpus statements.",
            "",
            "After labeling (`corpus/groundtruth/real-100.yaml`), run:",
            "",
            "```bash",
            "go test ./corpus/groundtruth/ -run TestKT2 -v",
            "bash scripts/rederive-results.sh",
            "grep -nE 'KT-2: (PASS|FAIL)' RESULTS.md",
            "```",
            "",
        ])
        return "\n".join(lines)

    false_na = int(kt2.get("false_not_affected", 0))
    total = kt2.get("label_count", 100)
    empty = kt2.get("empty_labels", 0)
    full = kt2.get("full_evaluable", empty == 0)

    if full:
        lines.append(
            f"**Hand labels:** **{total}/{total}** filled (`seed: {kt2.get('seed', 20260824)}`)."
        )
        if false_na >= 1:
            lines.extend([
                "",
                f"**Supporting analysis:** [FINDING-002.md](FINDING-002.md) — measured soundness failure on internal OpenSSL symbols (35 corpus D02 clearances; 22× CVE-2026-14456, 9× CVE-2026-42767, 4× CVE-2026-45445).",
            ])
    else:
        na_l = kt2.get("not_affected_labeled", 0)
        na_t = kt2.get("not_affected_total", 20)
        lines.extend([
            f"**Hand labels:** **{total - empty}/{total}** filled (`seed: {kt2.get('seed', 20260824)}`). "
            f"Soundness subset complete: **{na_l}/{na_t}** pipeline `NOT_AFFECTED` rows hand-labeled; "
            f"**{empty}** refusal rows pending CP-B1 (precision/recall per `reason_code`).",
            "",
            f"**Supporting analysis:** [FINDING-002.md](FINDING-002.md) — measured soundness failure on internal OpenSSL symbols (35 corpus D02 clearances; 22× CVE-2026-14456, 9× CVE-2026-42767, 4× CVE-2026-45445).",
        ])
    lines.append("")

    if false_na >= 1:
        lines.extend([
            f"**KT-2 is FAIL (unsound):** the pipeline emitted **{false_na}** false `not_affected` clearance(s) in the hand-labeled soundness subset — each listed below; one false clearance violates the pre-registered kill criterion.",
            "",
            "### False `not_affected` clearances (pipeline claimed NOT_AFFECTED; hand-check disagreed)",
            "",
        ])
        by_cve: dict[str, int] = {}
        for fc in kt2.get("false_clearances", []):
            by_cve[fc["cve"]] = by_cve.get(fc["cve"], 0) + 1
        if by_cve:
            lines.append("**By CVE (real-100 sample):** " + ", ".join(
                f"{cve} ×{n}" for cve, n in sorted(by_cve.items())
            ) + ".")
            lines.append("")
        for fc in kt2.get("false_clearances", []):
            lines.append(
                f"- **{fc['id']}** — **{fc['cve']}** on **`{fc['artifact']}`** / component **`{fc['component']}`**: "
                f"pipeline claimed **`{fc['pipeline_verdict']}`** (`{fc.get('justification') or fc.get('rule_id', '')}`); "
                f"hand-check found **`{fc['human_label']}`**. "
                f"{fc.get('human_notes') or fc.get('finding', '')}"
            )
        lines.append("")
    else:
        lines.extend([
            "**False `not_affected`: 0** — no pipeline `NOT_AFFECTED` verdict disagreed with hand label.",
            "",
        ])

    lines.extend([
        f"**KT-2: {kt2['verdict']}** — false `not_affected` count **{false_na}** (pre-registered bar: zero).",
        "",
    ])

    agree = kt2.get("agreement_count")
    agree_pct = kt2.get("agreement_rate_pct")
    if full and agree is not None and agree_pct is not None:
        lines.extend([
            f"**Pipeline–human agreement:** **{agree}/{total}** (**{agree_pct:.2f}%**).",
            "",
            "### Precision / recall per pipeline `reason_code` (refusal rows only)",
            "",
            "Computed on statements where the pipeline emitted `UNDER_INVESTIGATION`; "
            "precision = TP/(TP+FP), recall = TP/(TP+FN) vs hand `UNDER_INVESTIGATION`.",
            "",
            "| reason_code | precision | recall | tp | fp | fn |",
            "|-------------|----------:|-------:|---:|---:|---:|",
        ])
        for row in kt2.get("precision_recall_by_reason", []):
            lines.append(
                f"| `{row['reason_code']}` | {fmt_pct(row['precision'])} | {fmt_pct(row['recall'])} "
                f"| {row['tp']} | {row['fp']} | {row['fn']} |"
            )
        lines.extend([
            "",
            "The four labeled `reason_code` rows show precision and recall **1.000 on refusal rows only**; "
            "the `(none)` row (recall **0.000**, fn=**20**) is the **20** false `not_affected` clearances "
            "excluded from that denominator.",
        ])
    else:
        lines.extend([
            "**Pipeline–human agreement:** *pending labels* (80 refusal rows in CP-B1).",
            "",
            "### Precision / recall per pipeline `reason_code`",
            "",
            "*pending labels* — refusal rows not yet hand-labeled.",
        ])

    disagreements = kt2.get("disagreements", [])
    lines.extend([
        "",
        "### Pipeline vs hand label (all disagreements)",
        "",
    ])
    if not disagreements:
        lines.append("*None — pipeline verdict matched human label on all 100 statements.*")
    else:
        for d in disagreements:
            note = f" — {d['human_notes']}" if d.get("human_notes") else ""
            lines.append(
                f"- **{d['id']}** **{d['cve']}** **`{d['artifact']}`** "
                f"(component `{d.get('component') or '—'}`): "
                f"pipeline **`{d['pipeline_verdict']}`** → hand **`{d['human_label']}`**{note}"
            )

    lines.append("")
    return "\n".join(lines)


def patch_results(section: str) -> None:
    text = RESULTS.read_text()
    start = text.find(SECTION_START)
    end = text.find(SECTION_END)
    if start < 0 or end < 0 or end <= start:
        sys.exit(f"could not find KT-2 section markers in {RESULTS}")
    new_text = text[:start] + section.rstrip() + "\n\n---\n\n" + text[end:]
    RESULTS.write_text(new_text)


def main() -> int:
    if not METRICS.is_file():
        print(f"missing {METRICS}; run scripts/compute-cp11-metrics.py", file=sys.stderr)
        return 1
    m = json.loads(METRICS.read_text())
    kt2 = m.get("kt2")
    if not kt2:
        print("missing kt2 in cp11-metrics.json", file=sys.stderr)
        return 1
    section = render_kt2(kt2)
    patch_results(section)
    print(f"updated {RESULTS} §KT-2 (verdict={kt2.get('verdict')})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
