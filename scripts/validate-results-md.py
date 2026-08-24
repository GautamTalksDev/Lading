#!/usr/bin/env python3
"""Validate RESULTS.md figures against corpus/results/cp11-metrics.json."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
METRICS = ROOT / "corpus" / "results" / "cp11-metrics.json"
RESULTS = ROOT / "RESULTS.md"


def require_in_text(text: str, needle: str, label: str, errors: list[str]) -> None:
    if needle not in text:
        errors.append(f"{label}: missing {needle!r}")


def main() -> int:
    if not METRICS.is_file():
        print(f"missing {METRICS}; run scripts/compute-cp11-metrics.py", file=sys.stderr)
        return 1
    if not RESULTS.is_file():
        print(f"missing {RESULTS}", file=sys.stderr)
        return 1

    m = json.loads(METRICS.read_text())
    text = RESULTS.read_text()
    errors: list[str] = []

    kt1 = m["kt1"]
    kt2 = m["kt2"]
    stages = m.get("refusal_stages", {})

    # One-line verdicts (verification grep targets)
    require_in_text(text, f"KT-1: {kt1['verdict']}", "KT-1 verdict line", errors)
    # KT-2 section (rendered by scripts/render-results-kt2.py)
    if kt2.get("evaluable"):
        require_in_text(text, f"**KT-2: {kt2['verdict']}**", "KT-2 verdict line", errors)
        false_na = kt2.get("false_not_affected")
        if false_na is not None:
            require_in_text(
                text,
                f"false `not_affected` count **{false_na}**",
                "KT-2 false not_affected count",
                errors,
            )
        for fc in kt2.get("false_clearances", []):
            require_in_text(text, f"**{fc['id']}**", f"false clearance {fc['id']}", errors)
        if kt2.get("full_evaluable"):
            require_in_text(
                text,
                f"**{kt2['agreement_count']}/{kt2['label_count']}**",
                "KT-2 agreement count",
                errors,
            )
            for row in kt2.get("precision_recall_by_reason", []):
                require_in_text(
                    text,
                    f"| `{row['reason_code']}` |",
                    f"KT-2 pr/recall row {row['reason_code']}",
                    errors,
                )
        else:
            require_in_text(text, "*pending labels*", "KT-2 pending refusal labels", errors)
            require_in_text(text, "FINDING-002", "FINDING-002 reference", errors)
        for d in kt2.get("disagreements", []):
            require_in_text(text, f"**{d['id']}**", f"disagreement {d['id']}", errors)
    else:
        require_in_text(text, f"KT-2: {kt2['verdict']}", "KT-2 verdict line", errors)
        if kt2.get("empty_labels", 0) >= 100:
            require_in_text(text, "100/100 `human_label` fields empty", "KT-2 empty labels", errors)
        elif kt2.get("empty_labels", 0) > 0:
            require_in_text(
                text,
                f"{kt2['empty_labels']}/{kt2['label_count']} `human_label` fields empty",
                "KT-2 empty labels",
                errors,
            )
        require_in_text(text, "*pending labels*", "KT-2 pending labels", errors)
    require_in_text(text, "third consecutive", "third consecutive NOT EVALUABLE", errors)
    require_in_text(text, "## 5. What this result is", "What this result is section", errors)
    require_in_text(text, "§11 — Kill-test evaluability.", "README §11 quote", errors)

    # Core KT-1 figures
    checks = [
        (str(kt1["cves_in"]), "KT-1 cves_in"),
        (str(kt1["artifacts_scanned"]), "KT-1 artifacts_scanned"),
        (str(kt1["not_affected_with_evidence_bundle"]), "KT-1 na_with_bundle"),
        (str(kt1["decided"]), "KT-1 decided"),
        (f"{kt1['decided_coverage_pct']}%", "KT-1 decided pct"),
        (f"{kt1['decided_ci_low_pct']}%", "KT-1 CI low"),
        (f"{kt1['decided_ci_high_pct']}%", "KT-1 CI high"),
        (str(kt1["firmware"]["cves_in"]), "firmware cves_in"),
        (str(kt1["firmware"]["decided"]), "firmware decided"),
        (str(kt1["substitute_container"]["cves_in"]), "substitute cves_in"),
        (str(kt1["substitute_container"]["decided"]), "substitute decided"),
    ]
    for needle, label in checks:
        require_in_text(text, needle, label, errors)

    # Refusal-stage table (decisions.jsonl scope)
    by_stage = stages.get("by_stage", {})
    stage_rows = [
        ("S1 identity_resolution", by_stage.get("S1", 0)),
        ("S2 manifest_lookup", by_stage.get("S2", 0)),
        ("S3 symbol_table_usability", by_stage.get("S3", 0)),
        ("S5 symbol_stripped_gates", by_stage.get("S5", 0)),
        ("S5b symbol_observability", by_stage.get("S5b", 0)),
        ("S7 evidence_evaluation (decided)", by_stage.get("S7", 0)),
    ]
    for label, count in stage_rows:
        plain = f"| {label} | {count:,} |"
        bold = f"| {label} | **{count:,}** |"
        if plain not in text and bold not in text:
            errors.append(f"refusal stage {label}: missing {plain!r} or {bold!r}")

    if stages.get("symbol_refusals", -1) != 0:
        errors.append("refusal_stages: expected symbol_refusals == 0 in metrics")
    else:
        require_in_text(text, "**0**", "zero symbol-stage refusals", errors)

    if kt1.get("evaluable") is not False:
        errors.append("KT-1: expected evaluable=false in cp11-metrics.json")

    # Refusal reason counts
    for reason, count in m["refusals"]["by_reason_code"].items():
        require_in_text(text, f"| `{reason}` | {count} |", f"refusal {reason}", errors)

    # Tool / catalog anchors
    require_in_text(text, f"`{m['corpus']['catalog_version']}`", "catalog version", errors)
    require_in_text(text, f"`{m['tools']['manifest_version']}`", "manifest version", errors)
    require_in_text(text, m["tools"]["git_commit"], "git commit", errors)

    d01 = m.get("d01_corpus_absence", {})
    if d01:
        n_pkg = d01.get("artifacts_with_openssl_grype_package_match")
        n_dec = d01.get("artifacts_with_openssl_component_in_decisions")
        n_abs = d01.get("artifacts_without_openssl_so")
        if n_pkg is not None:
            require_in_text(text, f"**{n_pkg}**", "D01 grype package-match artifact count", errors)
        if n_dec is not None:
            require_in_text(text, f"**{n_dec}**", "D01 decisions-bound openssl count", errors)
        if n_abs == 0:
            require_in_text(text, "no natural corpus instance", "D01 no corpus instance", errors)

    if errors:
        print("RESULTS.md validation FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print("RESULTS.md matches cp11-metrics.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
