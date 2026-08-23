#!/usr/bin/env python3
"""Aggregate corpus scan summaries for KT-1 metrics."""
from __future__ import annotations

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "corpus" / "results"
OUT = RESULTS / "aggregate.json"


def load_summary(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def main() -> None:
    by_class: dict[str, list] = {}
    totals = {
        "artifacts": 0,
        "cves_in": 0,
        "not_affected": 0,
        "affected": 0,
        "refused": 0,
        "decided": 0,
    }
    artifacts = []

    import yaml

    catalog = yaml.safe_load((ROOT / "corpus" / "ARTIFACTS.yaml").read_text())
    classes = {a["id"]: a.get("class", "unknown") for a in catalog["artifacts"]}

    for child in sorted(RESULTS.iterdir()):
        if not child.is_dir():
            continue
        summary_path = child / "scan-summary.json"
        if not summary_path.is_file() or summary_path.stat().st_size < 2:
            continue
        s = load_summary(summary_path)
        if not s:
            continue
        aid = child.name
        cls = classes.get(aid, "unknown")
        cves = int(s.get("cves_in", 0))
        na = int(s.get("not_affected", 0))
        aff = int(s.get("affected", 0))
        ref = int(s.get("refused", 0))
        decided = na + aff
        pct = (decided * 100 // cves) if cves else 0
        rec = {
            "id": aid,
            "class": cls,
            "cves_in": cves,
            "not_affected": na,
            "affected": aff,
            "refused": ref,
            "coverage_percent": pct,
        }
        artifacts.append(rec)
        by_class.setdefault(cls, []).append(rec)
        totals["artifacts"] += 1
        totals["cves_in"] += cves
        totals["not_affected"] += na
        totals["affected"] += aff
        totals["refused"] += ref
        totals["decided"] += decided

    totals["coverage_percent"] = (
        (totals["decided"] * 100 // totals["cves_in"]) if totals["cves_in"] else 0
    )

    class_summary = {}
    for cls, rows in by_class.items():
        cves = sum(r["cves_in"] for r in rows)
        decided = sum(r["not_affected"] + r["affected"] for r in rows)
        class_summary[cls] = {
            "artifacts": len(rows),
            "cves_in": cves,
            "decided": decided,
            "coverage_percent": (decided * 100 // cves) if cves else 0,
        }

    OUT.write_text(
        json.dumps(
            {
                "totals": totals,
                "by_class": class_summary,
                "artifacts": artifacts,
            },
            indent=2,
        )
        + "\n"
    )
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
