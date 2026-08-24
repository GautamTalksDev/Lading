#!/usr/bin/env python3
"""Sample 100 real corpus verdicts into corpus/groundtruth/real-100.yaml (S-14).

Stratification (fixed seed):
  - ≥40 firmware-class artifacts
  - ≥20 pipeline not_affected
  - ≥20 refusals spanning multiple reason codes
  - remainder random

human_label is left empty for hand labeling (KT-2).
"""
from __future__ import annotations

import json
import random
import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "corpus" / "results"
ARTIFACTS = ROOT / "corpus" / "ARTIFACTS.yaml"
OUT = ROOT / "corpus" / "groundtruth" / "real-100.yaml"
SEED = 20260824


def load_artifact_class() -> dict[str, str]:
    doc = yaml.safe_load(ARTIFACTS.read_text())
    return {a["id"]: a.get("class") or "unknown" for a in doc["artifacts"]}


def load_decisions(classes: dict[str, str]) -> list[dict]:
    rows: list[dict] = []
    for path in sorted(RESULTS.glob("*/decisions.jsonl")):
        artifact = path.parent.name
        cls = classes.get(artifact, "unknown")
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            verdict = (rec.get("verdict") or "").upper()
            reason = rec.get("reason_code") or ""
            if verdict == "UNDER_INVESTIGATION":
                kind = "refusal"
            elif verdict == "NOT_AFFECTED":
                kind = "not_affected"
            elif verdict == "AFFECTED":
                kind = "affected"
            else:
                kind = "other"
            eb = rec.get("evidence_bundle") or ""
            if eb and not eb.startswith("corpus/"):
                # normalize to repo-relative
                try:
                    eb = str(Path(eb).resolve().relative_to(ROOT))
                except Exception:
                    eb = f"corpus/results/{artifact}/evidence-bundle/statements/{rec.get('statement_id','')}"
            rows.append(
                {
                    "artifact": artifact,
                    "artifact_class": cls,
                    "cve": rec.get("cve") or "",
                    "component": rec.get("component") or "",
                    "component_purl": rec.get("component_purl") or "",
                    "pipeline_verdict": verdict,
                    "rule_id": rec.get("rule_id") or "",
                    "reason_code": reason,
                    "justification": rec.get("justification") or "",
                    "evidence_bundle": eb,
                    "kind": kind,
                }
            )
    return rows


def pick_unique(pool: list[dict], n: int, rng: random.Random, seen: set[tuple]) -> list[dict]:
    rng.shuffle(pool)
    out: list[dict] = []
    for row in pool:
        key = (row["artifact"], row["cve"], row["component_purl"])
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
        if len(out) >= n:
            break
    return out


def sample(rows: list[dict], seed: int) -> list[dict]:
    rng = random.Random(seed)
    seen: set[tuple] = set()
    selected: list[dict] = []

    fw = [r for r in rows if r["artifact_class"] == "firmware"]
    na = [r for r in rows if r["kind"] == "not_affected"]
    refusals = [r for r in rows if r["kind"] == "refusal"]

    # Firmware quota (≥40)
    selected.extend(pick_unique(fw, 40, rng, seen))

    # not_affected quota (≥20)
    need_na = max(0, 20 - sum(1 for r in selected if r["kind"] == "not_affected"))
    selected.extend(pick_unique(na, need_na, rng, seen))

    # Refusals across reason codes (≥20)
    by_reason: dict[str, list[dict]] = defaultdict(list)
    for r in refusals:
        by_reason[r["reason_code"] or "unspecified"].append(r)
    reason_keys = sorted(by_reason.keys())
    if not reason_keys:
        raise SystemExit("no refusals in decisions.jsonl — cannot stratify")
    # round-robin across reasons until 20 refusals added (counting already selected)
    refusal_added = sum(1 for r in selected if r["kind"] == "refusal")
    idx = {k: 0 for k in reason_keys}
    shuffled_pools = {k: by_reason[k][:] for k in reason_keys}
    for k in reason_keys:
        rng.shuffle(shuffled_pools[k])
    while refusal_added < 20:
        progress = False
        for k in reason_keys:
            pool = shuffled_pools[k]
            while idx[k] < len(pool):
                row = pool[idx[k]]
                idx[k] += 1
                key = (row["artifact"], row["cve"], row["component_purl"])
                if key in seen:
                    continue
                seen.add(key)
                selected.append(row)
                refusal_added += 1
                progress = True
                break
            if refusal_added >= 20:
                break
        if not progress:
            break

    if sum(1 for r in selected if r["kind"] == "not_affected") < 20:
        raise SystemExit(
            f"stratification failed: not_affected="
            f"{sum(1 for r in selected if r['kind'] == 'not_affected')} (need ≥20)"
        )
    if sum(1 for r in selected if r["artifact_class"] == "firmware") < 40:
        raise SystemExit(
            f"stratification failed: firmware="
            f"{sum(1 for r in selected if r['artifact_class'] == 'firmware')} (need ≥40)"
        )
    if sum(1 for r in selected if r["kind"] == "refusal") < 20:
        raise SystemExit(
            f"stratification failed: refusals="
            f"{sum(1 for r in selected if r['kind'] == 'refusal')} (need ≥20)"
        )

    # Remainder random to 100
    need = 100 - len(selected)
    if need > 0:
        selected.extend(pick_unique(rows, need, rng, seen))
    if len(selected) < 100:
        raise SystemExit(f"only sampled {len(selected)} unique statements (need 100)")
    selected = selected[:100]
    rng.shuffle(selected)
    return selected


def main() -> int:
    classes = load_artifact_class()
    rows = load_decisions(classes)
    if not rows:
        print("no decisions.jsonl under corpus/results — run corpus-scan first", file=sys.stderr)
        return 1
    print(f"loaded {len(rows)} decisions", file=sys.stderr)
    counts = defaultdict(int)
    for r in rows:
        counts[r["kind"]] += 1
    print(dict(counts), file=sys.stderr)
    fw_n = sum(1 for r in rows if r["artifact_class"] == "firmware")
    print(f"firmware-class decisions: {fw_n}", file=sys.stderr)

    selected = sample(rows, SEED)
    statements = []
    for i, row in enumerate(selected, start=1):
        statements.append(
            {
                "id": f"real-{i:03d}",
                "cve": row["cve"],
                "component": row["component"],
                "component_purl": row["component_purl"],
                "artifact": row["artifact"],
                "artifact_class": row["artifact_class"],
                "pipeline_verdict": row["pipeline_verdict"],
                "rule_id": row["rule_id"],
                "reason_code": row["reason_code"],
                "justification": row["justification"],
                "evidence_bundle": row["evidence_bundle"],
                "human_label": "",
            }
        )

    doc = {
        "version": "real-100-v1",
        "seed": SEED,
        "source": "corpus/results/*/decisions.jsonl",
        "notes": (
            "S-14 KT-2 ground truth drawn from real corpus pipeline verdicts. "
            "human_label is empty until hand-labeled. Synthetic statements.yaml "
            "remains unit-test fixtures only and is not KT-2 evidence."
        ),
        "stratification": {
            "firmware_min": 40,
            "not_affected_min": 20,
            "refusals_min": 20,
            "firmware": sum(1 for s in statements if s["artifact_class"] == "firmware"),
            "not_affected": sum(1 for s in statements if s["pipeline_verdict"] == "NOT_AFFECTED"),
            "refusals": sum(
                1 for s in statements if s["pipeline_verdict"] == "UNDER_INVESTIGATION"
            ),
            "refusal_reason_codes": sorted(
                {
                    s["reason_code"]
                    for s in statements
                    if s["pipeline_verdict"] == "UNDER_INVESTIGATION" and s["reason_code"]
                }
            ),
        },
        "statements": statements,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    raw = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
    # Emit blank human_label scalars so `grep 'human_label: *$'` counts unlabeled rows.
    raw = raw.replace("human_label: ''", "human_label:")
    OUT.write_text(raw)
    print(f"wrote {OUT} ({len(statements)} statements, seed={SEED})", file=sys.stderr)
    print(yaml.safe_dump(doc["stratification"], sort_keys=False), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
