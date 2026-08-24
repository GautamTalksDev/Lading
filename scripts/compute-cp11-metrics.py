#!/usr/bin/env python3
"""Compute CP-11 kill-test metrics from on-disk corpus outputs (S-15).

Writes corpus/results/cp11-metrics.json — canonical figures for RESULTS.md
and scripts/rederive-results.sh validation.
"""
from __future__ import annotations

import json
import math
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "corpus" / "results"
AGGREGATE = RESULTS_DIR / "aggregate.json"
OUT = RESULTS_DIR / "cp11-metrics.json"
REFUSAL_STAGES = ROOT / "results" / "refusal-stages.csv"
REAL100 = ROOT / "corpus" / "groundtruth" / "real-100.yaml"
ARTIFACTS = ROOT / "corpus" / "ARTIFACTS.yaml"
PROFILE_ROOTFS = ROOT / ".lading" / "profile-rootfs"
D01_FIND_CMD = "find <rootfs> -name 'libssl.so*' -o -name 'libcrypto.so*'"


def wilson_ci(successes: int, n: int, z: float = 1.96) -> dict:
    if n <= 0:
        return {"n": n, "p": 0.0, "ci_low": 0.0, "ci_high": 0.0}
    p = successes / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return {
        "n": n,
        "successes": successes,
        "p": p,
        "pct": round(p * 100, 4),
        "ci_low_pct": round(max(0.0, center - margin) * 100, 4),
        "ci_high_pct": round(min(1.0, center + margin) * 100, 4),
    }


def run_cmd(cmd: str) -> str:
    try:
        return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT).strip()
    except subprocess.CalledProcessError as e:
        return e.output.strip()


def load_aggregate() -> dict:
    if not AGGREGATE.is_file():
        sys.exit(f"missing {AGGREGATE}; run scripts/corpus-aggregate.py")
    return json.loads(AGGREGATE.read_text())


def refusal_breakdown() -> dict:
    reasons: Counter[str] = Counter()
    total_refusals = 0
    for path in RESULTS_DIR.glob("*/decisions.jsonl"):
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("verdict") == "UNDER_INVESTIGATION":
                total_refusals += 1
                reasons[rec.get("reason_code") or "unspecified"] += 1
    return {
        "total_refusals": total_refusals,
        "by_reason_code": dict(sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0]))),
    }


def na_with_bundle() -> int:
    n = 0
    for path in RESULTS_DIR.glob("*/decisions.jsonl"):
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("verdict") == "NOT_AFFECTED" and rec.get("evidence_bundle"):
                n += 1
    return n


def compute_kt2_metrics() -> dict:
    """KT-2 metrics from real-100.yaml hand labels."""
    if not REAL100.is_file():
        return {
            "evaluable": False,
            "soundness_evaluable": False,
            "full_evaluable": False,
            "empty_labels": 100,
            "label_count": 0,
            "false_not_affected": None,
            "false_clearances": [],
            "agreement_count": None,
            "agreement_rate_pct": None,
            "precision_recall_by_reason": [],
            "disagreements": [],
            "source": str(REAL100.relative_to(ROOT)),
            "seed": 20260824,
        }

    doc = yaml.safe_load(REAL100.read_text())
    statements = doc.get("statements") or []

    def norm(s: str | None) -> str:
        return str(s or "").strip().upper()

    empty = sum(1 for s in statements if not norm(s.get("human_label")))
    na_stmts = [s for s in statements if norm(s.get("pipeline_verdict")) == "NOT_AFFECTED"]
    na_labeled = sum(1 for s in na_stmts if norm(s.get("human_label")))
    soundness_evaluable = len(na_stmts) > 0 and na_labeled == len(na_stmts)
    full_evaluable = empty == 0 and len(statements) == 100
    evaluable = soundness_evaluable or full_evaluable

    base = {
        "label_count": len(statements),
        "empty_labels": empty,
        "soundness_evaluable": soundness_evaluable,
        "full_evaluable": full_evaluable,
        "evaluable": evaluable,
        "not_affected_labeled": na_labeled,
        "not_affected_total": len(na_stmts),
        "source": str(REAL100.relative_to(ROOT)),
        "seed": doc.get("seed", 20260824),
    }

    if not evaluable:
        return {
            **base,
            "false_not_affected": None,
            "false_clearances": [],
            "agreement_count": None,
            "agreement_rate_pct": None,
            "precision_recall_by_reason": [],
            "disagreements": [],
        }

    false_clearances: list[dict] = []
    disagreements: list[dict] = []
    agree = 0
    by_reason: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})

    labeled = [s for s in statements if norm(s.get("human_label"))]
    score_set = statements if full_evaluable else labeled

    for st in score_set:
        pipe = norm(st.get("pipeline_verdict"))
        human = norm(st.get("human_label"))
        notes = str(st.get("human_notes") or st.get("finding") or "").strip()

        if pipe == human:
            agree += 1
        else:
            disagreements.append(
                {
                    "id": st.get("id"),
                    "cve": st.get("cve"),
                    "artifact": st.get("artifact"),
                    "component": st.get("component") or "",
                    "pipeline_verdict": pipe,
                    "human_label": human,
                    "reason_code": st.get("reason_code") or "",
                    "justification": st.get("justification") or "",
                    "human_notes": notes,
                }
            )

        if pipe == "NOT_AFFECTED" and human != "NOT_AFFECTED":
            false_clearances.append(
                {
                    "id": st.get("id"),
                    "cve": st.get("cve"),
                    "artifact": st.get("artifact"),
                    "component": st.get("component") or "",
                    "pipeline_verdict": pipe,
                    "human_label": human,
                    "justification": st.get("justification") or "",
                    "rule_id": st.get("rule_id") or "",
                    "evidence_bundle": st.get("evidence_bundle") or "",
                    "human_notes": notes,
                    "finding": notes,
                }
            )

        if not full_evaluable:
            continue

        rc = st.get("reason_code") or "(none)"
        counts = by_reason[rc]
        if pipe == "UNDER_INVESTIGATION" and human == "UNDER_INVESTIGATION":
            counts["tp"] += 1
        elif pipe == "UNDER_INVESTIGATION" and human != "UNDER_INVESTIGATION":
            counts["fp"] += 1
        elif pipe != "UNDER_INVESTIGATION" and human == "UNDER_INVESTIGATION":
            counts["fn"] += 1

    pr_rows: list[dict] = []
    for rc in sorted(by_reason.keys()):
        c = by_reason[rc]
        tp, fp, fn = c["tp"], c["fp"], c["fn"]
        prec = tp / (tp + fp) if (tp + fp) else None
        rec = tp / (tp + fn) if (tp + fn) else None
        pr_rows.append(
            {
                "reason_code": rc,
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "precision": round(prec, 6) if prec is not None else None,
                "recall": round(rec, 6) if rec is not None else None,
            }
        )

    false_na = len(false_clearances)
    total_scored = len(score_set)
    return {
        **base,
        "false_not_affected": false_na,
        "false_clearances": false_clearances,
        "agreement_count": agree if full_evaluable else None,
        "agreement_rate_pct": round(100 * agree / total_scored, 4) if full_evaluable and total_scored else None,
        "precision_recall_by_reason": pr_rows,
        "disagreements": disagreements,
    }


def kt2_status() -> dict:
    return compute_kt2_metrics()


def has_openssl_grype_finding(scan_dir: Path) -> bool:
    grype = scan_dir / "grype.json"
    if not grype.is_file():
        return False
    data = json.loads(grype.read_text())
    for m in data.get("matches", []):
        pkg = m.get("artifact", {}) or {}
        name = (pkg.get("name") or "").lower()
        purl = (pkg.get("purl") or "").lower()
        if any(token in name or token in purl for token in ("openssl", "libssl", "libcrypto")):
            return True
    return False


def find_openssl_shared_objects(rootfs: Path) -> list[str]:
    if not rootfs.is_dir():
        return []
    proc = subprocess.run(
        ["find", str(rootfs), "-name", "libssl.so*", "-o", "-name", "libcrypto.so*"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return [line for line in proc.stdout.strip().split("\n") if line]


def artifacts_with_openssl_component_in_decisions() -> list[str]:
    ids: set[str] = set()
    for path in RESULTS_DIR.glob("*/decisions.jsonl"):
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("component") == "openssl":
                ids.add(path.parent.name)
    return sorted(ids)


def d01_corpus_absence() -> dict:
    """OpenSSL presence on disk vs grype package-name/PURL matches (not decisions-bound)."""
    with_findings: list[str] = []
    without_so: list[str] = []
    with_so: list[dict] = []
    for scan_dir in sorted(RESULTS_DIR.iterdir()):
        if not scan_dir.is_dir() or not (scan_dir / "scan-summary.json").is_file():
            continue
        sid = scan_dir.name
        if not has_openssl_grype_finding(scan_dir):
            continue
        with_findings.append(sid)
        sos = find_openssl_shared_objects(PROFILE_ROOTFS / sid)
        if sos:
            with_so.append({"artifact": sid, "so_count": len(sos)})
        else:
            without_so.append(sid)
    scanned = sum(
        1 for d in RESULTS_DIR.iterdir() if d.is_dir() and (d / "scan-summary.json").is_file()
    )
    decisions_openssl = artifacts_with_openssl_component_in_decisions()
    return {
        "find_command": D01_FIND_CMD,
        "artifacts_scanned": scanned,
        "selection_criterion": (
            "grype.json has ≥1 match where package name or PURL contains "
            "openssl, libssl, or libcrypto"
        ),
        "artifacts_with_openssl_grype_package_match": len(with_findings),
        "artifacts_with_openssl_grype_package_match_ids": with_findings,
        "artifacts_with_openssl_component_in_decisions": len(decisions_openssl),
        "artifacts_with_openssl_component_in_decisions_ids": decisions_openssl,
        "artifacts_with_openssl_so": len(with_so),
        "artifacts_without_openssl_so": len(without_so),
        "artifacts_without_openssl_so_ids": without_so,
    }


def corpus_composition() -> dict:
    doc = yaml.safe_load(ARTIFACTS.read_text())
    product = [a for a in doc["artifacts"] if a.get("class") != "benchmark"]
    by_class = Counter(a.get("class", "unknown") for a in product)
    present = sum(1 for a in product if a.get("status") == "present" and a.get("sha256"))
    return {
        "catalog_version": doc.get("version"),
        "product_artifacts": len(product),
        "present_with_sha256": present,
        "by_class": dict(sorted(by_class.items())),
    }


def inventory_stats() -> dict:
    stripped = static = binaries = 0
    for path in RESULTS_DIR.glob("*/scan-summary.json"):
        if path.stat().st_size < 2:
            continue
        try:
            s = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        binaries += int(s.get("binaries_scanned", 0))
        stripped += int(s.get("stripped", 0))
        static += int(s.get("static_linked", 0))
    return {
        "binaries_scanned": binaries,
        "stripped": stripped,
        "static_linked": static,
    }


def tool_versions() -> dict:
    aliases_path = ROOT / "manifest" / "data" / "identity-aliases.json"
    aliases_doc = json.loads(aliases_path.read_text()) if aliases_path.is_file() else {}
    manifest_ver = (ROOT / "manifest" / "VERSION").read_text().strip()
    git_head = run_cmd(f"git -C {ROOT} rev-parse HEAD 2>/dev/null") or "unknown"
    grype = run_cmd("grype version 2>/dev/null | head -5")
    go_ver = run_cmd("go version 2>/dev/null")
    return {
        "git_commit": git_head,
        "go": go_ver,
        "grype": grype,
        "lading": "bin/lading (evidence-v1 / decide.ToolVersion)",
        "manifest_version": manifest_ver,
        "manifest_components": len(list((ROOT / "manifest" / "components").rglob("*.yaml"))),
        "identity_aliases": len(aliases_doc.get("aliases", [])),
        "identity_aliases_definitive": sum(
            1 for a in aliases_doc.get("aliases", []) if a.get("status") == "definitive"
        ),
        "corpus_catalog": yaml.safe_load(ARTIFACTS.read_text()).get("version"),
        "computed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def load_refusal_stages() -> dict:
    if not REFUSAL_STAGES.is_file():
        sys.exit(f"missing {REFUSAL_STAGES}; run scripts/refusal-stages.sh")
    import csv

    by_stage: dict[str, int] = {}
    total = 0
    with REFUSAL_STAGES.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row.get("scope") != "all":
                continue
            sid = row["stage_id"]
            count = int(row["count"])
            by_stage[sid] = count
            total += count
    symbol_refusals = by_stage.get("S3", 0) + by_stage.get("S5", 0)
    upstream = by_stage.get("S1", 0) + by_stage.get("S2", 0)
    upstream_pct = round(100 * upstream / total, 4) if total else 0.0
    return {
        "decisions_jsonl_total": total,
        "by_stage": by_stage,
        "symbol_refusals": symbol_refusals,
        "upstream_terminations": upstream,
        "upstream_termination_pct": upstream_pct,
        "reached_symbol_stage_or_later": total - upstream,
        "decided_s7": by_stage.get("S7", 0),
    }


def kt1_evaluable(stages: dict) -> bool:
    """NOT EVALUABLE per README §11 when symbol gates never fire and ≥99% stop upstream."""
    total = stages["decisions_jsonl_total"]
    if total <= 0:
        return False
    if stages["symbol_refusals"] != 0:
        return True
    return stages["upstream_termination_pct"] < 99.0


def kt1_verdict(pct: float, threshold: float, evaluable: bool) -> str:
    if not evaluable:
        return "NOT EVALUABLE"
    if pct >= threshold:
        return "PASS"
    return "FAIL"


def kt2_verdict(kt2: dict) -> str:
    if not kt2["evaluable"]:
        return "NOT EVALUABLE"
    if kt2.get("false_not_affected", 0) > 0:
        return "FAIL"
    return "PASS"


def main() -> int:
    agg = load_aggregate()
    totals = agg["totals"]
    by_class = agg.get("by_class", {})

    n_cves = int(totals["cves_in"])
    n_art = int(totals["artifacts"])
    na = int(totals["not_affected"])
    aff = int(totals["affected"])
    decided = int(totals["decided"])
    refused = int(totals["refused"])
    na_bundle = na_with_bundle()

    kt1_decided = wilson_ci(decided, n_cves)
    kt1_na_bundle = wilson_ci(na_bundle, n_cves)

    firmware = by_class.get("firmware", {})
    subst = by_class.get("substitute-container", {})

    fw_cves = int(firmware.get("cves_in", 0))
    fw_decided = int(firmware.get("decided", 0))
    sub_cves = int(subst.get("cves_in", 0))
    sub_decided = int(subst.get("decided", 0))

    kt2 = compute_kt2_metrics()
    kt2["verdict"] = kt2_verdict(kt2)
    refusals = refusal_breakdown()
    refusal_stages = load_refusal_stages()
    kt1_is_evaluable = kt1_evaluable(refusal_stages)

    metrics = {
        "kt1": {
            "cves_in": n_cves,
            "artifacts_scanned": n_art,
            "not_affected": na,
            "not_affected_with_evidence_bundle": na_bundle,
            "affected": aff,
            "decided": decided,
            "refused": refused,
            "decided_coverage_pct": kt1_decided["pct"],
            "decided_ci_low_pct": kt1_decided["ci_low_pct"],
            "decided_ci_high_pct": kt1_decided["ci_high_pct"],
            "na_bundle_coverage_pct": kt1_na_bundle["pct"],
            "na_bundle_ci_low_pct": kt1_na_bundle["ci_low_pct"],
            "na_bundle_ci_high_pct": kt1_na_bundle["ci_high_pct"],
            "threshold_pct": 30.0,
            "evaluable": kt1_is_evaluable,
            "verdict": kt1_verdict(kt1_decided["pct"], 30.0, kt1_is_evaluable),
            "firmware": {
                "artifacts": int(firmware.get("artifacts", 0)),
                "cves_in": fw_cves,
                "decided": fw_decided,
                "coverage_pct": round(100 * fw_decided / fw_cves, 4) if fw_cves else 0.0,
            },
            "substitute_container": {
                "artifacts": int(subst.get("artifacts", 0)),
                "cves_in": sub_cves,
                "decided": sub_decided,
                "coverage_pct": round(100 * sub_decided / sub_cves, 4) if sub_cves else 0.0,
            },
        },
        "kt2": kt2,
        "refusals": refusals,
        "refusal_stages": refusal_stages,
        "by_class": by_class,
        "corpus": corpus_composition(),
        "inventory": inventory_stats(),
        "tools": tool_versions(),
        "d01_corpus_absence": d01_corpus_absence(),
    }

    OUT.write_text(json.dumps(metrics, indent=2) + "\n")
    print(f"wrote {OUT}")
    print(f"KT-1: {metrics['kt1']['verdict']} ({metrics['kt1']['decided_coverage_pct']}% decided)")
    print(f"KT-2: {metrics['kt2']['verdict']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
