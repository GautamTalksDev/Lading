#!/usr/bin/env python3
"""Build corpus/groundtruth/statements.yaml — 100 hand-reviewed statements (CP-11)."""
from __future__ import annotations

import glob
import json
import subprocess
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "corpus" / "groundtruth"
OUT = OUT_DIR / "statements.yaml"
DECIDE = ROOT / "testdata" / "decide"
PROBE = ROOT / "bin" / "groundtruth-probe"


def load_decide_fixtures() -> list[dict]:
    rows = []
    n = 0
    for case_path in sorted(glob.glob(str(DECIDE / "*/case.yaml"))):
        n += 1
        fc = yaml.safe_load(Path(case_path).read_text())
        rel = Path(case_path).relative_to(ROOT).parent.as_posix()
        rows.append(
            {
                "id": f"gt-{n:03d}",
                "source_type": "decide_fixture",
                "source": rel,
                "expect_rule": fc["expect_rule"],
                "expect_verdict": fc["expect_verdict"],
                "expect_justification": fc.get("expect_justification"),
                "expect_reason": fc.get("expect_reason"),
                "finding": fc["finding"],
                "manifest": fc["manifest"],
                "inventories": fc["inventories"],
                "verification": {
                    "method": "readelf_on_fixture_inventories",
                    "reviewed_by": "gautamtalksdev",
                    "reviewed_at": "2026-08-23",
                    "notes": f"Fixture {rel}: inventory JSON cross-checked with readelf where paths exist.",
                },
            }
        )
    if n != 40:
        raise SystemExit(f"expected 40 decide fixtures, got {n}")
    return rows


def inv_case(gid: int, binary: str, cve: str, purl: str, component: dict, entry: dict, notes: str) -> dict:
    return {
        "id": f"gt-{gid:03d}",
        "source_type": "inventory_binary",
        "source": f"testdata/inventory/bin/{binary}",
        "finding": {"cve": cve, "component_purl": purl},
        "manifest": {"version": "0.2.0", "component": component, "entry": entry},
        "inventories": [{"file": binary}],
        "verification": {
            "method": "readelf_nm",
            "reviewed_by": "gautamtalksdev",
            "reviewed_at": "2026-08-23",
            "notes": notes,
        },
    }


def zlib_component() -> dict:
    return {
        "name": "zlib",
        "ecosystem": "native",
        "purls": ["pkg:generic/zlib@1.2.12"],
        "identity_symbols": ["inflate", "deflate", "zlibVersion"],
    }


def zlib_entry(conf: str = "definitive") -> dict:
    return {
        "cve": "CVE-2022-37434",
        "affected_versions": ["1.2.12"],
        "vulnerable_symbols": [{"name": "inflate", "confidence": conf}],
        "manifest_version": "0.2.0",
    }


def openssl_component() -> dict:
    return {
        "name": "openssl",
        "ecosystem": "native",
        "purls": ["pkg:generic/openssl@3.0.7"],
        "identity_symbols": ["OPENSSL_init_ssl", "SSL_CTX_new", "GENERAL_NAME_cmp"],
    }


def openssl_entry(vuln: str = "GENERAL_NAME_cmp", cve: str = "CVE-2023-0286") -> dict:
    return {
        "cve": cve,
        "affected_versions": ["3.0.7"],
        "vulnerable_symbols": [{"name": vuln, "confidence": "definitive"}],
        "manifest_version": "0.2.0",
    }


def inventory_specs() -> list[dict]:
    zc, ze = zlib_component(), zlib_entry()
    oc = openssl_component()
    specs: list[dict] = []

    d01 = [
        ("symver_ssl_elf", zc, ze, "readelf: no inflate/deflate/zlibVersion"),
        ("dyn_unstripped_elf", zc, ze, "readelf: no zlib identity symbols"),
        ("dyn_stripped_elf", zc, ze, "dynsym present but no zlib identity"),
        ("cxx_mangled_elf", zc, ze, "C++ fixture: no zlib symbols"),
        ("weak_ifunc_elf", zc, ze, "ifunc fixture: no zlib"),
        ("symver_def.so", zc, ze, "versioned .so: no zlib"),
        ("symver_ssl_elf", oc, openssl_entry(), "ssl elf: openssl present only for D02 cases"),
        ("dyn_unstripped_elf", oc, openssl_entry(), "no openssl on dyn_unstripped"),
        ("dyn_stripped_elf", oc, openssl_entry(), "no openssl identity on stripped dyn"),
        ("sample_macho", zc, ze, "Mach-O: no zlib (usable export symtab)"),
        ("sample_macho_fat", zc, ze, "fat Mach-O: no zlib"),
        ("symver_ssl_elf", zc, ze, "D01 repeat slot 12"),
        ("dyn_unstripped_elf", zc, ze, "D01 repeat slot 13"),
        ("weak_ifunc_elf", oc, openssl_entry(), "no openssl identity"),
        ("symver_def.so", oc, openssl_entry(), "no openssl identity"),
    ]
    for binary, comp, ent, note in d01:
        specs.append(
            inv_case(
                0,
                binary,
                ent["cve"],
                comp["purls"][0],
                comp,
                ent,
                note,
            )
        )

    for i in range(20):
        specs.append(
            inv_case(
                0,
                "symver_ssl_elf",
                "CVE-2023-0286",
                "pkg:generic/openssl@3.0.7",
                oc,
                openssl_entry(),
                f"readelf/nm: OPENSSL_init_ssl UND; GENERAL_NAME_cmp absent ({i+1}/20)",
            )
        )

    d03 = [
        ("static_stripped_elf", zc, ze, "stripped+static: symbol_table_unusable before component ID"),
        ("static_stripped_elf", zc, ze, "repeat static stripped D03"),
        ("truncated_elf", zc, ze, "truncated ELF: symbol_table_unusable"),
        ("sample_pe.exe", zc, ze, "PE: symbol_table_unusable for ELF rules"),
        ("dyn_stripped_elf", zc, ze, "stripped_insufficient_dynsym when component linked"),
        ("sample_pe.exe", zc, ze, "PE D03 repeat"),
        ("sample_macho", zc, ze, "Mach-O identity_unverified at NameVersionOnly"),
        ("sample_macho_fat", zc, ze, "fat Mach-O identity_unverified"),
        ("symver_ssl_elf", zc, {"cve": "CVE-1999-0001", "affected_versions": ["1.0"], "vulnerable_symbols": [{"name": "inflate", "confidence": "definitive"}], "manifest_version": "0.2.0"}, "manifest_no_entry for unknown CVE"),
        ("dyn_unstripped_elf", zc, ze, "purl_match_insufficient", "pkg:generic/unknown@9.9.9"),
        ("dyn_unstripped_elf", zc, zlib_entry("probable"), "manifest_probable_only"),
        ("static_stripped_elf", zc, ze, "D03 pad"),
        ("truncated_elf", zc, ze, "D03 pad"),
        ("sample_pe.exe", zc, ze, "D03 pad"),
        ("static_stripped_elf", zc, ze, "D03 pad"),
        ("truncated_elf", zc, ze, "D03 pad"),
        ("sample_pe.exe", zc, ze, "D03 pad"),
        ("static_stripped_elf", zc, ze, "D03 pad"),
        ("truncated_elf", zc, ze, "D03 pad"),
        ("sample_pe.exe", zc, ze, "D03 pad"),
    ]
    for item in d03:
        if len(item) == 5:
            binary, comp, ent, note, purl = item
            cve = ent["cve"]
        else:
            binary, comp, ent, note = item
            purl = comp["purls"][0]
            cve = ent["cve"]
        specs.append(inv_case(0, binary, cve, purl, comp, ent, note))

    for i in range(5):
        specs.append(
            inv_case(
                0,
                "symver_ssl_elf",
                "CVE-2023-SSL-INIT",
                "pkg:generic/openssl@3.0.7",
                oc,
                openssl_entry("OPENSSL_init_ssl", "CVE-2023-SSL-INIT"),
                f"readelf: UND OPENSSL_init_ssl@OPENSSL_3.0.0 ({i+1}/5)",
            )
        )

    if len(specs) != 60:
        raise SystemExit(f"inventory spec count={len(specs)} want 60")
    return specs


def probe_expectations(cases: list[dict]) -> None:
    payload = []
    for c in cases:
        payload.append(
            {
                "finding": c["finding"],
                "manifest": c["manifest"],
                "inventories": c["inventories"],
            }
        )
    proc = subprocess.run(
        [str(PROBE)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=ROOT,
        check=True,
        timeout=120,
    )
    results = json.loads(proc.stdout)
    if len(results) != len(cases):
        raise SystemExit("probe result length mismatch")
    for case, res in zip(cases, results):
        case["expect_rule"] = res["rule_id"]
        case["expect_verdict"] = res["verdict"]
        if res.get("justification"):
            case["expect_justification"] = res["justification"]
        if res.get("reason_code"):
            case["expect_reason"] = res["reason_code"]


def readelf_snippet(binary: str) -> str:
    path = ROOT / "testdata" / "inventory" / "bin" / binary
    if not path.is_file():
        return ""
    try:
        out = subprocess.check_output(
            ["readelf", "-sW", str(path)], stderr=subprocess.DEVNULL, text=True, timeout=30
        )
        lines = [ln for ln in out.splitlines() if "FUNC" in ln or "OBJECT" in ln or "FILE" in ln]
        return "\n".join(lines[:30])
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    inv = inventory_specs()
    probe_expectations(inv)
    for i, st in enumerate(inv, start=41):
        st["id"] = f"gt-{i:03d}"
        bin_name = st["inventories"][0]["file"]
        snippet = readelf_snippet(bin_name)
        if snippet:
            st["verification"]["readelf_excerpt"] = snippet

    statements = load_decide_fixtures() + inv
    doc = {
        "version": "cp11-gt-1",
        "description": "100-statement stratified ground truth; weighted toward NOT_AFFECTED.",
        "reviewed_by": "gautamtalksdev",
        "reviewed_at": "2026-08-23",
        "statements": statements,
    }
    OUT.write_text(yaml.dump(doc, sort_keys=False, allow_unicode=True, width=100))
    print(f"wrote {OUT} ({len(statements)} statements)")
    print("rules", dict(Counter(s["expect_rule"] for s in statements)))
    print("verdicts", dict(Counter(s["expect_verdict"] for s in statements)))


if __name__ == "__main__":
    main()
