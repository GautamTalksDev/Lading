# IDEAS.md — not built (CP-11)

Per CP-11: feature ideas only. Do not implement without a new checkpoint.

**CP-14 gated** (do not build until two paid consulting engagements request the same capability): hosted evidence retention, org CI audit log SaaS, private Manifest hosting, CRA technical file export service.

1. **Manifest auto-derive from NVD + patch diffs** — suggest candidate vulnerable_symbols; human review queue only.
2. **Kernel module / .ko inventory** — separate symtab rules for out-of-tree modules in firmware tarballs.
3. **Go/Rust panic path symbol mining** — derive probable symbols from compiler-generated names (probable tier only).
4. **RPM/Dpkg metadata layer** — decide when package manager version contradicts ELF identity symbols.
5. **Batched scan orchestrator** — S3/GCS corpus driver with resumable checkpoints (operational, not evidence logic).
6. **VEX diff between scanner runs** — show which CVEs moved decided/refused between grype versions.
7. **Interactive manifest review UI** — browse upstream_fix_commit hunks beside symbol candidates.
8. **musl vs glibc identity heuristics** — flag when scanner PURL ecosystem mismatches linker (refusal, not guess).
9. **CSAF expert mode** — emit machine-readable remediation only when manifest entry is definitive.
10. **Windows kernel/driver PE parsing depth** — PDB-assisted symbol recovery (explicitly out of v1 scope).
11. **Corpus subscription feeds** — track OpenWrt release RSS + vendor GPL pages; no auto-scan without human catalog edit.
12. **Cross-artifact component version reconciliation** — when same SHA256 appears in multiple images, unify evidence bundle IDs.
