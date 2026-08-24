# Inventory fixtures

Built by `make -C testdata/inventory`.
Do not hand-edit binaries; change sources and rebuild.

## sample_macho_fat

Single-arch universal Mach-O (`cafebabe` header + one x86_64 thin slice).

**Provenance:** regenerated from `sample_macho` (Go `GOOS=darwin` gocross
fixture) by `testdata/inventory/scripts/wrap-macho-fat.py`. Not an Apple SDK
binary and not a hand copy of an external fat file. The wrapper writes a
deterministic big-endian fat header (offset 32, align 3) so Linux hosts can
rebuild without `lipo`.

**Why it exists:** `TestScan_FatMachO` needs a fat magic (`cafebabe`) to exercise
the `macho_fat` warning path; a thin Mach-O alone is insufficient.

Tracked in the Makefile `FIXTURES` list and `FIXTURES.sha`.
