#!/usr/bin/env python3
"""Wrap a thin Mach-O in a single-arch fat (universal) header.

Deterministic substitute for `lipo -create` so Linux CI can regenerate
testdata/inventory/bin/sample_macho_fat without Xcode.

Fat layout (big-endian), matching Apple's single-slice universal files:
  magic (cafebabe) | nfat_arch=1 | fat_arch{cputype,cpusubtype,offset,size,align}
  padded to offset 32 | thin Mach-O bytes
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

FAT_MAGIC = 0xCAFEBABE
CPU_TYPE_X86_64 = 0x01000007
CPU_SUBTYPE_X86_64_ALL_LIB64 = 0x80000003
ALIGN = 3  # 2^3 = 8
DATA_OFFSET = 32


def wrap(thin: bytes) -> bytes:
    hdr = struct.pack(">II", FAT_MAGIC, 1)
    hdr += struct.pack(
        ">IIIII",
        CPU_TYPE_X86_64,
        CPU_SUBTYPE_X86_64_ALL_LIB64,
        DATA_OFFSET,
        len(thin),
        ALIGN,
    )
    hdr += b"\x00" * (DATA_OFFSET - len(hdr))
    if len(hdr) != DATA_OFFSET:
        raise SystemExit(f"fat header length {len(hdr)} != {DATA_OFFSET}")
    return hdr + thin


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} <thin-macho> <out-fat>")
    thin_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    thin = thin_path.read_bytes()
    if thin[:4] not in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        raise SystemExit(f"{thin_path}: not a little-endian Mach-O magic")
    out_path.write_bytes(wrap(thin))


if __name__ == "__main__":
    main()
