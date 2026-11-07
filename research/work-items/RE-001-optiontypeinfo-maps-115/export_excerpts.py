#!/usr/bin/env python3
"""Regenerate every disassembly excerpt in this packet, byte-for-byte.

Each excerpt is one whole function (FDE range from readelf
--debug-dump=frames-interp), emitted by
``objdump -d --start-address=<start> --stop-address=<stop>
work/hl-node-115.bin`` run from the repo root.  The four excerpts marked
"reshipped" below were first exported for RE-001-optiontypeinfo-mismatches-115
(#4233) and are regenerated here from the same ranges, so they are
byte-identical to the #4233 packet's copies.

Usage: python3 export_excerpts.py  (run from the repo root)
"""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
BIN = "work/hl-node-115.bin"

# (file name, start, stop) -- whole functions only.
EXCERPTS = [
    # The static initializer that builds both maps (reshipped from #4233).
    ("static-initializer-60aa2b0.objdump.txt", 0x60AA2B0, 0x60B1D78),
    # The pair ctor and the record/string dtors (reshipped from #4233).
    ("pair-ctor-5d400f0.objdump.txt", 0x5D400F0, 0x5D40477),
    ("record-dtor-5d3f950.objdump.txt", 0x5D3F950, 0x5D3F9D3),
    ("string-ctor-609fb90.objdump.txt", 0x609FB90, 0x609FC73),
    # Enum-map range ctors (unordered_map<string,int> in-place builders).
    ("helper-enummap1-60a76c0.objdump.txt", 0x60A76C0, 0x60A7B4F),
    ("helper-enummap2-60a7c90.objdump.txt", 0x60A7C90, 0x60A811F),
    ("helper-enummap3-60a8260.objdump.txt", 0x60A8260, 0x60A86EF),
    ("helper-enummap4-60a8830.objdump.txt", 0x60A8830, 0x60A8CBF),
    # Enum-typed OptionTypeInfo builders (mid helpers).
    ("helper-mid1-60a64d0.objdump.txt", 0x60A64D0, 0x60A65B4),
    ("helper-mid2-60a65c0.objdump.txt", 0x60A65C0, 0x60A66A4),
    ("helper-mid3-60a66b0.objdump.txt", 0x60A66B0, 0x60A6794),
    ("helper-mid4-60a67a0.objdump.txt", 0x60A67A0, 0x60A6884),
    # Nested-value builders.
    ("helper-nested-strfn-609f1c0.objdump.txt", 0x609F1C0, 0x609F1ED),
    ("helper-nested-strfn-609f1f0.objdump.txt", 0x609F1F0, 0x609F21D),
    ("helper-nested-strfn-609f220.objdump.txt", 0x609F220, 0x609F24D),
    ("helper-nested-60a0180.objdump.txt", 0x60A0180, 0x60A0237),
    ("helper-nested-60a63d0.objdump.txt", 0x60A63D0, 0x60A6446),
    ("helper-nested-60a6450.objdump.txt", 0x60A6450, 0x60A64C6),
    # Dtors registered with __cxa_atexit by the initializer.
    ("dtor-strings-609fd10.objdump.txt", 0x609FD10, 0x609FD6C),
    ("dtor-map-60a00a0.objdump.txt", 0x60A00A0, 0x60A0145),
    ("dtor-609fff0.objdump.txt", 0x609FFF0, 0x60A0095),
    ("enum-dtor-609fe90.objdump.txt", 0x609FE90, 0x609FF35),
    ("enum-dtor-609ff40.objdump.txt", 0x609FF40, 0x609FFE5),
    # The unordered_map range ctor and the OptionTypeInfo move ctors.
    ("range-ctor-5d405b0.objdump.txt", 0x5D405B0, 0x5D40F32),
    ("movefn-5e32b10.objdump.txt", 0x5E32B10, 0x5E32C65),
    ("movefn-5e332c0.objdump.txt", 0x5E332C0, 0x5E3354F),
    ("map-dtor-5d3f820.objdump.txt", 0x5D3F820, 0x5D3F94D),
    # Consumers: the three functions that reference the maps directly.
    ("consumer-mutable-60a1d60.objdump.txt", 0x60A1D60, 0x60A1F03),
    ("consumer-mutable-60a2080.objdump.txt", 0x60A2080, 0x60A2357),
    ("consumer-bothmaps-60a47f0.objdump.txt", 0x60A47F0, 0x60A636B),
    # The apply loop, the per-entry apply, the lookup helper, the
    # unknown-option path, the serialize dispatch, and the single-option
    # getter / map dumper.
    ("fn-60c18b0.objdump.txt", 0x60C18B0, 0x60C1B7C),
    ("fn-60bedc0.objdump.txt", 0x60BEDC0, 0x60BF5BC),
    ("fn-60ba0b0.objdump.txt", 0x60BA0B0, 0x60BA441),
    ("fn-60c0e90.objdump.txt", 0x60C0E90, 0x60C112F),
    ("fn-60ba600.objdump.txt", 0x60BA600, 0x60BB855),
    ("fn-60c78a0.objdump.txt", 0x60C78A0, 0x60C870D),
    ("fn-60bfda0.objdump.txt", 0x60BFDA0, 0x60C057F),
    ("fn-6099ce0.objdump.txt", 0x6099CE0, 0x6099E34),
    ("fn-60bb890.objdump.txt", 0x60BB890, 0x60BB932),
]


def main():
    for name, start, stop in EXCERPTS:
        out = subprocess.run(
            ["objdump", "-d",
             f"--start-address=0x{start:x}",
             f"--stop-address=0x{stop:x}", BIN],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout
        (HERE / name).write_text(out)
        print(f"wrote {name} (0x{start:x}..0x{stop:x})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
