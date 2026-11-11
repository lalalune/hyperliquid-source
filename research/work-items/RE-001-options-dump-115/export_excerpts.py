#!/usr/bin/env python3
"""Regenerate every disassembly excerpt in this packet, byte-for-byte.

Each excerpt is one whole function (FDE range from readelf
--debug-dump=frames-interp), emitted by
``objdump -d --start-address=<start> --stop-address=<stop>
work/hl-node-115.bin`` run from the repo root.  The objdump command
is recorded in the work-item README, and the excerpts are the raw
objdump text exactly as emitted: instruction mnemonics such as
``endbr64`` are genuine instructions present in the target binary,
not placeholders.

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
    # The ColumnFamilyOptions header dump itself.
    ("dump-60b50c0.objdump.txt", 0x60B50C0, 0x60B79A6),
    # The leveled log helper the dump calls 93 times.
    ("helper-5fceda0.objdump.txt", 0x5FCEDA0, 0x5FCEE93),
    # The sibling no-level helper (one caller, 0x60a0fb9).
    ("helper-nolevel-5fceea0.objdump.txt", 0x5FCEEA0, 0x5FCEF5B),
    # The CompressionType name function (jump table at 0x96d4f0).
    ("enumfn-5d8b3c0.objdump.txt", 0x5D8B3C0, 0x5D8B4CB),
    # The sole caller of the dump (FDE 0x5d954b0..0x5d96890).
    ("host-5d954b0.objdump.txt", 0x5D954B0, 0x5D96890),
]


def main():
    for name, start, stop in EXCERPTS:
        out = subprocess.run(
            ["objdump", "-d", f"--start-address={start:#x}",
             f"--stop-address={stop:#x}", BIN],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        (HERE / name).write_text(out)
        print(f"wrote {name} ({start:#x}..{stop:#x})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
