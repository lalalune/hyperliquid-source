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

The apply excerpt (fn-60bedc0) is re-shipped byte-identical from the
RE-001-optiontypeinfo-maps-115 packet (#4237), which first exported
it; the serializer excerpt is generated fresh here.

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
    # The per-entry apply: the verification gate lives here.
    ("fn-60bedc0.objdump.txt", 0x60BEDC0, 0x60BF5BC),
    # The per-entry serializer: verification 4 skips the dump here.
    ("fn-60bb9a0.objdump.txt", 0x60BB9A0, 0x60BBDEB),
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
