"""Regenerate the verbatim objdump excerpts for this work item.

Usage: python3 export_excerpts.py [--out DIR]  (default: this directory)

The excerpts are the whole functions exactly as objdump emits them.
The window excerpt runs to the next FDE start (0x514dce0), so it
includes the 4 int3 padding bytes after the window's FDE end
(0x514dcdc). The commands recorded in the README are: objdump -d
--start-address=<start> --stop-address=<stop> work/hl-node-94.bin
(run from the repository root). plt.objdump.txt concatenates the five
PLT stub ranges.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

BIN = Path(os.environ.get("HL_NODE94_BIN", "work/hl-node-94.bin"))
RANGES = {
    "window.objdump.txt": [(0x514D770, 0x514DCE0)],
    "helper.objdump.txt": [(0x514B1C0, 0x514B220)],
    "callers.objdump.txt": [(0x51560B0, 0x5157A19)],
    "plt.objdump.txt": [(0x56605F0, 0x5660600), (0x5660710, 0x5660720),
                        (0x5660470, 0x5660480), (0x5660430, 0x5660440),
                        (0x56606C0, 0x56606D0)],
}


def excerpt(start, stop):
    result = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(start),
         "--stop-address=%s" % hex(stop), str(BIN)],
        capture_output=True, text=True, check=True,
    )
    lines = [line for line in result.stdout.splitlines()
             if line.strip() and (line.startswith(" ") or line[0].isdigit())]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    outdir = Path(args.out) if args.out else Path(__file__).resolve().parent
    if not BIN.exists():
        print("missing binary: %s" % BIN, file=sys.stderr)
        return 1
    for name, ranges in RANGES.items():
        (outdir / name).write_text("".join(excerpt(s, e) for s, e in ranges))
        print("wrote %s" % name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
