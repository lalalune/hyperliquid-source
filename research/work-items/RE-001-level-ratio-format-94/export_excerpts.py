"""Regenerate the verbatim objdump excerpts for this work item.

Usage: python3 export_excerpts.py [--out DIR]  (default: this directory)

The excerpts are the whole functions exactly as objdump emits them,
including the int3 padding up to the next FDE start.  The commands
recorded in the README are: objdump -d --start-address=<start>
--stop-address=<stop> work/hl-node-94.bin (run from the repository
root).  plt.objdump.txt concatenates the two PLT stub ranges.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

# Absolute override so a copied packet still exports against the real
# target; otherwise the repository-relative path, run from the repo root.
BIN = Path(os.environ.get("HL_NODE94_BIN", "work/hl-node-94.bin"))
RANGES = {
    "window.objdump.txt": [(0x514CC10, 0x514CD00)],
    "parser.objdump.txt": [(0x54307C0, 0x5430860)],
    "ratio.objdump.txt": [(0x51CA8A0, 0x51CA970)],
    "plt.objdump.txt": [(0x5660430, 0x5660450)],
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
