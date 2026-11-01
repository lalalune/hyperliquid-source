"""Regenerate the verbatim objdump excerpts for this work item.

Usage: python3 export_excerpts.py [--out DIR]  (default: this directory)

The excerpts are the whole functions exactly as objdump emits them.
Each excerpt runs to the next FDE start, so it includes the int3
padding after the function's FDE end. The commands recorded in the
README are: objdump -d --start-address=<start>
--stop-address=<stop> work/hl-node-94.bin (run from the repository
root). There are no PLT stubs in these functions: every call is an
indirect call through a dispatch slot.
"""

import argparse
import os
import subprocess
from pathlib import Path

BIN = Path(os.environ.get("HL_NODE94_BIN", "work/hl-node-94.bin"))
RANGES = {
    "helper.objdump.txt": [(0x514DF80, 0x514DFA0)],
    "getters.objdump.txt": [(0x514DFA0, 0x514E030),
                            (0x514E030, 0x514E0C0),
                            (0x514E0C0, 0x514E160)],
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
    import sys
    raise SystemExit(main())
