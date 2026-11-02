"""Regenerate the verbatim objdump excerpts for this work item.

Usage: python3 export_excerpts.py [--out DIR]  (default: this directory)

The excerpts are the whole functions exactly as objdump emits them,
including the int3 padding up to the next FDE start.  The command recorded
in the README is: objdump -d --start-address=<start> --stop-address=<stop>
work/hl-node-94.bin
"""

import argparse
import subprocess
import sys
from pathlib import Path

BIN = Path("work/hl-node-94.bin")
RANGES = {
    "window.objdump.txt": (0x514C780, 0x514C8F0),
    "copy.objdump.txt": (0x514B7E0, 0x514BA10),
    "erase.objdump.txt": (0x514B690, 0x514B6C5),
    "cleanup.objdump.txt": (0x514C74E, 0x514C780),
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
    for name, (start, stop) in RANGES.items():
        (outdir / name).write_text(excerpt(start, stop))
        print("wrote %s" % name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
