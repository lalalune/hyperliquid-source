#!/usr/bin/env python3
"""Regenerate the objdump excerpt files in this packet.

Run from the repository root:

    python3 research/work-items/RE-001-spot-scale-roundup-fc0-115/export_excerpts.py

Reads the materialised node binary at work/hl-node-115.bin and
writes main.txt (the wrapper at 0x5a00fc0) and round.txt (the
round leaf at 0x63efe40) next to this script. Output is
byte-identical to the committed files when the binary is the
pinned #115 artifact.
"""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"

WINDOWS = {
    "main.txt": (0x5A00FC0, 0x5A01101),
    "round.txt": (0x63EFE40, 0x63EFEB1),
}


def main():
    if not BINARY.exists():
        sys.exit("missing binary: %s" % BINARY)
    for name, (start, stop) in WINDOWS.items():
        out = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, str(BINARY)],
            capture_output=True, text=True, check=True).stdout
        # Drop the objdump header up to (but excluding) the
        # "Disassembly of section" line, so no local path or
        # format banner is baked into the excerpt.
        lines = out.splitlines(keepends=True)
        for i, line in enumerate(lines):
            if line.startswith("Disassembly of section"):
                lines = lines[i:]
                break
        (HERE / name).write_text("".join(lines))
        print("wrote %s (%#x..%#x)" % (name, start, stop))


if __name__ == "__main__":
    main()
