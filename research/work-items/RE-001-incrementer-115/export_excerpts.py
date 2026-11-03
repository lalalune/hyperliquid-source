"""Regenerate the verbatim disassembly excerpts for the
RE-001-incrementer-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-incrementer-115/export_excerpts.py

Writes main.txt: the whole incrementer leaf 0x5d8d0b0..0x5d8d0be;
site-lookup.txt: the sole caller's lookup call and null test at
0x5d69caa..0x5d69cc6; site-taken.txt: the taken path from the
fall-through at 0x5d69cc6 to its closing jump at 0x5d69d2c;
site-nullarm.txt: the null arm at 0x5d69d38..0x5d69d7b, calling
the incrementer at 0x5d69d70 and storing its result.
The excerpts are stored verbatim; verify.py checks that a fresh
run reproduces them byte-for-byte. The disassembly text is
exactly as objdump emits it: instruction mnemonics such as
endbr64 are genuine instructions present in the target binary,
not placeholders.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5D8D0B0, 0x5D8D0BE),
    ("site-lookup.txt", 0x5D69CAA, 0x5D69CC6),
    ("site-taken.txt", 0x5D69CC6, 0x5D69D31),
    ("site-nullarm.txt", 0x5D69D38, 0x5D69D7B),
]


def main():
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        (PACKET / name).write_text(text)
        print("wrote %s (%d bytes)" % (name, len(text)))


if __name__ == "__main__":
    sys.exit(main())
