"""Regenerate the verbatim disassembly excerpts for the
RE-001-tree-assign-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-tree-assign-115/export_excerpts.py

Writes rebuilder.txt: the whole rebuilder 0x5d4e6a0..0x5d4ea62
(including its landing pads), and assign.txt: the whole assign
0x5d4ea90..0x5d4ec32 (including its landing pad).
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
    ("rebuilder.txt", 0x5D4E6A0, 0x5D4EA62),
    ("assign.txt", 0x5D4EA90, 0x5D4EC32),
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
