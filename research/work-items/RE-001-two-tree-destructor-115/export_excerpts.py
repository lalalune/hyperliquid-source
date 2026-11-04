"""Regenerate the verbatim disassembly excerpt for the
RE-001-two-tree-destructor-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-two-tree-destructor-115/export_excerpts.py

Writes main.txt: the whole destructor 0x5d50170..0x5d503f5.
The excerpt is stored verbatim; verify.py checks that a fresh
run reproduces it byte-for-byte. The disassembly text is
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
    ("main.txt", 0x5D50170, 0x5D503F5),
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
