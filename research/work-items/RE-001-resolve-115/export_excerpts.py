"""Regenerate the verbatim disassembly excerpts for the
RE-001-resolve-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-resolve-115/export_excerpts.py

Writes main.txt: the whole resolve-and-cache wrapper
0x5d8cf30..0x5d8cf6d; leaf.txt: the whole default leaf
0x5d8ce80..0x5d8ce8c, which the wrapper calls on its zero-id
arm. The excerpts are stored verbatim; verify.py checks that a
fresh run reproduces them byte-for-byte. The disassembly text
is exactly as objdump emits it: instruction mnemonics such as
endbr64 are genuine instructions present in the target binary,
not placeholders.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5D8CF30, 0x5D8CF6D),
    ("leaf.txt", 0x5D8CE80, 0x5D8CE8C),
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
