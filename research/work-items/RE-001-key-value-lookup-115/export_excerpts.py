"""Regenerate the verbatim disassembly excerpts for the
RE-001-key-value-lookup-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-key-value-lookup-115/export_excerpts.py

Writes main.txt: the whole key lookup routine 0x5d8cf70..0x5d8d0ac;
tail.txt: the whole second-stage value lookup 0x5d8ce90..0x5d8cf24,
which the key lookup tail-jumps into on a match.
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
    ("main.txt", 0x5D8CF70, 0x5D8D0AC),
    ("tail.txt", 0x5D8CE90, 0x5D8CF24),
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
