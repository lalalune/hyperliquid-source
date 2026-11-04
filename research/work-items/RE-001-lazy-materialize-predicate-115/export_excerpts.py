"""Regenerate the verbatim disassembly excerpts for the
RE-001-lazy-materialize-predicate-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-lazy-materialize-predicate-115/export_excerpts.py

Writes main.txt: the whole FDE window 0x5f77190..0x5f77326 of the
digest-verified node #115 work binary, exactly as objdump emits it.
The excerpt is stored verbatim; verify.py checks that a fresh run
reproduces it byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5F77190, 0x5F77326),
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
