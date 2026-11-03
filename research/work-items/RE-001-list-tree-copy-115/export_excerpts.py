"""Regenerate the verbatim disassembly excerpts for the
RE-001-list-tree-copy-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-list-tree-copy-115/export_excerpts.py

Writes main.txt: the whole FDE window 0x5d4caa0..0x5d4cb94
of the digest-verified node #115 work binary, exactly as objdump
emits it, including both trailing landing pads; site-large.txt:
the 0x5d80440 function's call site at 0x5d80ee3 with its
argument setup, null guard, and post-call walks. The excerpts
are stored verbatim; verify.py checks that a fresh run
reproduces them byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5D4CAA0, 0x5D4CB94),
    ("site-large.txt", 0x5D80E9B, 0x5D80F38),
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
