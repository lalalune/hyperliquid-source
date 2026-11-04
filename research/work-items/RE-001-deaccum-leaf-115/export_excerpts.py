"""Regenerate the verbatim disassembly excerpts for the
RE-001-deaccum-leaf-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-deaccum-leaf-115/export_excerpts.py

Writes main.txt: the whole FDE window 0x5f6b620..0x5f6b660 of the
digest-verified node #115 work binary, exactly as objdump emits it;
site-5f53747.txt, site-5f537af.txt and site-5f5390a.txt: the
verbatim direct-call excerpts (argument setup plus the call itself
plus the immediate post-call step); and tail-5f45d50.txt and
tail-5f45df6.txt: the verbatim tail-jump excerpts (the first covers
the lookup function's entry, where the tail-call argument registers
are established, through the first tail jump; the second covers the
second tail jump's own setup). The excerpts are stored verbatim;
verify.py checks that a fresh run reproduces them byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5F6B620, 0x5F6B660),
    ("site-5f53747.txt", 0x5F536FF, 0x5F53750),
    ("site-5f537af.txt", 0x5F5376B, 0x5F537BA),
    ("site-5f5390a.txt", 0x5F538FC, 0x5F53918),
    ("tail-5f45d50.txt", 0x5F45CF0, 0x5F45D55),
    ("tail-5f45df6.txt", 0x5F45DB0, 0x5F45DFB),
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
