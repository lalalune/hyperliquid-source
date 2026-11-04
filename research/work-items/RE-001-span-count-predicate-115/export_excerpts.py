"""Regenerate the verbatim disassembly excerpts for the
RE-001-span-count-predicate-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-span-count-predicate-115/export_excerpts.py

Writes main.txt: the whole FDE window 0x5f6ea90..0x5f6eab5
of the digest-verified node #115 work binary, exactly as objdump
emits it; site.txt: the sole call site 0x5fa159d in
0x5fa0e40..0x5fa1d4a, from the argument setup through the call,
the result test, and the true-arm loop head; exit.txt: the
empty-range arm and the loop-exit follow-up call; cleanup.txt:
the shared cleanup block the false arm jumps to. The excerpts
are stored verbatim; verify.py checks that a fresh run
reproduces them byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5F6EA90, 0x5F6EAB5),
    ("site.txt", 0x5FA1598, 0x5FA15F6),
    ("exit.txt", 0x5FA1786, 0x5FA17A0),
    ("cleanup.txt", 0x5FA129C, 0x5FA12BF),
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
