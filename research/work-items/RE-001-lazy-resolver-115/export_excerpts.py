"""Regenerate the verbatim disassembly excerpts for the
RE-001-lazy-resolver-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-lazy-resolver-115/export_excerpts.py

Writes one excerpt per window. Whole-function excerpts cover
the lazy one-time resolver 0x5f074e0..0x5f07603 (0x123 bytes)
and its canonical chain-walk continuation 0x5d4b100..0x5d4b20c
(0x10c bytes). The call-site window 0x5f0ef1c..0x5f0ef60
covers the decision sequence in 0x5f0e890: the +0xc18 gate,
the once-helper call 0x5f07490 and the resolver call.
The once helper 0x5f07490..0x5f074d3 and its predicate
0x5f07300..0x5f07481 are re-shipped byte-identical from the
RE-001-owner-tail-phases-115 packet (#3304), which pins the
once decision itself; this packet pins the resolver that runs
right after it on the same owner object.

Each excerpt is stored verbatim; verify.py checks that a fresh
run reproduces it byte-for-byte. Instruction-level detail lives
only in these excerpt text files, not in records.json. The
mnemonics in the excerpts (endbr64 included) are genuine
instructions present in the target binary, not placeholders.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("resolver.txt", 0x5F074E0, 0x5F07603),
    ("canonical.txt", 0x5D4B100, 0x5D4B20C),
    ("callsite.txt", 0x5F0EF1C, 0x5F0EF60),
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
