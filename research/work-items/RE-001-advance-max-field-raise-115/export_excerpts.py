"""Regenerate the verbatim disassembly excerpts for the
RE-001-advance-max-field-raise-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-advance-max-field-raise-115/export_excerpts.py

Writes main-advance.txt: the whole FDE window 0x5f6f400..0x5f6f424
of the digest-verified node #115 work binary, exactly as objdump
emits it; main-max.txt: the whole FDE window 0x5f6f430..0x5f6f450;
site-5e6987d.txt, site-5e6b3ac.txt, site-5e82edc.txt,
site-5f9846d.txt: the verbatim direct-call excerpts (argument setup
plus the call itself plus the immediate post-call step);
site-shared-5f9dfb1.txt: the verbatim triple-call excerpt in the
shared caller (max-store call, then two advance-past calls, plus the
immediate post-call step). The excerpts are stored verbatim;
verify.py checks that a fresh run reproduces them byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main-advance.txt", 0x5F6F400, 0x5F6F424),
    ("main-max.txt", 0x5F6F430, 0x5F6F450),
    ("site-5e6987d.txt", 0x5E69876, 0x5E69889),
    ("site-5e6b3ac.txt", 0x5E6B3A1, 0x5E6B3B5),
    ("site-5e82edc.txt", 0x5E82EC3, 0x5E82EE8),
    ("site-5f9846d.txt", 0x5F98467, 0x5F98477),
    ("site-shared-5f9dfb1.txt", 0x5F9DFA6, 0x5F9DFDA),
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
