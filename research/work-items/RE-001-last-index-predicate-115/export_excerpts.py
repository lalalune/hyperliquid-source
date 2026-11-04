"""Regenerate the verbatim disassembly excerpts for the
RE-001-last-index-predicate-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-last-index-predicate-115/export_excerpts.py

Writes main.txt: the whole FDE window 0x5f6afa0..0x5f6afc8 of the
digest-verified node #115 work binary, exactly as objdump emits it;
site-5f6b0e9.txt, site-5f73880.txt, site-5f92bce.txt and
site-5f9a0e4.txt: the verbatim call-site excerpts (argument setup
plus the call itself plus the immediate result disposition); and
record-store.txt: the verbatim excerpt where the 0x5f6b0e9 site's
result is stored into the record field at +0x92. The excerpts are
stored verbatim; verify.py checks that a fresh run reproduces them
byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5F6AFA0, 0x5F6AFC8),
    ("site-5f6b0e9.txt", 0x5F6B0DE, 0x5F6B0F7),
    ("record-store.txt", 0x5F6B24A, 0x5F6B258),
    ("site-5f73880.txt", 0x5F73853, 0x5F738A8),
    ("site-5f92bce.txt", 0x5F92BBE, 0x5F92BDE),
    ("site-5f9a0e4.txt", 0x5F9A0D9, 0x5F9A0EF),
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
