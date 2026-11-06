"""Regenerate the verbatim disassembly excerpts for the
RE-001-list-copy-insert-12320-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-list-copy-insert-12320-115/export_excerpts.py

Writes main.txt: the whole FDE window 0x5f12320..0x5f12413 of
the digest-verified node #115 work binary, exactly as objdump
emits it, including the trailing landing pad at 0x5f12407;
cleanup.txt: the shared cleanup block 0x5f122e0..0x5f12318 in
the neighbouring FDE, which the landing pad jumps into;
site.txt: the whole caller FDE 0x5f12840..0x5f129a6 (the
copy-on-write move helper), holding both call sites. The
excerpts are stored verbatim; verify.py checks that a fresh
run reproduces them byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5F12320, 0x5F12413),
    ("cleanup.txt", 0x5F122E0, 0x5F12318),
    ("site.txt", 0x5F12840, 0x5F129A6),
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
