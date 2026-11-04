"""Regenerate the verbatim disassembly excerpts for the
RE-001-indexed-call-loop-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-indexed-call-loop-115/export_excerpts.py

Writes main.txt: the whole FDE window 0x5f6b520..0x5f6b581 of the
digest-verified node #115 work binary, exactly as objdump emits it;
and caller-site.txt: the verbatim call-site excerpt
0x5d60780..0x5d607ae (argument setup plus the call itself), not the
whole caller function. The excerpts are stored verbatim; verify.py
checks that a fresh run reproduces them byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5F6B520, 0x5F6B581),
    ("caller-site.txt", 0x5D60780, 0x5D607AE),
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
