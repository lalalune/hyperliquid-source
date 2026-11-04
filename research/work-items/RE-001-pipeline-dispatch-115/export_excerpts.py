"""Regenerate the verbatim disassembly excerpts for the
RE-001-pipeline-dispatch-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-pipeline-dispatch-115/export_excerpts.py

Writes main.txt: the whole FDE window 0x5f88550..0x5f8858f of the
digest-verified node #115 work binary, exactly as objdump emits it;
site-5f956ab.txt, site-5f973b5.txt, site-5fa01f1.txt and
site-5fa600e.txt: the verbatim direct-call excerpts (argument setup
plus the call itself plus the immediate post-call step). The
excerpts are stored verbatim; verify.py checks that a fresh run
reproduces them byte-for-byte.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5F88550, 0x5F8858F),
    ("site-5f956ab.txt", 0x5F956A3, 0x5F956BA),
    ("site-5f973b5.txt", 0x5F97398, 0x5F973C1),
    ("site-5fa01f1.txt", 0x5FA01CE, 0x5FA01FB),
    ("site-5fa600e.txt", 0x5FA5FE9, 0x5FA601A),
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
