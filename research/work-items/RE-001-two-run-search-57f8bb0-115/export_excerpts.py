"""Regenerate the verbatim disassembly excerpts for the
RE-001-two-run-search-57f8bb0-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-two-run-search-57f8bb0-115/export_excerpts.py

Writes main.txt (0x57f8bb0..0x57f8ccc), the whole search routine
body, and caller.txt (0x5a07610..0x5a07646), the block engine's
call site with its result gate and first clamp instructions.
The excerpts are stored verbatim; verify.py checks that a fresh
run reproduces them byte-for-byte. Instruction-level detail
lives only in these excerpt texts, not in records.json.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x57F8BB0, 0x57F8CCC),
    ("caller.txt", 0x5A07610, 0x5A07646),
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
