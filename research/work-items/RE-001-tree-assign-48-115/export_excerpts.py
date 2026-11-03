"""Regenerate the verbatim disassembly excerpts for the
RE-001-tree-assign-48-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-tree-assign-48-115/export_excerpts.py

Writes assign.txt (0x5d4e140..0x5d4e257), rebuilder.txt
(0x5d4de20..0x5d4e11a) and teardown.txt (0x5d4cba0..0x5d4cbf9).
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
    ("assign.txt", 0x5D4E140, 0x5D4E257),
    ("rebuilder.txt", 0x5D4DE20, 0x5D4E11A),
    ("teardown.txt", 0x5D4CBA0, 0x5D4CBF9),
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
