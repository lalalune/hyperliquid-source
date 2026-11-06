"""Regenerate the verbatim disassembly excerpts for the
RE-001-timestamp-guard-8810-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-timestamp-guard-8810-115/export_excerpts.py

Writes main.txt (0x5d58810..0x5d58ac5), status_builder.txt
(0x61cf670..0x61cf767) and default_getter.txt
(0x5d48510..0x5d4851c), each the whole routine body. The excerpts
are stored verbatim; verify.py checks that a fresh run
reproduces them byte-for-byte. Instruction-level detail lives
only in these excerpt texts, not in records.json.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5D58810, 0x5D58AC5),
    ("status_builder.txt", 0x61CF670, 0x61CF767),
    ("default_getter.txt", 0x5D48510, 0x5D4851C),
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
