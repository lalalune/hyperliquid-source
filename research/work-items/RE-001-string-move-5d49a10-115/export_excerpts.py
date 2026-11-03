"""Regenerate the verbatim disassembly excerpt for the
RE-001-string-move-5d49a10-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-string-move-5d49a10-115/export_excerpts.py

Writes main.txt: the whole routine 0x5d49a10..0x5d49ae8.
The excerpt is stored verbatim; verify.py checks that a fresh
run reproduces it byte-for-byte. Instruction-level detail
lives only in this excerpt text, not in records.json.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5D49A10, 0x5D49AE8),
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
