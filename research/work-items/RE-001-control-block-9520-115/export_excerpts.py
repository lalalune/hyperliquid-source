"""Regenerate the verbatim disassembly excerpts for the
RE-001-control-block-9520-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-control-block-9520-115/export_excerpts.py

Writes main.txt (0x5fc9520..0x5fc955e), the whole routine body,
reset.txt (0x5fc9460..0x5fc947b), the vtable reset routine the
new block's first slot points at, and deleting.txt
(0x5fc9480..0x5fc949b), the deleting destructor in the second
slot. The excerpts are stored verbatim; verify.py checks that a
fresh run reproduces them byte-for-byte. Instruction-level
detail lives only in these excerpt texts, not in records.json.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5FC9520, 0x5FC955E),
    ("reset.txt", 0x5FC9460, 0x5FC947B),
    ("deleting.txt", 0x5FC9480, 0x5FC949B),
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
