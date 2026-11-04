"""Regenerate the verbatim disassembly excerpts for the
RE-001-take-record-4e420-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-take-record-4e420-115/export_excerpts.py

Writes main.txt (0x5d4e420..0x5d4e59c), the whole routine body
including its report path and its landing-pad stub, and helper.txt
(0x5d49b10..0x5d49b79), the move-assign helper body. The excerpts
are stored verbatim; verify.py checks that a fresh run reproduces
them byte-for-byte. Instruction-level detail lives only in these
excerpt texts, not in records.json. Mnemonics such as `endbr64`
are genuine instructions present in the target binary, not
placeholders.

Commands recorded:
    objdump -d --start-address=0x5d4e420 --stop-address=0x5d4e59c work/hl-node-115.bin
    objdump -d --start-address=0x5d49b10 --stop-address=0x5d49b79 work/hl-node-115.bin
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5D4E420, 0x5D4E59C),
    ("helper.txt", 0x5D49B10, 0x5D49B79),
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
