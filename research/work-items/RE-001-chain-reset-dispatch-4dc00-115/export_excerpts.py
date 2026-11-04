"""Regenerate the verbatim disassembly excerpts for the
RE-001-chain-reset-dispatch-4dc00-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-chain-reset-dispatch-4dc00-115/export_excerpts.py

Writes main.txt (0x5d4dc00..0x5d4dd50), the whole routine body
including its landing-pad stub. The excerpt is stored verbatim;
verify.py checks that a fresh run reproduces it byte-for-byte.
Instruction-level detail lives only in this excerpt text, not
in records.json. Mnemonics such as `endbr64` are genuine
instructions present in the target binary, not placeholders.

Command recorded:
    objdump -d --start-address=0x5d4dc00 --stop-address=0x5d4dd50 work/hl-node-115.bin
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5D4DC00, 0x5D4DD50),
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
