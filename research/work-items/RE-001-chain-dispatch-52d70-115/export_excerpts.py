"""Regenerate the verbatim disassembly excerpts for the
RE-001-chain-dispatch-52d70-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-chain-dispatch-52d70-115/export_excerpts.py

Writes main.txt (0x5d52d70..0x5d52e21), the whole routine body,
acquire.txt (0x60d5390..0x60d5395), the no-op acquire stub,
sentinel.txt (0x5d4b320..0x5d4b3e2), the whole routine the
relocated global at 0x64ed590 points at, and rsi_target.txt
(0x5dd6060..0x5dd6097), the whole routine whose address the
dispatch passes in rsi. The excerpts are stored verbatim;
verify.py checks that a fresh run reproduces them byte-for-byte.
Instruction-level detail lives only in these excerpt texts, not
in records.json.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5D52D70, 0x5D52E21),
    ("acquire.txt", 0x60D5390, 0x60D5395),
    ("sentinel.txt", 0x5D4B320, 0x5D4B3E2),
    ("rsi_target.txt", 0x5DD6060, 0x5DD6097),
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
