"""Regenerate the verbatim disassembly excerpts for the
RE-001-mutex-wrappers-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-mutex-wrappers-115/export_excerpts.py

Writes lock.txt (0x60d5230..0x60d52c5), lock_cleanup.txt
(0x60d5200..0x60d5225), unlock.txt (0x60d52f0..0x60d5385),
unlock_cleanup.txt (0x60d52c6..0x60d52eb) and stub.txt
(0x606ca00..0x606ca09). The excerpts are stored verbatim;
verify.py checks that a fresh run reproduces them
byte-for-byte. Instruction-level detail lives only in these
excerpt texts, not in records.json. Mnemonics such as `endbr64`
are genuine instructions present in the target binary, not
placeholders.

Commands recorded:
    objdump -d --start-address=0x60d5230 --stop-address=0x60d52c5 work/hl-node-115.bin
    objdump -d --start-address=0x60d5200 --stop-address=0x60d5225 work/hl-node-115.bin
    objdump -d --start-address=0x60d52f0 --stop-address=0x60d5385 work/hl-node-115.bin
    objdump -d --start-address=0x60d52c6 --stop-address=0x60d52eb work/hl-node-115.bin
    objdump -d --start-address=0x606ca00 --stop-address=0x606ca09 work/hl-node-115.bin
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("lock.txt", 0x60D5230, 0x60D52C5),
    ("lock_cleanup.txt", 0x60D5200, 0x60D5225),
    ("unlock.txt", 0x60D52F0, 0x60D5385),
    ("unlock_cleanup.txt", 0x60D52C6, 0x60D52EB),
    ("stub.txt", 0x606CA00, 0x606CA09),
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
