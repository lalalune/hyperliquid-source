"""Regenerate the verbatim disassembly excerpts for the
RE-001-record-pushback-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-record-pushback-115/export_excerpts.py

Writes one whole-function excerpt per window. Each excerpt is
stored verbatim; verify.py checks that a fresh run reproduces
it byte-for-byte. Instruction-level detail lives only in these
excerpt text files, not in records.json. The mnemonics in the
excerpts (endbr64 included) are genuine instructions present
in the target binary, not placeholders.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("pushback.txt", 0x6099CE0, 0x6099E34),
    ("growth.txt", 0x6099790, 0x6099CAD),
    ("caller_64440.txt", 0x6064440, 0x6064551),
    ("caller_5fd0090.txt", 0x5FD0090, 0x5FD0178),
    ("table_init.txt", 0x60DB710, 0x60DBD69),
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
