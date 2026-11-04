"""Regenerate the verbatim disassembly excerpts for the
RE-001-keyed-lookup-finalize-52660-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-keyed-lookup-finalize-52660-115/export_excerpts.py

Writes wrapper.txt (0x606c680..0x606c6a5) and lookup.txt
(0x5d52660..0x5d52765), each the whole routine body.
The excerpts are stored verbatim; verify.py checks that a
fresh run reproduces them byte-for-byte. Instruction-level
detail lives only in these excerpt texts, not in
records.json.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("wrapper.txt", 0x606C680, 0x606C6A5),
    ("lookup.txt", 0x5D52660, 0x5D52765),
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
