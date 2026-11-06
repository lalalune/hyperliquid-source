"""Regenerate the verbatim disassembly excerpts for the
RE-001-options-default-init-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-options-default-init-115/export_excerpts.py

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
    ("main.txt", 0x60B3FB0, 0x60B44C7),
    ("base.txt", 0x60B3C30, 0x60B3EEB),
    ("preset.txt", 0x606EAD0, 0x606EB0C),
    ("singleton.txt", 0x61BE810, 0x61BE8C8),
    ("table_init.txt", 0x60DB710, 0x60DBD69),
    ("wrapper.txt", 0x60DBD80, 0x60DBDBB),
    ("singleton_stub.txt", 0x61BE8D0, 0x61BE8D9),
    ("caller_a.txt", 0x5E5A8C0, 0x5E5AA63),
    ("site-5e61cdb.txt", 0x5E61C80, 0x5E61E20),
    ("caller_c.txt", 0x5FA47E0, 0x5FA4C5F),
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
