"""Regenerate the verbatim disassembly excerpts for the
RE-001-table-factory-role9-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-table-factory-role9-115/export_excerpts.py

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
    ("table_init.txt", 0x60DB710, 0x60DBD69),
    ("wrapper.txt", 0x60DBD80, 0x60DBDBB),
    ("tree_copy.txt", 0x60D7FB0, 0x60D8082),
    ("impl_ctor.txt", 0x5DB8800, 0x5DB886F),
    ("release.txt", 0x5D350C0, 0x5D35145),
    ("destroy_dispatch.txt", 0x5D35070, 0x5D350BC),
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
