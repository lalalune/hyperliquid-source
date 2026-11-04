"""Regenerate the verbatim disassembly excerpts for the
RE-001-node-tree-60-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-node-tree-60-115/export_excerpts.py

Writes teardown.txt: the whole teardown 0x5d4cfd0..0x5d4d041;
copy.txt: the whole copy 0x5d4d050..0x5d4d241 including its
exception landing pads; helper.txt: the whole string builder
0x5d4a6a0..0x5d4a743; sites_copy1.txt / sites_copy2.txt: the
two copy call sites in 0x5d7fc80..0x5d8043e with their
null guards and post-call chain walks; sites_teardown_cleanup.txt:
the teardown cleanup site 0x5d8037f; sites_teardown_loops.txt:
the two inline destroy loops in 0x5d80440..0x5d81813.
The excerpts are stored verbatim; verify.py checks that a
fresh run reproduces them byte-for-byte. The disassembly text
is exactly as objdump emits it: instruction mnemonics such as
endbr64 are genuine instructions present in the target binary,
not placeholders.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("teardown.txt", 0x5D4CFD0, 0x5D4D041),
    ("copy.txt", 0x5D4D050, 0x5D4D241),
    ("helper.txt", 0x5D4A6A0, 0x5D4A743),
    ("sites_copy1.txt", 0x5D8006E, 0x5D800C8),
    ("sites_copy2.txt", 0x5D80104, 0x5D80158),
    ("sites_teardown_cleanup.txt", 0x5D80378, 0x5D8039C),
    ("sites_teardown_loops.txt", 0x5D80609, 0x5D806CD),
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
