"""Regenerate the verbatim disassembly excerpts for the
RE-001-canonical-lea-sites-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-canonical-lea-sites-115/export_excerpts.py

Writes one excerpt per window. Whole-function excerpts cover
the four routines that take the canonical continuation's
address with lea and unroll its chain walk inline:

  site_a 0x5dc9d70..0x5dca807 (11 levels compared, 12th called)
  site_b 0x5e18d20..0x5e19117 (9 levels compared, 10th called)
  site_c 0x5f7d7d0..0x5f7de6e (11 levels compared, 12th called)
  site_d 0x5f865d0..0x5f87065 (11 levels compared, 12th called)

plus the five SystemClockWrapper vtable installers, which
install the vtable by lea of its header 0x64cdd78 plus 0x10:

  vtable_install_1 0x5fd0090..0x5fd0178
  vtable_install_2 0x6029110..0x602922b
  vtable_install_3 0x6029230..0x602934b
  vtable_install_4 0x6029500..0x602961b
  vtable_install_5 0x6029620..0x602973b

and the three ObjectLibrary FactoryEntry vtable installers:

  entry_install_1 0x5fcc5d0..0x5fcc5fd (vtable 0x64cd9d0)
  entry_install_2 0x5fcc600..0x5fcc62d (vtable 0x64cd9e0)
  entry_install_3 0x5fcc630..0x5fcc65d (vtable 0x64cd9f0)

The canonical continuation 0x5d4b100..0x5d4b20c and the lazy
resolver 0x5f074e0..0x5f07603 are re-shipped byte-identical
from the RE-001-lazy-resolver-115 packet (#3322); their
SHA-256 hashes are pinned in the README and checked by
verify.py.

Each excerpt is stored verbatim; verify.py checks that a fresh
run reproduces it byte-for-byte. Instruction-level detail lives
only in these excerpt text files, not in records.json. The
mnemonics in the excerpts (endbr64 included) are genuine
instructions present in the target binary, not placeholders.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("site_a.txt", 0x5DC9D70, 0x5DCA807),
    ("site_b.txt", 0x5E18D20, 0x5E19117),
    ("site_c.txt", 0x5F7D7D0, 0x5F7DE6E),
    ("site_d.txt", 0x5F865D0, 0x5F87065),
    ("vtable_install_1.txt", 0x5FD0090, 0x5FD0178),
    ("vtable_install_2.txt", 0x6029110, 0x602922B),
    ("vtable_install_3.txt", 0x6029230, 0x602934B),
    ("vtable_install_4.txt", 0x6029500, 0x602961B),
    ("vtable_install_5.txt", 0x6029620, 0x602973B),
    ("entry_install_1.txt", 0x5FCC5D0, 0x5FCC5FD),
    ("entry_install_2.txt", 0x5FCC600, 0x5FCC62D),
    ("entry_install_3.txt", 0x5FCC630, 0x5FCC65D),
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
