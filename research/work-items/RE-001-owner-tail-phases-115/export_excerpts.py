"""Regenerate the verbatim disassembly excerpts for the
RE-001-owner-tail-phases-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-owner-tail-phases-115/export_excerpts.py

Writes one excerpt per window. Whole-function excerpts cover the
owner 0x5f103f0..0x5f10cf8 (0x908 bytes, including its landing
pads), the rwlock element ctor 0x60d5880, the once-flag helper
0x5f07490, the once predicate 0x5f07300, the prologue helper
0x5f07230, the small-install descriptor builder 0x61c26f0, the
small-control _M_dispose 0x5f0a290, the small owner caller
0x5d8ca00 and the SkipListRep slot-15 zero stub 0x6062fb0. One
caller-site window covers the big caller 0x5ed01f0 around its
owner call (0x5ed086c..0x5ed08c6); the big caller's whole
function (0x5ed01f0..0x5ed2238, 0x2048 bytes) is out of scope,
only the call site and its argument setup are pinned.

The owner excerpt subsumes the two owner windows shipped by
PR #3286 (owner_window.txt 0x5f104cd..0x5f105a0 and
owner_noncanon.txt 0x5f10c40..0x5f10c53); those files are not
re-shipped here because the whole-function excerpt regenerates
the same bytes. The +0xd10 table init 0x5f0b420 is merged ground
(shared-table-resize, RE-001-shared-table-resize-115) and is
cited, not re-shipped; the release helper 0x5d350c0 and the
destroy dispatch 0x5d35070 are cited from earlier packets
(#3263, #3272) and from RE-001-shared-table-resize-115.

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
    ("owner.txt", 0x5F103F0, 0x5F10CF8),
    ("elem_ctor.txt", 0x60D5880, 0x60D5917),
    ("once_helper.txt", 0x5F07490, 0x5F074D3),
    ("once_pred.txt", 0x5F07300, 0x5F07481),
    ("prologue_helper.txt", 0x5F07230, 0x5F072F6),
    ("small_install.txt", 0x61C26F0, 0x61C27A8),
    ("small_dispose.txt", 0x5F0A290, 0x5F0A319),
    ("caller_small.txt", 0x5D8CA00, 0x5D8CA6A),
    ("caller_big_window.txt", 0x5ED086C, 0x5ED08C6),
    ("slot15.txt", 0x6062FB0, 0x6062FB7),
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
