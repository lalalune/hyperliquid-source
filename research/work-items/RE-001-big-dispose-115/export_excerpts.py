"""Regenerate the verbatim disassembly excerpts for the
RE-001-big-dispose-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-big-dispose-115/export_excerpts.py

Writes one excerpt per window. Whole-function excerpts cover the
big control's _M_dispose 0x5f061b0..0x5f06548 (0x398 bytes), its
sort-phase callees 0x5f053d0 (__introsort_loop) and 0x5f05120
(__insertion_sort), the heapsort helper 0x5f04f80 (__adjust_heap)
called by the introsort fallback, the tree destroy 0x5f059b0
that releases each +0x60 node's subtree, and the Cleanable
drain 0x61bd0e0 with its init 0x61bd0c0.

The embedded clear object at state+0x98 is the same layout the
merged RE-001-sorted-unique-clear-50470-115 packet pins for the
standalone routine 0x5d50470; that packet is cited, not
re-shipped, and its sort callees (0x5d4a3f0/0x5d497e0) are a
different instantiation from the ones pinned here. The small
control's _M_dispose 0x5f0a290, the release helper 0x5d350c0,
the destroy dispatch 0x5d35070 and the release-loop helper
0x5f0a1dc are cited from #3304/#3263, not re-shipped.

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
    ("big_dispose.txt", 0x5F061B0, 0x5F06548),
    ("introsort.txt", 0x5F053D0, 0x5F05678),
    ("insertion_sort.txt", 0x5F05120, 0x5F051F5),
    ("adjust_heap.txt", 0x5F04F80, 0x5F0511D),
    ("tree_destroy.txt", 0x5F059B0, 0x5F05B79),
    ("cleanable_drain.txt", 0x61BD0E0, 0x61BD131),
    ("cleanable_init.txt", 0x61BD0C0, 0x61BD0D4),
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
