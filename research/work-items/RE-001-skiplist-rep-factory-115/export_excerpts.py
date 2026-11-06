"""Regenerate the verbatim disassembly excerpts for the
RE-001-skiplist-rep-factory-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-skiplist-rep-factory-115/export_excerpts.py

Writes one excerpt per window. Whole-function excerpts cover the
SkipListFactory slot-19 factory 0x6063640, the ConcurrentArena
init 0x605e010, its +0x60 sub-init 0x605dd90, the small +0x80
init 0x605e810, the huge-page align helper 0x605cfa0, the arena
slot-4 stat getter 0x5f04da0, the slot-20 forwarder 0x5f04d90,
the SkipListRep slot-19 forwarder 0x5f04d80 (to slot 18) and the no-op
SkipListRep slots 10/11 (0x5f04d50/0x5f04d60). Two caller-site
windows cover the owner dispatch (0x5f104cd..0x5f105a0) and the
non-canonical slot-20 path (0x5f10c40..0x5f10c53); the owner
function itself (0x5f103f0..0x5f10cf8, 0x908 bytes) is a large
constructor whose other phases are separate work items (its
0x5f0b420 callee is already mapped by merged PR #2124).

Each excerpt is stored verbatim; verify.py checks that a fresh
run reproduces it byte-for-byte. Instruction-level detail lives
only in these excerpt text files, not in records.json. The
mnemonics in the excerpts (endbr64 included) are genuine
instructions present in the target binary, not placeholders.

Re-shipped byte-identical from an earlier packet (SHA-256 pinned
in verify.py): holder_ctor.txt from RE-001-skiplist-holder-115
(#3272).

NOT re-shipped, because merged PRs already mapped them and this
packet only cites them: the ConcurrentArena slot-2 allocate
0x5f11c40 (merged PR #2170), slot-3 AllocateAligned 0x5f117a0
(merged PR #2160), the slow-path block allocator 0x605d7b0
(merged PR #2150), the destructor pair 0x5f10180/0x5f10d00 and
the +0x60 member destructor 0x605cc30 (merged PR #2133).
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("factory.txt", 0x6063640, 0x6063752),
    ("holder_ctor.txt", 0x6064440, 0x6064551),
    ("arena_init.txt", 0x605E010, 0x605E163),
    ("arena_subinit.txt", 0x605DD90, 0x605DFCD),
    ("small_init.txt", 0x605E810, 0x605E826),
    ("huge_align.txt", 0x605CFA0, 0x605CFD6),
    ("arena_stat.txt", 0x5F04DA0, 0x5F04DAC),
    ("fwd_slot20.txt", 0x5F04D90, 0x5F04D9D),
    ("fwd_rep_slot19.txt", 0x5F04D80, 0x5F04D8D),
    ("noop_rep_slot10.txt", 0x5F04D50, 0x5F04D55),
    ("noop_rep_slot11.txt", 0x5F04D60, 0x5F04D65),
    ("owner_window.txt", 0x5F104CD, 0x5F105A0),
    ("owner_noncanon.txt", 0x5F10C40, 0x5F10C53),
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
