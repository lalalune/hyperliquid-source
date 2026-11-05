"""Regenerate the verbatim disassembly excerpts for the
RE-001-stats-snapshot-insert-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-stats-snapshot-insert-115/export_excerpts.py

Writes one whole-function file per pinned window (FDE range):
the stats-snapshot insert, its caller, the B-slot wrapper, the
state initializer, the two getters, the node initializer, the
locked lookup, the map copy, the lower-bound helper, the key
comparator, the two node destructors, the two tree-free twins,
the remaining vtable slots of both node types, the static
initializer of the version-key table, and the string
constructor it uses. Five helpers are NOT generated here:
they are re-shipped byte-identical from PR #2592 (delimited
key parse), PR #3196 (decimal parser), PR #3221 (hex helper,
Status builder, strdup), whose packets map them in full. The
excerpts are stored verbatim; verify.py checks that a fresh
run reproduces them byte-for-byte. Instruction-level detail
lives only in these excerpt texts, not in records.json. The
mnemonics in them (endbr64 included) are genuine instructions
present in the target binary, not placeholders.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x606EF50, 0x606F91F),
    ("caller.txt", 0x5D4CC80, 0x5D4CE6A),
    ("wrapper.txt", 0x606F920, 0x606F94B),
    ("state_init.txt", 0x60B21F0, 0x60B2262),
    ("bound_getter.txt", 0x5D532D0, 0x5D532DC),
    ("count_getter.txt", 0x606DE00, 0x606DE09),
    ("node_init.txt", 0x606C680, 0x606C6A5),
    ("locked_lookup.txt", 0x5D52660, 0x5D52765),
    ("map_copy.txt", 0x5D4E140, 0x5D4E257),
    ("lower_bound.txt", 0x5D6C600, 0x5D6C79B),
    ("comparator.txt", 0x5D498C0, 0x5D4990E),
    ("dtor_a.txt", 0x606C5E0, 0x606C657),
    ("dtor_b.txt", 0x606E250, 0x606E2C7),
    ("tree_free_a.txt", 0x606C280, 0x606C5DD),
    ("tree_free_b.txt", 0x606DEF0, 0x606E24D),
    ("slot1_a.txt", 0x606C660, 0x606C67B),
    ("slot1_b.txt", 0x606E2D0, 0x606E2EB),
    ("slot2_a.txt", 0x606C180, 0x606C189),
    ("slot2_b.txt", 0x606DDF0, 0x606DDF9),
    ("slot3_a.txt", 0x606C6B0, 0x606C6DB),
    ("slot4_a.txt", 0x606C190, 0x606C199),
    ("slot5.txt", 0x606C170, 0x606C17A),
    ("slot6_a.txt", 0x606C1A0, 0x606C1A9),
    ("slot6_b.txt", 0x606DE10, 0x606DE19),
    ("slot7_a.txt", 0x606C1E0, 0x606C278),
    ("slot7_b.txt", 0x606DE50, 0x606DEE8),
    ("initializer.txt", 0x606F950, 0x606FA16),
    ("string_ctor.txt", 0x5F204E0, 0x5F205C3),
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
