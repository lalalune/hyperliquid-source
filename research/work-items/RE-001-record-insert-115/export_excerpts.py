"""Regenerate the verbatim disassembly excerpts for the
RE-001-record-insert-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-record-insert-115/export_excerpts.py

Writes one excerpt per window. Whole-function excerpts cover
the record insert 0x5f0e890..0x5f0f37e (0xaee bytes), the map
find-or-insert 0x5f0e660..0x5f0e85f (0x1ff bytes), the 32-bit
hash 0x61c34a0..0x61c3525 (0x85 bytes), the varint32 encoder
0x61bd410..0x61bd4e9 (0xd9 bytes) and the record move-assign
0x5f05310..0x5f05379 (0x69 bytes). The value resolve-and-store
0x5f09e90..0x5f09faf and the ProtectionInfo validation
0x5f09b10..0x5f09e84 are re-shipped byte-identical from the
merged packets that pin them (RE-001-value-resolve-store-115
and RE-001-protection-info-validate-115); the once helper
0x5f07490..0x5f074d3 and its predicate 0x5f07300..0x5f07481
from #3304, the lazy resolver 0x5f074e0..0x5f07603 and its
canonical 0x5d4b100..0x5d4b20c from #3322, the release helper
0x5d350c0..0x5d35145 from #3263 and the Status builder
0x61cf670..0x61cf767 from #3251. The generator re-emits all
of them from the binary, so a re-ship is verified byte-for-byte
against a fresh objdump run by verify.py.

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
    ("main.txt", 0x5F0E890, 0x5F0F37E),
    ("hash_resolve.txt", 0x5F09E90, 0x5F09FAF),
    ("key_validate.txt", 0x5F09B10, 0x5F09E84),
    ("map_find_or_insert.txt", 0x5F0E660, 0x5F0E85F),
    ("hash32.txt", 0x61C34A0, 0x61C3525),
    ("varint_encode.txt", 0x61BD410, 0x61BD4E9),
    ("record_move.txt", 0x5F05310, 0x5F05379),
    ("once_helper.txt", 0x5F07490, 0x5F074D3),
    ("once_pred.txt", 0x5F07300, 0x5F07481),
    ("resolver.txt", 0x5F074E0, 0x5F07603),
    ("canonical.txt", 0x5D4B100, 0x5D4B20C),
    ("release.txt", 0x5D350C0, 0x5D35145),
    ("status_builder.txt", 0x61CF670, 0x61CF767),
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
