"""Regenerate the verbatim disassembly excerpts for the
RE-001-record-write-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-record-write-115/export_excerpts.py

Writes one excerpt per window. Whole-function excerpts cover
the record-write entry 0x5f0f930..0x5f10134 (516 bytes code),
the internal-key builder 0x5eab0c0..0x5eab192 (210 bytes), the
value-length reader 0x5f06f40..0x5f06f99 (89 bytes), the varint32
decoder 0x61bd4f0..0x61bd53b, and the bucket rwlock write-lock
0x60d5ab0..0x60d5b45 and unlock 0x60d5c30..0x60d5cc5 (149 bytes
each). The record insert 0x5f0e890..0x5f0f37e, the record
move-assign 0x5f05310..0x5f05379, the varint32 encoder
0x61bd410..0x61bd4e9, the once helper 0x5f07490..0x5f074d3 and
its predicate 0x5f07300..0x5f07481, the value resolve-and-store
0x5f09e90..0x5f09faf and the ProtectionInfo validation
0x5f09b10..0x5f09e84 are re-shipped byte-identical from #3330
(their SHA-256s are recorded in the README); the hash-bucket
projection 0x5f099b0..0x5f09a42 is re-shipped byte-identical
from upstream main (#2115, merged). The generator re-emits all
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
    ("main.txt", 0x5F0F930, 0x5F10134),
    ("key_build.txt", 0x5EAB0C0, 0x5EAB192),
    ("key_len.txt", 0x5F06F40, 0x5F06F99),
    ("varint_decode.txt", 0x61BD4F0, 0x61BD53B),
    ("rwlock_wrlock.txt", 0x60D5AB0, 0x60D5B45),
    ("rwlock_unlock.txt", 0x60D5C30, 0x60D5CC5),
    ("record_insert.txt", 0x5F0E890, 0x5F0F37E),
    ("record_move.txt", 0x5F05310, 0x5F05379),
    ("varint_encode.txt", 0x61BD410, 0x61BD4E9),
    ("once_helper.txt", 0x5F07490, 0x5F074D3),
    ("once_predicate.txt", 0x5F07300, 0x5F07481),
    ("value_resolve.txt", 0x5F09E90, 0x5F09FAF),
    ("protection_validate.txt", 0x5F09B10, 0x5F09E84),
    ("hash_bucket.txt", 0x5F099B0, 0x5F09A42),
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
