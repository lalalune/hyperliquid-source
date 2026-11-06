"""Regenerate the verbatim disassembly excerpts for the
RE-001-block-builder-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-block-builder-115/export_excerpts.py

Writes ctor.txt (0x6129a00..0x6129b0b, the BlockBuilder
constructor), estimate.txt (0x6129b10..0x6129c0d,
EstimateSizeAfterKV), finish.txt (0x6129c10..0x6129d88, Finish),
reset.txt (0x6129f60..0x612a000, Reset), add.txt
(0x612a1b0..0x612a4f2, Add), hash_add.txt (0x612ca80..0x612cc47,
DataBlockHashIndexBuilder::Add), hash_finish.txt
(0x612cc80..0x612ce0c, DataBlockHashIndexBuilder::Finish),
hash_reset.txt (0x612ce10..0x612ce2f, the annex reset helper),
trailer.txt (0x612ce90..0x612cea6, the block trailer word helper)
and hash.txt (0x61c34a0..0x61c3525, rocksdb::Hash).  The excerpts
are stored verbatim; verify.py checks that a fresh run reproduces
them byte-for-byte.  Instruction-level detail lives only in these
excerpt texts, not in records.json.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("ctor.txt", 0x6129A00, 0x6129B0B),
    ("estimate.txt", 0x6129B10, 0x6129C0D),
    ("finish.txt", 0x6129C10, 0x6129D88),
    ("reset.txt", 0x6129F60, 0x612A000),
    ("add.txt", 0x612A1B0, 0x612A4F2),
    ("hash_add.txt", 0x612CA80, 0x612CC47),
    ("hash_finish.txt", 0x612CC80, 0x612CE0C),
    ("hash_reset.txt", 0x612CE10, 0x612CE2F),
    ("trailer.txt", 0x612CE90, 0x612CEA6),
    ("hash.txt", 0x61C34A0, 0x61C3525),
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
