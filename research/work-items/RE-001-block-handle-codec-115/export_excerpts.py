"""Regenerate the verbatim disassembly excerpts for the
RE-001-block-handle-codec-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-block-handle-codec-115/export_excerpts.py

Writes encode_str.txt (0x6167d00..0x6167dc8, the std::string
EncodeTo body), encode_buf.txt (0x6167dd0..0x6167e2d, the char*
EncodeTo body), decode.txt (0x6167e30..0x6167f27, DecodeFrom),
varint64.txt (0x61bd540..0x61bd58b, the GetVarint64Ptr leaf) and
twin_encode_str.txt (0x5f38b10..0x5f38bd8, the second copy of the
std::string EncodeTo body).  The excerpts are stored verbatim;
verify.py checks that a fresh run reproduces them byte-for-byte.
Instruction-level detail lives only in these excerpt texts, not
in records.json.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("encode_str.txt", 0x6167D00, 0x6167DC8),
    ("encode_buf.txt", 0x6167DD0, 0x6167E2D),
    ("decode.txt", 0x6167E30, 0x6167F27),
    ("varint64.txt", 0x61BD540, 0x61BD58B),
    ("twin_encode_str.txt", 0x5F38B10, 0x5F38BD8),
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
