"""Regenerate the verbatim disassembly excerpts for the
RE-001-stats-version-fetch-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-stats-version-fetch-115/export_excerpts.py

Writes one whole-function file per pinned window (FDE range):
the stats version-key fetch, its exception cleanup block, the
default produce (canonical slot 0xe8), the forward produce
(canonical slot 0xf0), the cleanup-chain init/dtor pair, and
the two call-site windows in the sole caller (the persistent
stats column-family open at 0x5e61ad0). Six helpers are NOT
generated here: they are re-shipped byte-identical from PR
#3237 (state initializer, bound getter, version-key
initializer, string constructor, Status builder) and PR #3196
(decimal parser), whose packets map them in full. The
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
    ("main.txt", 0x606E3A0, 0x606EA29),
    ("cleanup.txt", 0x606E2EB, 0x606E39B),
    ("default_produce.txt", 0x5D33A90, 0x5D33C67),
    ("forward_produce.txt", 0x5D2D0E0, 0x5D2D127),
    ("chain_init.txt", 0x61BD0C0, 0x61BD0D4),
    ("chain_dtor.txt", 0x61BD0E0, 0x61BD131),
    ("site-5e61b9e.txt", 0x5E61B80, 0x5E61BA3),
    ("site-5e61bc6.txt", 0x5E61BA3, 0x5E61C54),
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
