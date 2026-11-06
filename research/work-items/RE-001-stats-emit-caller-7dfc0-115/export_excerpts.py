"""Regenerate the verbatim disassembly excerpts for the
RE-001-stats-emit-caller-7dfc0-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-stats-emit-caller-7dfc0-115/export_excerpts.py

Writes whole-function verbatim excerpts for the stats-emit caller
0x5d7dfc0..0x5d7e627, its shared cleanup fragment
0x5d7dede..0x5d7dfba, the pinned callees, and the per-site windows
for the caller's own call sites. The excerpts are stored verbatim;
verify.py checks that a fresh run reproduces them byte-for-byte.
Instruction-level detail lives only in these excerpt texts, not in
records.json. The acquire and stats-emit excerpts are re-shipped
byte-identical from their own packets so this packet verifies
standalone; see README.md.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x5D7DFC0, 0x5D7E627),
    ("cleanup.txt", 0x5D7DEDE, 0x5D7DFBA),
    ("string_assign.txt", 0x5D4AB80, 0x5D4AC63),
    ("version_release.txt", 0x5D911E0, 0x5D912A3),
    ("mutex_unlock.txt", 0x60D52F0, 0x60D5385),
    ("noop_hook.txt", 0x5F04CE0, 0x5F04CE5),
    ("identity.txt", 0x5D3A940, 0x5D3A945),
    ("log_dispatch.txt", 0x5FCF060, 0x5FCF153),
    ("registry_lookup.txt", 0x5EEE790, 0x5EEE9E7),
    ("trim_invoke.txt", 0x5EEE9F0, 0x5EEEA59),
    ("acquire.txt", 0x606CA40, 0x606CC6A),
    ("stats_emit.txt", 0x5D52020, 0x5D520C1),
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
