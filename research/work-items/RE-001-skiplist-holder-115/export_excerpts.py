"""Regenerate the verbatim disassembly excerpts for the
RE-001-skiplist-holder-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-skiplist-holder-115/export_excerpts.py

Writes one whole-function excerpt per window. Each excerpt is
stored verbatim; verify.py checks that a fresh run reproduces
it byte-for-byte. Instruction-level detail lives only in these
excerpt text files, not in records.json. The mnemonics in the
excerpts (endbr64 included) are genuine instructions present
in the target binary, not placeholders.

Re-shipped byte-identical from earlier packets (SHA-256 pinned
in verify.py): holder_ctor.txt and pushback.txt from
RE-001-record-pushback-115 (#3257); base_init.txt from
RE-001-options-default-init-115 (#3254); release.txt from
RE-001-table-factory-role9-115 (#3263).
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("holder_ctor.txt", 0x6064440, 0x6064551),
    ("pushback.txt", 0x6099CE0, 0x6099E34),
    ("base_init.txt", 0x60B3C30, 0x60B3EEB),
    ("replace.txt", 0x5D946B0, 0x5D9518D),
    ("setter_skip.txt", 0x61935B0, 0x6193791),
    ("setter_hash.txt", 0x6193390, 0x6193559),
    ("hash_factory_ctor.txt", 0x605F150, 0x605F28E),
    ("release.txt", 0x5D350C0, 0x5D35145),
    ("dispatcher.txt", 0x6195290, 0x619686D),
    ("accessor_skip.txt", 0x6192860, 0x619288D),
    ("accessor_hash.txt", 0x6192890, 0x61928BD),
    ("parse_stub.txt", 0x61D1EF0, 0x61D1EF9),
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
