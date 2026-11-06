"""Export the verbatim objdump excerpts for the
RE-001-stats-ticker-map-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-stats-ticker-map-115/export_excerpts.py

Each excerpt is one whole function (FDE range) from the node #115
binary, dumped with objdump -d on the relative path
work/hl-node-115.bin, so the header line is reproducible
byte-for-byte against a fresh objdump run by verify.py.

Re-shipped excerpts (ticker_getter.txt, mutex_lock.txt,
mutex_unlock.txt) are copied byte-identical from the
RE-001-stats-produce-115 packet (#3362, branch
fix/stats-produce-115), not regenerated here; verify.py
regenerates every excerpt fresh from the binary and requires
byte-equality, which subsumes the re-ship check.

Instruction-level detail lives only in these excerpt text files,
not in records.json. The mnemonics in the excerpts (endbr64
included) are genuine instructions present in the target binary,
not placeholders.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("slotf0.txt", 0x6076030, 0x6076615),             # StatisticsImpl slot 0xf0
    ("cleanup_fragment.txt", 0x6075FF6, 0x607602A),   # shared exception cleanup
    ("tree_erase.txt", 0x60700D0, 0x607042D),         # _Rb_tree::_M_erase
    ("rebuild.txt", 0x5D58720, 0x5D58809),            # DBImpl rebuild (slot 0x2d0)
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
