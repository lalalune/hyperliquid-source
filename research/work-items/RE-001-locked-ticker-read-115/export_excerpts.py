"""Export the verbatim objdump excerpts for the
RE-001-locked-ticker-read-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-locked-ticker-read-115/export_excerpts.py

Each excerpt is one whole function (FDE range) from the node #115
binary, dumped with objdump -d on the relative path
work/hl-node-115.bin, so the header line is reproducible
byte-for-byte against a fresh objdump run by verify.py.

Re-shipped excerpts (ticker_getter.txt from
RE-001-stats-ticker-map-115 #3378; histogram_builder.txt,
mutex_lock.txt, mutex_unlock.txt from RE-001-stats-produce-115
#3362) are copied byte-identical, not regenerated here;
verify.py regenerates every excerpt fresh from the binary and
requires byte-equality, which subsumes the re-ship check.

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
    ("locked_ticker.txt", 0x6070490, 0x60704D2),         # slot 0x98 locked read
    ("landing_pad.txt", 0x607047E, 0x607048E),           # 0x98 exception cleanup
    ("locked_percentiles.txt", 0x6070610, 0x60706C9),    # slot 0xa0
    ("locked_histogram_text.txt", 0x6070700, 0x60707C1),  # slot 0xa8
    ("shared_cleanup.txt", 0x60706CA, 0x60706FE),        # delete temp + unlock
    ("builder_cleanup.txt", 0x60705D8, 0x607060C),       # builder-callers cleanup
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
