"""Export the verbatim objdump excerpts for the RE-001-serializer-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-serializer-115/export_excerpts.py

Each excerpt is one whole function (FDE range) from the node #115
binary, dumped with objdump -d on the relative path
work/hl-node-115.bin, so the header line is reproducible
byte-for-byte against a fresh objdump run by verify.py.

Instruction-level detail lives only in these excerpt text files,
not in records.json. The mnemonics in the excerpts (endbr64
included) are genuine instructions present in the target binary,
not placeholders.

The move_assign excerpt was already exported byte-identical by the
RE-001-registry-find-sibling-115 (#3488) packet; this script
regenerates it from the same binary so the packet stays
self-contained, and verify.py checks it byte-for-byte against a
fresh objdump run like every other excerpt.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    # Core behaviour: the value serializer and its jump table.
    ("serializer.txt", 0x60BA600, 0x60BB855),            # 25-kind serializer
    # Its direct callees.
    ("int_to_string.txt", 0x5F06BB0, 0x5F06F38),         # signed i32 decimal
    ("snprintf_string.txt", 0x60BA450, 0x60BA600),       # vsnprintf into string
    ("escape_copy.txt", 0x61D0F30, 0x61D108E),           # backslash-escape copy
    ("escape_copy_cleanup.txt", 0x61D0F1C, 0x61D0F2C),    # its landing pad
    ("escape_predicate.txt", 0x61D0E90, 0x61D0ED5),      # needs-escape test
    ("escape_letter.txt", 0x61D0F00, 0x61D0F1C),         # escape letter
    ("hex_encode.txt", 0x61C7E30, 0x61C7FB6),            # hex encode / raw copy
    ("hexchar.txt", 0x61C7DA0, 0x61C7DB2),               # nibble -> hex char
    # Re-shipped byte-identical from #3488.
    ("move_assign.txt", 0x60B79E0, 0x60B7AB8),           # string move-assign
]


def main():
    (PACKET / "excerpts").mkdir(exist_ok=True)
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        (PACKET / "excerpts" / name).write_text(text)
        print("wrote excerpts/%s (%d bytes)" % (name, len(text)))


if __name__ == "__main__":
    sys.exit(main())
