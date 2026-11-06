"""Export the verbatim objdump excerpts for the
RE-001-registry-find-sibling-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-registry-find-sibling-115/export_excerpts.py

Each excerpt is one whole function (FDE range) from the node #115
binary, dumped with objdump -d on the relative path
work/hl-node-115.bin, so the header line is reproducible
byte-for-byte against a fresh objdump run by verify.py.

Instruction-level detail lives only in these excerpt text files,
not in records.json. The mnemonics in the excerpts (endbr64
included) are genuine instructions present in the target binary,
not placeholders.

The find_norm, parser, map_clear, fallback_delegate,
delegate_impl and status_builder excerpts were already exported
byte-identical by the RE-001-registry-find-115 packet (#3485)
and the RE-001-registry-create-115 packet (#3440); this script
regenerates them from the same binary so the packet stays
self-contained, and verify.py checks them byte-for-byte against
a fresh objdump run like every other excerpt.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    # Core behaviour: the sibling Find entry point 0x609a740,
    # its '=' / ';' helper, its no-'=' helper, the kind
    # dispatcher and the element scan, the name lookup with its
    # dotted-name fallback, and the small string helpers.
    ("entry.txt", 0x609A740, 0x609B6F3),           # sibling Find entry
    ("find_e70.txt", 0x6099E70, 0x609A1A9),        # '=' / ';' helper
    ("no_equals.txt", 0x609BA30, 0x609BA76),       # no-'=' wrapper
    ("resolve_no_equals.txt", 0x609B8A0, 0x609BA2A),  # name fill + element scan
    ("kind_dispatch.txt", 0x609B700, 0x609B869),   # kind dispatch + recursion
    ("element_scan.txt", 0x6096F40, 0x609710F),    # element-vector scan
    ("name_lookup.txt", 0x60BA0B0, 0x60BA441),     # name lookup, dotted fallback
    ("hash_name_find.txt", 0x60B84B0, 0x60B8564),  # hash-bucket name find
    ("move_assign.txt", 0x60B79E0, 0x60B7AB8),     # std::string move-assign
    ("ends_with.txt", 0x61D1390, 0x61D13DB),       # suffix check (".id")
    ("str_compare.txt", 0x61D13E0, 0x61D1437),     # lexicographic string compare
    ("fallback_delegate.txt", 0x6097150, 0x6097192),  # fallback delegate wrapper
    ("delegate_impl.txt", 0x6097110, 0x609714E),   # delegate vtable slot 0x48 call
    ("zero_stub.txt", 0x60956F0, 0x609570C),       # zero-Status stub (slot 0x40 default)
    # Re-shipped byte-identical from #3485 / #3440.
    ("find_norm.txt", 0x609A410, 0x609A67C),       # Find normalizer
    ("parser.txt", 0x60C1190, 0x60C1887),          # '=' options parser
    ("map_clear.txt", 0x5D5B300, 0x5D5B39B),       # options-map clear
    ("status_builder.txt", 0x61CF670, 0x61CF767),  # Status(code, msg1, msg2)
    ("shared_release.txt", 0x5D35070, 0x5D350BC),  # shared_ptr control release
]


def main():
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        (PACKET / "excerpts" / name).write_text(text)
        print("wrote excerpts/%s (%d bytes)" % (name, len(text)))


if __name__ == "__main__":
    sys.exit(main())
