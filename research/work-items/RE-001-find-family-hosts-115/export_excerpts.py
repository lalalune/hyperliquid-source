"""Export the verbatim objdump excerpts for the
RE-001-find-family-hosts-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-find-family-hosts-115/export_excerpts.py

Each excerpt is one whole function (FDE range) from the node #115
binary, dumped with objdump -d on the relative path
work/hl-node-115.bin, so the header line is reproducible
byte-for-byte against a fresh objdump run by verify.py.

Instruction-level detail lives only in these excerpt text files,
not in records.json. The mnemonics in the excerpts (endbr64
included) are genuine instructions present in the target binary,
not placeholders.

The entry, find_e70, no_equals, resolve_no_equals, kind_dispatch,
element_scan, name_lookup, hash_name_find, move_assign, ends_with,
str_compare, fallback_delegate, delegate_impl, zero_stub, find_norm,
parser, map_clear, status_builder and shared_release excerpts were
already exported byte-identical by the RE-001-registry-find-115
(#3485) and RE-001-registry-find-sibling-115 (#3488) packets; the
matcher, resolver, value_copy, value_dtor and cstr_ctor_60b7d80
excerpts by #3485; this script regenerates them from the same
binary so the packet stays self-contained, and verify.py checks
them byte-for-byte against a fresh objdump run like every other
excerpt.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    # Core behaviour: the four sibling Find-family hosts.
    ("plain_table.txt", 0x6080B10, 0x6080DCC),          # PlainTableOptions host
    ("plain_table_cleanup.txt", 0x6080A71, 0x6080B0D),   # its landing pad
    ("block_table.txt", 0x60818F0, 0x6081D08),          # BlockTableOptions host
    ("block_table_cleanup.txt", 0x608183A, 0x60818EB),   # its landing pad
    ("element_scan_host.txt", 0x6098AD0, 0x6099003),     # element-scan host
    ("element_scan_host_cleanup.txt", 0x6098A9C, 0x6098ACE),  # its landing pad
    ("walker.txt", 0x609BCB0, 0x609C782),                # registry walker
    # New helpers called by the hosts.
    ("cstr_ctor_607d9f0.txt", 0x607D9F0, 0x607DAD3),     # string ctor from cstr
    ("plain_creator.txt", 0x6193B40, 0x6193B7B),         # new PlainTableOptions
    ("plain_ctor.txt", 0x6193A00, 0x6193B1C),            # PlainTableOptions ctor
    ("block_creator.txt", 0x60DBD80, 0x60DBDBB),         # new BlockTableOptions
    ("block_ctor.txt", 0x60DB710, 0x60DBD69),            # BlockTableOptions ctor
    ("options_list_destroy.txt", 0x607E020, 0x607E1E9),  # options-list destroy
    ("map_find_name.txt", 0x609A1B0, 0x609A2E7),         # hash-map find by name
    ("map_erase_next.txt", 0x609A2F0, 0x609A3DE),        # hash-map erase, next
    ("map_insert.txt", 0x609BAD0, 0x609BBB1),            # hash-map insert
    ("cstr_dup.txt", 0x61CF610, 0x61CF64F),              # strdup-like helper
    ("counted_release.txt", 0x5D350C0, 0x5D35145),        # counted-base release
    ("options_record_append.txt", 0x6099CE0, 0x6099E34),  # options-record append
    ("clear_string.txt", 0x60B79B0, 0x60B79DE),           # string clear helper
    # Re-shipped byte-identical from #3485 / #3488.
    ("entry.txt", 0x609A740, 0x609B6F3),                 # sibling Find entry
    ("find_e70.txt", 0x6099E70, 0x609A1A9),              # '=' / ';' helper
    ("no_equals.txt", 0x609BA30, 0x609BA76),             # no-'=' wrapper
    ("resolve_no_equals.txt", 0x609B8A0, 0x609BA2A),     # name fill + element scan
    ("kind_dispatch.txt", 0x609B700, 0x609B869),         # kind dispatch + recursion
    ("element_scan.txt", 0x6096F40, 0x609710F),          # element-vector scan
    ("name_lookup.txt", 0x60BA0B0, 0x60BA441),           # name lookup, dotted fallback
    ("hash_name_find.txt", 0x60B84B0, 0x60B8564),        # hash-bucket name find
    ("move_assign.txt", 0x60B79E0, 0x60B7AB8),           # std::string move-assign
    ("ends_with.txt", 0x61D1390, 0x61D13DB),             # suffix check (".id")
    ("str_compare.txt", 0x61D13E0, 0x61D1437),           # lexicographic string compare
    ("fallback_delegate.txt", 0x6097150, 0x6097192),     # fallback delegate wrapper
    ("delegate_impl.txt", 0x6097110, 0x609714E),         # delegate vtable slot 0x48 call
    ("zero_stub.txt", 0x60956F0, 0x609570C),             # zero-Status stub (slot 0x40 default)
    ("find_norm.txt", 0x609A410, 0x609A67C),             # Find normalizer
    ("parser.txt", 0x60C1190, 0x60C1887),                # '=' options parser
    ("map_clear.txt", 0x5D5B300, 0x5D5B39B),             # options-map clear
    ("status_builder.txt", 0x61CF670, 0x61CF767),        # Status(code, msg1, msg2)
    ("shared_release.txt", 0x5D35070, 0x5D350BC),        # shared_ptr control release
    ("matcher.txt", 0x60BB9A0, 0x60BBDEB),               # kind-0x15/0x16 matcher
    ("resolver.txt", 0x60971C0, 0x609755B),              # name resolver
    ("value_copy.txt", 0x60B9D70, 0x60B9DFC),            # value-struct copy
    ("value_dtor.txt", 0x5E33FB0, 0x5E33FEA),            # value-struct destroy
    ("cstr_ctor_60b7d80.txt", 0x60B7D80, 0x60B7E63),     # string ctor from cstr
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
