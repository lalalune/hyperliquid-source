"""Export the verbatim objdump excerpts for the
RE-001-find-family-merge-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-find-family-merge-115/export_excerpts.py

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
parser, map_clear, status_builder, shared_release, matcher, resolver,
value_copy, value_dtor, cstr_ctor_60b7d80, walker, counted_release,
options_record_append, clear_string, plain_table, plain_table_cleanup,
block_table, block_table_cleanup, element_scan_host,
element_scan_host_cleanup, cstr_ctor_607d9f0, plain_creator, plain_ctor,
block_creator, block_ctor, options_list_destroy, map_find_name,
map_erase_next, map_insert and cstr_dup excerpts were already
exported byte-identical by the RE-001-find-family-hosts-115 (#3537)
packet; this script regenerates them from the same binary so the
packet stays self-contained, and verify.py checks them byte-for-byte
against a fresh objdump run like every other excerpt.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    # Core behaviour: the two sibling Find-family hosts.
    ("host_a.txt", 0x609D0E0, 0x609D75E),                # Find host A
    ("host_a_cleanup.txt", 0x609D08E, 0x609D0D8),        # its landing pad
    ("host_b.txt", 0x60BEDC0, 0x60BF5BC),                # kind-switch host B
    ("host_b_catch.txt", 0x60BEA8C, 0x60BEDBA),          # its landing pad
    # The merge driver and the worker wrapper (host A's callees).
    ("merge_driver.txt", 0x609C8C0, 0x609D08E),          # options-map merge
    ("worker_wrapper.txt", 0x6098510, 0x60985AF),        # worker wrapper
    ("range_ctor.txt", 0x60B7CD0, 0x60B7D73),            # string range ctor
    ("node_clone.txt", 0x6095B80, 0x6095CF9),            # options-map node clone
    ("rehash.txt", 0x5D38260, 0x5D3839D),                # hash-table rehash
    # The value parsers (host B's kind arms).
    ("escape_assign.txt", 0x61D10A0, 0x61D11E3),         # unescape-assign
    ("escape_decoder.txt", 0x61D0EE0, 0x61D0EFC),        # escape-char decoder
    ("bool_parser.txt", 0x61D1480, 0x61D1504),           # bool parser
    ("stoull_parser.txt", 0x61D1540, 0x61D178B),         # u64 stoull parser
    ("stoll_parser.txt", 0x61D18A0, 0x61D1AEB),          # i64 stoll parser
    ("stoi_parser.txt", 0x61D1B90, 0x61D1E0E),           # i32 stoi parser
    ("u32_parser.txt", 0x61D1840, 0x61D1866),            # u32 parser
    ("u8_parser.txt", 0x61D17D0, 0x61D17F6),             # u8 parser
    ("i32_parser.txt", 0x61D1B30, 0x61D1B5B),            # i32 via stoll
    ("stoull_alias.txt", 0x61D1EF0, 0x61D1EF9),          # u64 alias stub
    ("stod_parser.txt", 0x61D1E30, 0x61D1EE6),           # double stod parser
    ("hex_decode.txt", 0x61C7FC0, 0x61C80F4),             # hex decode
    ("hexval.txt", 0x61C7DC0, 0x61C7E16),                 # hex digit value
    # The seven enum lookups (six u8, one u32).
    ("enum_60be160.txt", 0x60BE160, 0x60BE2AB),          # enum map 0x65070a0
    ("enum_60be2b0.txt", 0x60BE2B0, 0x60BE3FB),          # enum map 0x6507060
    ("enum_60be400.txt", 0x60BE400, 0x60BE54B),          # enum map 0x6507120
    ("enum_60be550.txt", 0x60BE550, 0x60BE69B),          # enum map 0x6507160
    ("enum_60be6a0.txt", 0x60BE6A0, 0x60BE7EB),          # enum map 0x65070e0
    ("enum_60be7f0.txt", 0x60BE7F0, 0x60BE93B),          # u32, map 0x6507020
    ("enum_60be940.txt", 0x60BE940, 0x60BEA8B),          # enum map 0x6506fe0
    # Re-shipped byte-identical from #3537.
    ("plain_table.txt", 0x6080B10, 0x6080DCC),
    ("plain_table_cleanup.txt", 0x6080A71, 0x6080B0D),
    ("block_table.txt", 0x60818F0, 0x6081D08),
    ("block_table_cleanup.txt", 0x608183A, 0x60818EB),
    ("element_scan_host.txt", 0x6098AD0, 0x6099003),
    ("element_scan_host_cleanup.txt", 0x6098A9C, 0x6098ACE),
    ("walker.txt", 0x609BCB0, 0x609C782),
    ("cstr_ctor_607d9f0.txt", 0x607D9F0, 0x607DAD3),
    ("plain_creator.txt", 0x6193B40, 0x6193B7B),
    ("plain_ctor.txt", 0x6193A00, 0x6193B1C),
    ("block_creator.txt", 0x60DBD80, 0x60DBDBB),
    ("block_ctor.txt", 0x60DB710, 0x60DBD69),
    ("options_list_destroy.txt", 0x607E020, 0x607E1E9),
    ("map_find_name.txt", 0x609A1B0, 0x609A2E7),
    ("map_erase_next.txt", 0x609A2F0, 0x609A3DE),
    ("map_insert.txt", 0x609BAD0, 0x609BBB1),
    ("cstr_dup.txt", 0x61CF610, 0x61CF64F),
    ("counted_release.txt", 0x5D350C0, 0x5D35145),
    ("options_record_append.txt", 0x6099CE0, 0x6099E34),
    ("clear_string.txt", 0x60B79B0, 0x60B79DE),
    ("entry.txt", 0x609A740, 0x609B6F3),
    ("find_e70.txt", 0x6099E70, 0x609A1A9),
    ("no_equals.txt", 0x609BA30, 0x609BA76),
    ("resolve_no_equals.txt", 0x609B8A0, 0x609BA2A),
    ("kind_dispatch.txt", 0x609B700, 0x609B869),
    ("element_scan.txt", 0x6096F40, 0x609710F),
    ("name_lookup.txt", 0x60BA0B0, 0x60BA441),
    ("hash_name_find.txt", 0x60B84B0, 0x60B8564),
    ("move_assign.txt", 0x60B79E0, 0x60B7AB8),
    ("ends_with.txt", 0x61D1390, 0x61D13DB),
    ("str_compare.txt", 0x61D13E0, 0x61D1437),
    ("fallback_delegate.txt", 0x6097150, 0x6097192),
    ("delegate_impl.txt", 0x6097110, 0x609714E),
    ("zero_stub.txt", 0x60956F0, 0x609570C),
    ("find_norm.txt", 0x609A410, 0x609A67C),
    ("parser.txt", 0x60C1190, 0x60C1887),
    ("map_clear.txt", 0x5D5B300, 0x5D5B39B),
    ("status_builder.txt", 0x61CF670, 0x61CF767),
    ("shared_release.txt", 0x5D35070, 0x5D350BC),
    ("matcher.txt", 0x60BB9A0, 0x60BBDEB),
    ("resolver.txt", 0x60971C0, 0x609755B),
    ("value_copy.txt", 0x60B9D70, 0x60B9DFC),
    ("value_dtor.txt", 0x5E33FB0, 0x5E33FEA),
    ("cstr_ctor_60b7d80.txt", 0x60B7D80, 0x60B7E63),
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
