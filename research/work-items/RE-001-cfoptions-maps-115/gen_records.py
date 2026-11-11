#!/usr/bin/env python3
"""Build the semantic record set for RE-001-cfoptions-maps-115.

Reads the census TSVs (blocks, specials, ranges, atexit, sections,
helpers) and emits records.json (semantic records only, no
per-instruction mnemonic list) and entries.tsv (the flat 114-row
table).  All values come from census.py's resolution of the verbatim
objdump of the static initializer 0x6089b50..0x6091e5c.

Type names follow the convention pinned in #4237; the exact C++ enum
names for types 3 vs 7 vs 8, 4 vs 6, and 5 / 23 are still open (see
open_unknowns) and are labelled by their numeric code's #4237 label.
Verification: 0 = normal, 1/2/3/5 = checked (distinct check kinds,
not yet distinguished), 4 = the apply path accepts and ignores the
entry (never dereferences the offset).

Usage: python3 gen_records.py  (run from the repo root)
"""

import csv
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

TYPE_NAMES = {
    0: "bool", 1: "int32", 2: "uint32", 3: "uint64", 4: "uint32",
    5: "1-byte", 6: "uint32", 7: "uint64", 8: "size_t", 9: "string",
    10: "double", 11: "named-enum", 12: "named-enum", 13: "named-enum",
    14: "named-enum", 15: "named-enum", 16: "named-enum", 17: "struct",
    18: "enum", 19: "struct", 20: "vector", 21: "struct", 22: "struct",
    23: "string-like", 24: "named-enum", 26: "shared-ptr/struct",
}

MAPS = [
    ("CompressionOptions", "0x6506be0", 0, 8, "0x608a584"),
    ("CompactionOptionsFIFO", "0x6506ba0", 9, 12, "0x608aa76"),
    ("CompactionOptionsUniversal", "0x6506b60", 13, 20, "0x608b23d"),
    ("MutableCFOptions", "0x6506b20", 21, 74, "0x608ec56"),
    ("ImmutableCFOptions", "0x6506ae0", 75, 97, "0x6090e68"),
]

SPECIAL_MAP = {
    "max_bytes_for_level_multiplier_additional": "MutableCFOptions",
    "prefix_extractor": "MutableCFOptions",
    "compaction_options_fifo": "MutableCFOptions",
    "compaction_options_universal": "MutableCFOptions",
    "prepopulate_blob_cache": "MutableCFOptions",
    "compression_per_level": "MutableCFOptions",
    "comparator": "ImmutableCFOptions",
    "memtable_insert_with_hint_prefix_extractor": "ImmutableCFOptions",
    "table_factory": "ImmutableCFOptions",
    "table_properties_collectors": "ImmutableCFOptions",
    "compaction_filter": "ImmutableCFOptions",
    "compaction_filter_factory": "ImmutableCFOptions",
    "merge_operator": "ImmutableCFOptions",
    "sst_partitioner_factory": "ImmutableCFOptions",
}

PAIR_MOVE_SPECIALS = [
    {"name": "compression_opts", "map": "MutableCFOptions",
     "offset": 0x158, "type": 19, "verification": 0, "flags": 0x101,
     "sub_map": "0x6506be0", "section": "compression_opts",
     "builder_call": "0x608eb58", "pair_move_call": "0x608eb72",
     "template": "-0x5e90(%rbp)", "pair": "-0x1f0(%rbp)"},
    {"name": "bottommost_compression_opts", "map": "MutableCFOptions",
     "offset": 0x188, "type": 19, "verification": 0, "flags": 0x101,
     "sub_map": "0x6506be0", "section": "bottommost_compression_opts",
     "builder_call": "0x608ebe5", "pair_move_call": "0x608ec1b",
     "template": "-0x5dd0(%rbp)", "pair": "-0x118(%rbp)"},
]

CONSUMERS = [
    {"function": "0x6086e00", "fde": "0x6086e00..0x608818d",
     "role": "CFOptions OPTIONS-file dump: serializes the MutableCFOptions "
             "map (0x6506b20) under the literal 'MutableCFOptions' and the "
             "ImmutableCFOptions map (0x6506ae0) under 'ImmutableCFOptions' "
             "via the per-map serializer 0x6099ce0; this consumer is what "
             "proves the two map names",
     "maps": ["0x6506b20", "0x6506ae0"]},
    {"function": "0x607dd50", "fde": "0x607dd50..0x607ddab",
     "role": "section-name matcher: memcmp against the literal "
             "'ColumnFamilyOptions'",
     "maps": ["0x6506ac0"]},
    {"function": "0x607e560", "fde": "0x607e560..0x607e6e9",
     "role": "FIFO-section parser: builds the section name "
             "'compaction_options_fifo' and parses it through the shared "
             "per-section parser 0x60c1d50 with the CompactionOptionsFIFO "
             "map (0x6506ba0)",
     "maps": ["0x6506ba0"]},
    {"function": "0x60833b0", "fde": "0x60833b0..0x6083484",
     "role": "nested CompressionOptions section parser for "
             "'bottommost_compression_opts' through 0x60c1d50 with the "
             "CompressionOptions map (0x6506be0)",
     "maps": ["0x6506be0"]},
    {"function": "0x6083490", "fde": "0x6083490..0x6083564",
     "role": "nested CompressionOptions section parser for "
             "'compression_opts' through 0x60c1d50 with the "
             "CompressionOptions map (0x6506be0)",
     "maps": ["0x6506be0"]},
    {"function": "0x60c4550", "fde": "0x60c4550..0x60c46b8",
     "role": "writes the 'ColumnFamilyOptions' section header via "
             "0x60c3e10",
     "maps": ["0x6506ac0"]},
]


def read_tsv(name):
    with open(HERE / name) as f:
        return list(csv.DictReader(f, delimiter="\t"))


def main():
    blocks = read_tsv("blocks.tsv")
    specials = read_tsv("specials.tsv")
    ranges = read_tsv("ranges.tsv")
    atexit = read_tsv("atexit.tsv")
    sections = read_tsv("sections.tsv")
    helpers = read_tsv("helpers.tsv")

    entries = []
    for b in blocks:
        lo, hi = None, None
        for (mname, mglobal, blo, bhi, _) in MAPS:
            if blo <= int(b["block"]) <= bhi:
                lo, hi = mname, mglobal
                break
        typ = int(b["type"])
        entries.append({
            "map": lo, "map_global": hi, "name": b["name"],
            "offset": int(b["offset"]),
            "offset_hex": f"0x{int(b['offset']):x}",
            "type": typ, "type_name": TYPE_NAMES[typ],
            "verification": int(b["verification"]),
            "flags": int(b["flags"]),
            "flags_hex": f"0x{int(b['flags']):x}",
            "source": {"kind": "pair-ctor", "block": int(b["block"]),
                       "call": b["call"], "builder": b["builder"],
                       "pair_dest": b["pair_dest"],
                       "key_temp": b["key_temp"],
                       "value_temp": b["value_temp"]},
        })
    for s in specials:
        typ = int(s["type"])
        entries.append({
            "map": SPECIAL_MAP[s["key"]],
            "map_global": ("0x6506b20" if SPECIAL_MAP[s["key"]]
                           == "MutableCFOptions" else "0x6506ae0"),
            "name": s["key"],
            "offset": int(s["offset"]),
            "offset_hex": f"0x{int(s['offset']):x}",
            "type": typ, "type_name": TYPE_NAMES[typ],
            "verification": int(s["verification"]),
            "flags": int(s["flags"]),
            "flags_hex": f"0x{int(s['flags']):x}",
            "source": {"kind": "value-move", "call": s["call"],
                       "how": s["how"],
                       "pair_key_temp": s["pair_key_temp"],
                       "value_dest": s["value_dest"],
                       "src_temp": s["src"]},
        })
    for pm in PAIR_MOVE_SPECIALS:
        entries.append({
            "map": pm["map"], "map_global": "0x6506b20",
            "name": pm["name"],
            "offset": pm["offset"],
            "offset_hex": f"0x{pm['offset']:x}",
            "type": pm["type"], "type_name": TYPE_NAMES[pm["type"]],
            "verification": pm["verification"],
            "flags": pm["flags"],
            "flags_hex": f"0x{pm['flags']:x}",
            "source": {"kind": "pair-move",
                       "builder_call": pm["builder_call"],
                       "pair_move_call": pm["pair_move_call"],
                       "template": pm["template"], "pair": pm["pair"]},
        })

    # order: by map, then by offset (stable within a map by name for
    # the offset-0 ignored entries)
    map_order = {m[0]: i for i, m in enumerate(MAPS)}
    entries.sort(key=lambda e: (map_order[e["map"]], e["offset"],
                                e["name"]))
    assert len(entries) == 114, len(entries)

    maps_rec = []
    for (mname, mglobal, blo, bhi, rcall) in MAPS:
        r = next(x for x in ranges if x["map"] == mglobal)
        n = sum(1 for e in entries if e["map"] == mname)
        maps_rec.append({
            "name": mname, "global": mglobal, "entries": n,
            "pair_blocks": f"{blo}-{bhi}",
            "range_ctor_call": rcall,
            "range": {"first": r["first"], "last": r["last"]},
            "pair_stride": "0xd8",
        })

    sub_maps = [
        {"entry": "compaction_options_fifo", "map": "MutableCFOptions",
         "sub_map": "0x6506ba0", "sub_map_name": "CompactionOptionsFIFO",
         "builder": "type19-5e32c70", "call": "0x608d909"},
        {"entry": "compaction_options_universal",
         "map": "MutableCFOptions", "sub_map": "0x6506b60",
         "sub_map_name": "CompactionOptionsUniversal",
         "builder": "type19-5e32c70", "call": "0x608d9d3"},
        {"entry": "compression_opts", "map": "MutableCFOptions",
         "sub_map": "0x6506be0", "sub_map_name": "CompressionOptions",
         "builder": "nested-wrap-607f1b0", "call": "0x608eb58"},
        {"entry": "bottommost_compression_opts",
         "map": "MutableCFOptions", "sub_map": "0x6506be0",
         "sub_map_name": "CompressionOptions",
         "builder": "nested-wrap-607f1b0", "call": "0x608ebe5"},
    ]

    ignored = [e["name"] for e in entries if e["verification"] == 4]
    records = {
        "task": "RE-001",
        "work_item": "RE-001-cfoptions-maps-115",
        "node": 115,
        "artifact": {
            "binary": "work/hl-node-115.bin",
            "sha256": ARTIFACT_SHA256,
            "provenance": "provenance/artifacts.json",
        },
        "initializer": {
            "function": "0x6089b50",
            "fde": "0x6089b50..0x6091e5c",
            "size_bytes": "0x830c",
            "thunk": "0x6093030..0x6093039",
            "init_array_index": 93,
            "invocation": ".init_array[93] holds a RELATIVE relocation "
                          "to the thunk 0x6093030, which jumps to "
                          "0x6089b50 (the .init_array entries are all 0 "
                          "in the PIE file; verified via .rela.dyn and "
                          "a byte-scan for direct calls to 0x6089b50, "
                          "single hit at 0x6093034)",
        },
        "maps": maps_rec,
        "entries": entries,
        "sub_maps": sub_maps,
        "sections": [{"literal": s["literal"], "global": s["dest"],
                      "string_ctor_call": s["call"]}
                     for s in sections],
        "consumers": CONSUMERS,
        "shared_helpers": {
            "per_section_parser": "0x60c1d50 (FDE 0x60c1d50..0x60c26d5; "
                "calls the per-entry apply 0x60bedc0 x2 and the map "
                "lookup 0x60ba0b0 x2)",
            "per_map_serializer": "0x6099ce0 (FDE 0x6099ce0..0x6099e34; "
                "calls 0x6099790)",
            "pair_ctor": "0x5d400f0 (98 calls)",
            "range_ctor": "0x5d405b0 (5 calls)",
            "record_dtor": "0x5d3f950 (128 calls)",
            "map_dtor": "0x5d3f820 (5 __cxa_atexit registrations)",
            "value_move_ctors": "0x5e32b10 and 0x5e332c0",
            "string_ctor": "0x607d9f0 (122 calls)",
        },
        "atexit": [{"call": a["call"], "func": a["func"],
                    "object": a["obj"], "dso": a["dso"]}
                   for a in atexit],
        "findings": [
            "The static initializer builds FIVE OptionTypeInfo maps, "
            "not one: CompressionOptions (9), CompactionOptionsFIFO "
            "(4), CompactionOptionsUniversal (8), MutableCFOptions "
            "(62), ImmutableCFOptions (31) = 114 entries. The "
            "Mutable/Immutable split is proven by the consumer "
            "0x6086e00, which serializes map 0x6506b20 under the "
            "literal 'MutableCFOptions' and map 0x6506ae0 under "
            "'ImmutableCFOptions'.",
            "This resolves the first open unknown of #4239: "
            "PrepopulateBlobCache's map home is MutableCFOptions "
            "(offset 0x144, type 18 enum, verification 0, flags "
            "0x100); it is built by the enum helper 0x6083c90, which "
            "hardcodes type 18 at value+0xa8.",
            "Three names address the same TableFactory field at "
            "ImmutableCFOptions+0x78: table_factory (type 22, "
            "verification 1, flags 0xc402), block_based_table_factory "
            "and plain_table_factory (type 22, verification 5, flags "
            "0x402). Two names address the MemTableFactory field at "
            "ImmutableCFOptions+0x68: memtable_factory (verification "
            "1) and memtable (verification 5), both type 22, flags "
            "0x400. The binary literally builds separate entries at "
            "the same offset with different verification/flags, so "
            "the names are aliases of one field with different "
            "parse/verify behaviour.",
            f"{len(ignored)} entries carry verification 4: the apply "
            "path accepts and ignores them and never dereferences "
            "their offset, so all of them record offset 0. They are: "
            + ", ".join(ignored) + ".",
            "Each map's first entry sits at its struct's offset 0 "
            "with verification 0 (a genuine first field, not an "
            "ignored entry): window_bits (CompressionOptions), "
            "max_table_files_size (CompactionOptionsFIFO), size_ratio "
            "(CompactionOptionsUniversal), write_buffer_size "
            "(MutableCFOptions), compaction_style (ImmutableCFOptions).",
            "CompactionOptionsFIFO's ttl entry is verification 4 / "
            "offset 0 (accepted-and-ignored, like #4237's offset-0 "
            "entries); the binary field order is "
            "max_table_files_size @0, allow_compaction @8, "
            "age_for_warm @16.",
            "Nested entries route through sub-maps: "
            "compaction_options_fifo -> CompactionOptionsFIFO, "
            "compaction_options_universal -> "
            "CompactionOptionsUniversal, compression_opts and "
            "bottommost_compression_opts -> CompressionOptions. The "
            "last two are built by the nested-template builder "
            "0x607f1b0, which delegates to the type-19 builder "
            "0x5e32c70, and installed by the pair-move helper "
            "0x60842a0.",
            "The two vector entries (max_bytes_for_level_multiplier_"
            "additional @0xc0 and compression_per_level @0x1c8) are "
            "built by the vector helpers 0x6083570 / 0x6083d80, which "
            "hardcode type 20 at value+0xa8 and take an element tag "
            "0x3a in r9d.",
            "The DBOptions section string (0x6506c80) is NOT built by "
            "this initializer: it belongs to the sibling DBOptions "
            "initializer analysed in #4237. This initializer builds "
            "seven section strings (Version, CFOptions, "
            "TableOptions/, Unknown, compression_opts, "
            "bottommost_compression_opts, ColumnFamilyOptions).",
        ],
        "corrections_to_prior_prs": [
            "None: #4237's single-map claim was already corrected by "
            "#4237 itself (two maps), and #4239's open unknown about "
            "PrepopulateBlobCache's map home is resolved here, not "
            "corrected. No #4237/#4239 entry value is changed by "
            "this packet.",
        ],
        "open_unknowns": [
            "Exact C++ OptionType enum names for types 4 vs 6 and 3 "
            "vs 7 vs 8, and for types 5 / 23 (carried from #4237 / "
            "#4239; this packet uses the #4237 numeric labels).",
            "What verification values 1, 2, 3 and 5 each check (only "
            "verification 4 is pinned: accept-and-ignore). Observed "
            "here: verification 1 on the type-22 factory entries "
            "(comparator, table_factory, compaction_filter, "
            "compaction_filter_factory, sst_partitioner_factory), "
            "verification 2 on the type-22 prefix-extractor entries "
            "(prefix_extractor, "
            "memtable_insert_with_hint_prefix_extractor), verification "
            "3 on merge_operator, verification 5 on memtable, "
            "block_based_table_factory and plain_table_factory.",
            "The allow_2pc field (carried from #4237): block 26 of "
            "the DBOptions map, offset 0x173, is still not tied to a "
            "struct member.",
            "The 0x3a element tag passed in r9d to the vector helpers "
            "0x6083570 / 0x6083d80: it is identical for both vector "
            "entries and is stored in the parse-function capture; "
            "its meaning is not pinned.",
        ],
    }

    with open(HERE / "records.json", "w") as f:
        json.dump(records, f, indent=2)
        f.write("\n")
    with open(HERE / "entries.tsv", "w") as f:
        f.write("map\tname\toffset\ttype\ttype_name\tverification\t"
                "flags\tsource_kind\tsource_call\n")
        for e in entries:
            s = e["source"]
            call = s.get("call") or s.get("pair_move_call", "")
            f.write(f"{e['map']}\t{e['name']}\t{e['offset']}\t"
                    f"{e['type']}\t{e['type_name']}\t"
                    f"{e['verification']}\t{e['flags']}\t"
                    f"{s['kind']}\t{call}\n")
    print(f"entries: {len(entries)} (maps: "
          + ", ".join(f"{m['name']}={m['entries']}"
                      for m in maps_rec) + ")")
    print(f"verification-4 (ignored) entries: {len(ignored)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
