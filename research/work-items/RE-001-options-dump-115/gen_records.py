#!/usr/bin/env python3
"""Build records.json for RE-001-options-dump-115.

Reads the census outputs (fields.tsv, enum-table.tsv, levels.tsv,
callers.tsv, frames.txt) and the hand-verified semantic field table
below, cross-checks the census-derived formats against the
annotations, and writes records.json (semantic records only -- no
per-instruction mnemonic lists; instruction detail lives in the raw
excerpts).

Run from the repository root:
  python3 research/work-items/RE-001-options-dump-115/gen_records.py
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

# Annotated field table: (line, format, struct offset, kind, notes).
# Offsets are ColumnFamilyOptions-relative, read from the dump's
# %rbx loads.  Kinds: name (vtable slot 0x70), scalar, bool
# (byte -> "true"/"false"), enumfn (0x5d8b3c0), enummap (std::map
# lookup in a #4239 registry), slot (other vtable slot), loop.
FIELDS = [
    (0, "Options.comparator: %s", "0x1e8", "name",
     "unconditional deref; no null check"),
    (1, "Options.merge_operator: %s", "0x1f0", "name", "null -> None"),
    (2, "Options.compaction_filter: %s", "0x200", "name", "null -> None"),
    (3, "Options.compaction_filter_factory: %s", "0x208", "name",
     "null -> None"),
    (4, "Options.sst_partitioner_factory: %s", "0x2f0", "name",
     "null -> None; slot 0x70 vs GOT 0x64ed508 (RELATIVE -> 0x6093050); "
     "equal -> literal SstPartitionerFixedPrefixFactory; else cold "
     "0x60b72a0 calls Name()"),
    (5, "Options.memtable_factory: %s", "0x128", "name",
     "unconditional deref; no null check"),
    (6, "Options.table_factory: %s", "0x2b8", "name",
     "slot 0x70 vs GOT 0x64edca0 (RELATIVE -> 0x60b1d90); equal -> "
     "literal BlockBasedTable; else cold 0x60b6e90 calls Name(); "
     "unconditional deref"),
    (7, "table_factory options: %s", "0x2b8", "slot",
     "vtable slot 4 (0x20) on the factory fills a temp string"),
    (8, "Options.write_buffer_size: %zu", "0x218", "scalar", "u64"),
    (9, "Options.max_write_buffer_number: %d", "0x0", "scalar", "i32"),
    (10, "Options.compression[%d]: %s", "0x70", "loop",
     "vector<u8> at +0x70/+0x78, one line per element, value via "
     "enumfn; runs only when the vector is non-empty"),
    (11, "Options.bottommost_compression: %s", "0x221", "enumfn",
     "byte 0xff -> literal Disabled (fast path); else cold 0x60b6dd0 "
     "via enumfn"),
    (12, "Options.prefix_extractor: %s", "0x290", "name", "null -> nullptr"),
    (13, "Options.memtable_insert_with_hint_prefix_extractor: %s", "0x50",
     "name", "null -> nullptr"),
    (14, "Options.num_levels: %d", "0x88", "scalar", "i32"),
    (15, "Options.min_write_buffer_number_to_merge: %d", "0x4", "scalar",
     "i32"),
    (16, "Options.max_write_buffer_number_to_maintain: %d", "0x8",
     "scalar", "i32"),
    (17, "Options.max_write_buffer_size_to_maintain: %lu", "0x10",
     "scalar", "u64"),
    (18, "Options.bottommost_compression_opts.window_bits: %d", "0x228",
     "scalar", "i32"),
    (19, "Options.bottommost_compression_opts.level: %d", "0x22c",
     "scalar", "i32"),
    (20, "Options.bottommost_compression_opts.strategy: %d", "0x230",
     "scalar", "i32"),
    (21, "Options.bottommost_compression_opts.max_dict_bytes: %u", "0x234",
     "scalar", "u32"),
    (22, "Options.bottommost_compression_opts.zstd_max_train_bytes: %u",
     "0x238", "scalar", "u32"),
    (23, "Options.bottommost_compression_opts.parallel_threads: %u",
     "0x23c", "scalar", "u32"),
    (24, "Options.bottommost_compression_opts.enabled: %s", "0x240",
     "bool", "byte != 0 -> true"),
    (25, "Options.bottommost_compression_opts.max_dict_buffer_bytes: %lu",
     "0x248", "scalar", "u64"),
    (26, "Options.bottommost_compression_opts.use_zstd_dict_trainer: %s",
     "0x250", "bool", "byte != 0 -> true"),
    (27, "Options.compression_opts.window_bits: %d", "0x258", "scalar",
     "i32"),
    (28, "Options.compression_opts.level: %d", "0x25c", "scalar", "i32"),
    (29, "Options.compression_opts.strategy: %d", "0x260", "scalar", "i32"),
    (30, "Options.compression_opts.max_dict_bytes: %u", "0x264", "scalar",
     "u32"),
    (31, "Options.compression_opts.zstd_max_train_bytes: %u", "0x268",
     "scalar", "u32"),
    (32, "Options.compression_opts.use_zstd_dict_trainer: %s", "0x280",
     "bool", "byte != 0 -> true"),
    (33, "Options.compression_opts.parallel_threads: %u", "0x26c",
     "scalar", "u32"),
    (34, "Options.compression_opts.enabled: %s", "0x270", "bool",
     "byte != 0 -> true"),
    (35, "Options.compression_opts.max_dict_buffer_bytes: %lu", "0x278",
     "scalar", "u64"),
    (36, "Options.level0_file_num_compaction_trigger: %d", "0x288",
     "scalar", "i32"),
    (37, "Options.level0_slowdown_writes_trigger: %d", "0x8c", "scalar",
     "i32"),
    (38, "Options.level0_stop_writes_trigger: %d", "0x90", "scalar", "i32"),
    (39, "Options.target_file_size_base: %lu", "0x98", "scalar", "u64"),
    (40, "Options.target_file_size_multiplier: %d", "0xa0", "scalar", "i32"),
    (41, "Options.max_bytes_for_level_base: %lu", "0x2a0", "scalar", "u64"),
    (42, "Options.level_compaction_dynamic_level_bytes: %d", "0xa4",
     "scalar", "bool byte printed as %d"),
    (43, "Options.max_bytes_for_level_multiplier: %f", "0xa8", "scalar",
     "f64"),
    (44, "Options.max_bytes_for_level_multiplier_addtl[%zu]: %d", "0xb0",
     "loop", "vector<i32> at +0xb0/+0xb8, one line per element"),
    (45, "Options.max_sequential_skip_in_iterations: %lu", "0x120",
     "scalar", "u64"),
    (46, "Options.max_compaction_bytes: %lu", "0xc8", "scalar", "u64"),
    (47, "Options.ignore_max_compaction_bytes_for_input: %s", "0xd0",
     "bool", "byte != 0 -> true"),
    (48, "Options.arena_block_size: %zu", "0x68", "scalar", "u64"),
    (49, "Options.soft_pending_compaction_bytes_limit: %lu", "0xd8",
     "scalar", "u64"),
    (50, "Options.hard_pending_compaction_bytes_limit: %lu", "0xe0",
     "scalar", "u64"),
    (51, "Options.disable_auto_compactions: %d", "0x2b0", "scalar",
     "bool byte printed as %d"),
    (52, "Options.compaction_style: %s", "0xe8", "enummap",
     "std::map<u8,string> at 0x6507260 (#4239 CompactionStyle: "
     "0 Level, 1 Universal, 2 FIFO, 3 None); miss -> cold 0x60b6b20 "
     "builds unknown_<n> via ostringstream"),
    (53, "Options.compaction_pri: %s", "0xe9", "enummap",
     "std::map<u8,string> at 0x6507220 (#4239 CompactionPri: 0 "
     "ByCompensatedSize, 1 OldestLargestSeqFirst, 2 "
     "OldestSmallestSeqFirst, 3 MinOverlappingRatio, 4 RoundRobin); "
     "miss -> cold 0x60b6870 builds unknown_<n>"),
    (54, "Options.compaction_options_universal.size_ratio: %u", "0xec",
     "scalar", "u32"),
    (55, "Options.compaction_options_universal.min_merge_width: %u",
     "0xf0", "scalar", "u32"),
    (56, "Options.compaction_options_universal.max_merge_width: %u",
     "0xf4", "scalar", "u32"),
    (57, "Options.compaction_options_universal.max_size_amplification_percent: %u",
     "0xf8", "scalar", "u32"),
    (58, "Options.compaction_options_universal.compression_size_percent: %d",
     "0xfc", "scalar", "i32"),
    (59, "Options.compaction_options_universal.stop_style: %s", "0x100",
     "enummap", "std::map<u8,string> at 0x65071e0 (#4239 "
     "CompactionStopStyle: 0 SimilarSize, 1 TotalSize); miss -> cold "
     "unknown_<n> path"),
    (60, "Options.compaction_options_fifo.max_table_files_size: %lu",
     "0x108", "scalar", "u64"),
    (61, "Options.compaction_options_fifo.allow_compaction: %d", "0x110",
     "scalar", "bool byte printed as %d"),
    (62, "Options.table_properties_collectors: %s", "0x138", "loop",
     "vector at +0x138/+0x140; each element's vtable slot 0xa0 vs GOT "
     "0x64edca8 (RELATIVE -> 0x60b1ea0), mismatch -> cold 0x60b64c0; "
     "Name() slot 0x70 joined with a separator via ostringstream; "
     "trailing separator trimmed via _M_replace; empty vector -> "
     "cold 0x60b72b0"),
    (63, "Options.inplace_update_support: %d", "0x18", "scalar",
     "bool byte printed as %d"),
    (64, "Options.inplace_update_num_locks: %zu", "0x20", "scalar", "u64"),
    (65, "Options.memtable_prefix_bloom_size_ratio: %f", "0x38", "scalar",
     "f64"),
    (66, "Options.memtable_whole_key_filtering: %d", "0x40", "scalar",
     "bool byte printed as %d"),
    (67, "Options.memtable_huge_page_size: %zu", "0x48", "scalar", "u64"),
    (68, "Options.bloom_locality: %d", "0x60", "scalar", "i32"),
    (69, "Options.max_successive_merges: %zu", "0x150", "scalar", "u64"),
    (70, "Options.optimize_filters_for_hits: %d", "0x158", "scalar",
     "bool byte printed as %d"),
    (71, "Options.paranoid_file_checks: %d", "0x15a", "scalar",
     "bool byte printed as %d"),
    (72, "Options.force_consistency_checks: %d", "0x15b", "scalar",
     "bool byte printed as %d"),
    (73, "Options.report_bg_io_stats: %d", "0x15c", "scalar",
     "bool byte printed as %d"),
    (74, "Options.ttl: %lu", "0x160", "scalar", "u64"),
    (75, "Options.periodic_compaction_seconds: %lu", "0x168", "scalar",
     "u64"),
    (76, "Options.preclude_last_level_data_seconds: %lu", "0x180",
     "scalar", "u64"),
    (77, "Options.preserve_internal_time_seconds: %lu", "0x188", "scalar",
     "u64"),
    (78, "Options.enable_blob_files: %s", "0x190", "bool",
     "byte != 0 -> true"),
    (79, "Options.min_blob_size: %lu", "0x198", "scalar", "u64"),
    (80, "Options.blob_file_size: %lu", "0x1a0", "scalar", "u64"),
    (81, "Options.blob_compression_type: %s", "0x1a8", "enumfn",
     "CompressionType byte via 0x5d8b3c0"),
    (82, "Options.enable_blob_garbage_collection: %s", "0x1a9", "bool",
     "byte != 0 -> true"),
    (83, "Options.blob_garbage_collection_age_cutoff: %f", "0x1b0",
     "scalar", "f64"),
    (84, "Options.blob_garbage_collection_force_threshold: %f", "0x1b8",
     "scalar", "f64"),
    (85, "Options.blob_compaction_readahead_size: %lu", "0x1c0", "scalar",
     "u64"),
    (86, "Options.blob_file_starting_level: %d", "0x1c8", "scalar", "i32"),
    (87, "Options.blob_cache: %s", "0x1d0", "slot",
     "vtable slot 2 (0x10) returns the name; null cache jumps to "
     "0x60b62dd, skipping lines 87-89"),
    (88, "blob_cache options: %s", "0x1d0", "slot",
     "vtable slot 25 (0xc8) vs GOT 0x64ecd20 (RELATIVE -> 0x5d3f6c0); "
     "equal -> empty string; else cold 0x60b7080 calls the slot to "
     "fill the temp string"),
    (89, "blob_cache prepopulated: %s", "0x1e0", "scalar",
     "byte == 1 -> flush only; else disabled (#4239 "
     "PrepopulateBlobCache: 0 Disable, 1 FlushOnly)"),
    (90, "Options.experimental_mempurge_threshold: %f", "0x28", "scalar",
     "f64"),
    (91, "Options.bottommost_compression: %s", "0x221", "enumfn",
     "cold-block emission at 0x60b6df3 (same format as line 11)"),
    (92, "Options.compression: %s", "0x220", "enumfn",
     "cold-block emission at 0x60b704a; reached only when "
     "compression_per_level is empty"),
]

# CompressionType names from the 0x5d8b3c0 jump table (0x96d4f0).
# Indices 8..63 map to the default arm (empty string); byte 0xff maps
# to DisableOption via the >0x40 path.
COMPRESSION_NAMES = {
    0: "NoCompression", 1: "Snappy", 2: "Zlib", 3: "BZip2", 4: "LZ4",
    5: "LZ4HC", 6: "Xpress", 7: "ZSTD", 64: "ZSTDNotFinal",
    255: "DisableOption",
}


def read_tsv(name):
    rows = []
    with open(HERE / name) as f:
        header = f.readline()
        for line in f:
            line = line.rstrip("\n")
            if line:
                rows.append(line.split("\t"))
    return header.strip(), rows


def main():
    _, field_rows = read_tsv("fields.tsv")
    assert len(field_rows) == 93, len(field_rows)
    assert len(FIELDS) == 93, len(FIELDS)
    # Cross-check: census formats (stripped of alignment padding) match
    # the annotated formats.
    for (line, fmt, off, kind, notes), row in zip(FIELDS, field_rows):
        assert int(row[0]) == line, (row, line)
        census_fmt = row[4].strip()
        assert census_fmt == fmt, (line, census_fmt, fmt)
        assert int(row[2]) == 5, (line, row[2])
    _, enum_rows = read_tsv("enum-table.tsv")
    assert len(enum_rows) == 65
    enum_records = []
    for idx, target, name in enum_rows:
        enum_records.append({"index": int(idx), "target": target,
                             "name": name})
    for idx, name in COMPRESSION_NAMES.items():
        if idx < 65:
            rec = enum_records[idx]
            assert rec["name"] == name, (idx, rec)
    # Index 255 is outside the 65-entry table: the >0x40 path at
    # 0x5d8b4b0 checks for 0xff and appends the literal at 0x4350f0.
    data = (ROOT / "work" / "hl-node-115.bin").read_bytes()
    raw = data[0x4350F0:0x4350F0 + 32]
    assert raw[:raw.find(b"\x00")].decode() == "DisableOption"
    assert data[0x4376FD:0x4376FE] == b"\x00"  # default arm: empty string
    _, level_rows = read_tsv("levels.tsv")
    assert len(level_rows) == 341
    from collections import Counter
    level_counts = Counter(int(r[1]) for r in level_rows)
    assert dict(sorted(level_counts.items())) == {
        -1: 1, 0: 2, 1: 84, 2: 43, 3: 31, 5: 180}, level_counts
    _, caller_rows = read_tsv("callers.tsv")
    by_target = {}
    for t, s in caller_rows:
        by_target.setdefault(t, []).append(s)
    assert by_target["0x60b50c0"] == ["0x5d95e69"], by_target["0x60b50c0"]
    assert len(by_target["0x5fceda0"]) == 341
    assert len(by_target["0x5d8b3c0"]) == 14
    assert by_target["0x5fceea0"] == ["0x60a0fb9"]

    records = {
        "task": "RE-001",
        "work_item": "RE-001-options-dump-115",
        "artifact": {
            "node": 115,
            "file": "work/hl-node-115.bin",
            "sha256": ARTIFACT_SHA256,
        },
        "question": "Pin, for node #115, the ColumnFamilyOptions header "
                    "dump end to end: the 93 lines it logs, the struct "
                    "field behind each line, the name/enum/bool value "
                    "rules, the sole caller that drives it, and the "
                    "leveled log helper it funnels through.",
        "dump": {
            "function": "0x60b50c0..0x60b79a6",
            "size_bytes": 0x60B79A6 - 0x60B50C0,
            "signature": "(this: ColumnFamilyOptions*, logger) -> void",
            "helper_calls": 93,
            "helper_level": 5,
            "return": "ret at 0x60b6445; 0x60b6445..0x60b79a6 are cold "
                      "blocks and landing pads",
            "stack_frame": "0x368 bytes; stack canary at rsp+0x358; "
                           "local ostringstream and temp strings",
        },
        "helper": {
            "function": "0x5fceda0..0x5fcee93",
            "size_bytes": 0xF3,
            "signature": "(level: u8, logger, fmt: const char*, ...) "
                         "-> void",
            "contract": [
                "builds a va_list from the varargs",
                "level_now = logger->vtable[8]() (level query); "
                "if level_now > level, log nothing and return",
                "if level == 5, logger->vtable[3](fmt, va_list) "
                "(header-format path)",
                "otherwise logger->vtable[5](level, fmt, va_list) "
                "(leveled path)",
                "level values match InfoLogLevel: 0 DEBUG, 1 INFO, "
                "2 WARN, 3 ERROR, 4 FATAL, 5 HEADER",
            ],
            "direct_callers": 341,
            "level_counts": {"dynamic": 1, "0": 2, "1": 84, "2": 43,
                             "3": 31, "4": 0, "5": 180},
            "dynamic_level_site": "0x605c6de (level from a variable byte)",
            "zero_level_sites": ["0x61983ab", "0x6198572"],
            "sibling": {
                "function": "0x5fceea0..0x5fcef5b",
                "contract": "(logger, fmt, ...) -> void; calls "
                            "logger->vtable[3](fmt, va_list) directly "
                            "with no level check",
                "direct_callers": 1,
                "caller": "0x60a0fb9",
            },
        },
        "sole_caller": {
            "function": "0x5d954b0..0x5d96890",
            "call_site": "0x5d95e69",
            "header_log_site": "0x5d95e56",
            "header_level": 1,
            "header_format": "[%s:619] --------------- Options for "
                             "column family [%s]:\\n",
            "header_args": ["0x444573 (db/column_family.cc)",
                            "*(3rd argument) (column family name)"],
            "dump_args": ["rdi = 4th argument (the options object, "
                          "saved at -0x110(%rbp))",
                          "rsi = *(this+0x588) (the logger)"],
        },
        "enumfn": {
            "function": "0x5d8b3c0..0x5d8b4cb",
            "signature": "(out: string*, value: u8) -> void",
            "jump_table": "0x96d4f0, 65 int32 entries, relative to the "
                          "table base",
            "mapping": COMPRESSION_NAMES,
            "default_arm": "0x5d8b3f0 appends the empty string at "
                           "0x4376fd; indices 8..63 and bytes > 0x40 "
                           "(other than 0xff) take it",
            "direct_callers": 14,
            "dump_callers": ["0x60b5309 (compression loop)",
                             "0x60b611b (blob_compression_type)",
                             "0x60b6dd5 (bottommost cold block)",
                             "0x60b702c (compression cold block)"],
            "cross_check": "values 64 (ZSTDNotFinal) and 255 "
                           "(DisableOption) confirm the as-built "
                           "CompressionType values pinned by #4239",
        },
        "registries_consumed": [
            {"address": "0x6507260", "enum": "CompactionStyle",
             "entries": {"0": "kCompactionStyleLevel",
                         "1": "kCompactionStyleUniversal",
                         "2": "kCompactionStyleFIFO",
                         "3": "kCompactionStyleNone"},
             "used_for": "line 52 (+0xe8)"},
            {"address": "0x6507220", "enum": "CompactionPri",
             "entries": {"0": "kByCompensatedSize",
                         "1": "kOldestLargestSeqFirst",
                         "2": "kOldestSmallestSeqFirst",
                         "3": "kMinOverlappingRatio",
                         "4": "kRoundRobin"},
             "used_for": "line 53 (+0xe9)"},
            {"address": "0x65071e0", "enum": "CompactionStopStyle",
             "entries": {"0": "kCompactionStopStyleSimilarSize",
                         "1": "kCompactionStopStyleTotalSize"},
             "used_for": "line 59 (+0x100)"},
        ],
        "fields": [
            {"line": line, "format": fmt, "offset": off, "kind": kind,
             "notes": notes}
            for line, fmt, off, kind, notes in FIELDS
        ],
        "cold_blocks": [
            {"address": "0x60b6b20",
             "for": "compaction_style (+0xe8) registry miss",
             "does": "builds unknown_<n> via ostringstream and logs "
                     "line 52"},
            {"address": "0x60b6870",
             "for": "compaction_pri (+0xe9) registry miss",
             "does": "builds unknown_<n> via ostringstream and logs "
                     "line 53"},
            {"address": "0x60b6dd0",
             "for": "bottommost_compression byte != 0xff",
             "does": "enum-name via 0x5d8b3c0, logs line 91, jumps back "
                     "to 0x60b538f"},
            {"address": "0x60b6e90",
             "for": "table_factory Name slot != GOT 0x64edca0",
             "does": "calls Name(), logs line 6, jumps back to "
                     "0x60b5236"},
            {"address": "0x60b7020",
             "for": "compression_per_level empty (begin == end)",
             "does": "enum-name of the scalar byte +0x220, logs line "
                     "92, jumps back to 0x60b5361"},
            {"address": "0x60b7080",
             "for": "blob_cache slot 0xc8 != GOT 0x64ecd20",
             "does": "calls the slot to fill the temp string, logs "
                     "line 88"},
            {"address": "0x60b72a0",
             "for": "sst_partitioner_factory Name slot != GOT 0x64ed508",
             "does": "calls Name(), logs line 4, jumps back to "
                     "0x60b51d8"},
            {"address": "0x60b72b0",
             "for": "table_properties_collectors vector empty",
             "does": "joins to the collectors log line 62"},
            {"address": "0x60b64c0",
             "for": "collector slot 0xa0 != GOT 0x64edca8",
             "does": "cold path for a non-default collector"},
        ],
        "name_getter": {
            "slot": "vtable slot 14 (0x70)",
            "objects": ["comparator +0x1e8", "merge_operator +0x1f0",
                        "compaction_filter +0x200",
                        "compaction_filter_factory +0x208",
                        "sst_partitioner_factory +0x2f0",
                        "memtable_factory +0x128",
                        "table_factory +0x2b8",
                        "prefix_extractor +0x290",
                        "memtable_insert_with_hint_prefix_extractor +0x50",
                        "table_properties_collectors elements"],
            "null_defaults": {"merge_operator": "None",
                              "compaction_filter": "None",
                              "compaction_filter_factory": "None",
                              "sst_partitioner_factory": "None",
                              "prefix_extractor": "nullptr",
                              "memtable_insert_with_hint_prefix_extractor":
                                  "nullptr"},
            "no_null_check": ["comparator +0x1e8",
                              "memtable_factory +0x128",
                              "table_factory +0x2b8"],
        },
        "relocations": [
            {"got": "0x64ed508", "type": "R_X86_64_RELATIVE",
             "addend": "0x6093050",
             "role": "default sst_partitioner_factory Name()"},
            {"got": "0x64edca0", "type": "R_X86_64_RELATIVE",
             "addend": "0x60b1d90",
             "role": "default table_factory Name() (BlockBasedTable)"},
            {"got": "0x64edca8", "type": "R_X86_64_RELATIVE",
             "addend": "0x60b1ea0",
             "role": "default collector slot 0xa0"},
            {"got": "0x64ecd20", "type": "R_X86_64_RELATIVE",
             "addend": "0x5d3f6c0",
             "role": "default blob_cache slot 0xc8"},
            {"got": "0x64ed5a8", "type": "R_X86_64_GLOB_DAT",
             "addend": "basic_ostringstream vtable",
             "role": "local ostringstream vtable"},
            {"got": "0x64ed5b0", "type": "R_X86_64_GLOB_DAT",
             "addend": "basic_stringbuf vtable",
             "role": "local ostringstream stringbuf vtable"},
        ],
    }
    with open(HERE / "records.json", "w") as f:
        json.dump(records, f, indent=1)
        f.write("\n")
    print(f"records.json: {len(FIELDS)} fields, "
          f"{len(enum_records)} enum entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
