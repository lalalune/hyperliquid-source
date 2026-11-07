#!/usr/bin/env python3
"""Generate records.json for RE-001-optiontypeinfo-mismatches-115.

Reads entries.tsv (from census.py) and census-21b.tsv (from
census_21b.py) and emits the semantic records only. Instruction-level
detail lives in the verbatim objdump excerpts, never here: this file
holds no per-instruction mnemonic list.

The ctor-pack, BuildDBOptions and default-ctor records below are
hand-verified against the excerpts (addresses cited per record);
verify.py re-checks each cited instruction byte-for-byte against a
fresh objdump run and the raw binary.

Usage: python3 gen_records.py  (run from the repo root)
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "records.json"

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)

# Group attribution by entry-block range in the static initializer.
# A: MutableDBOptions (flags 0x100, blocks 0-18).
# B: the EnvOptions bool cluster, ImmutableDBOptions-relative (blocks
#    19-26). C: DBOptions proper (blocks 27-91).
GROUPS = [
    {"group": "A", "blocks": [0, 18], "struct": "MutableDBOptions",
     "flags": "0x100",
     "note": "MutableDBOptions fields; BuildDBOptions copies them into "
             "DBOptions (see builddboptions records)."},
    {"group": "B", "blocks": [19, 26], "struct": "EnvOptions (bool cluster)",
     "flags": "0x0",
     "note": "Offsets are ImmutableDBOptions-relative; the ImmutableDBOptions "
             "ctor packs DBOptions+0x128..0x12d and +0x148 into "
             "+0x108..0x10e. use_direct_writes (offset 0) and allow_2pc "
             "(offset 0x173) do not fit the cluster; see open_unknowns."},
    {"group": "C", "blocks": [27, 91], "struct": "DBOptions",
     "flags": "0x0",
     "note": "DBOptions fields; offsets are ImmutableDBOptions-relative "
             "except where the ctor packs them from a different DBOptions "
             "source offset (see ctor_pack)."},
]

# ImmutableDBOptions ctor (0x60a3b60) pack records: destination slot
# (ImmutableDBOptions offset) <- DBOptions source byte(s), in BYTE
# order (low byte first), with the instruction addresses that prove
# the copy. rbp = source DBOptions, rbx = destination
# ImmutableDBOptions.
CTOR_PACK = [
    # The +0x158 word: {DBOptions+0x1c0, +0x1d0, +0x1d1, +0x1d2}.
    {"dst": "0x158", "src": ["0x1c0", "0x1d0", "0x1d1", "0x1d2"],
     "width": 4, "store": "0x60a3ff0",
     "note": "enable_pipelined_write, unordered_write, "
             "allow_concurrent_memtable_write, enable_write_thread_"
             "adaptive_yield (see default_ctor values)."},
    {"dst": "0x15c", "src": ["0x1d3"], "width": 1, "store": "0x60a3ffd",
     "note": "write_thread_slow_yield_usec low byte (the full 8-byte "
             "field is copied by the -0x28 shifted movdqu block)."},
    # The +0x190 word: {DBOptions+0x210, +0x211, +0x212, +0x214}.
    {"dst": "0x190", "src": ["0x210", "0x211", "0x212", "0x214"],
     "width": 4, "store": "0x60a407e",
     "note": "DBOptions+0x213 is SKIPPED: the four bytes are packed "
             "from +0x210/+0x211/+0x212/+0x214, not a contiguous word."},
    {"dst": "0x194", "src": ["0x215", "0x216"], "width": 2,
     "store": "0x60a408b", "note": "2-byte copy."},
    # The tail: +0x196 <- +0x217; +0x197 word <- {+0x218, +0x219, +0x21a,
    # +0x138}; +0x199 <- +0x138 is the TOP byte of that word.
    {"dst": "0x196", "src": ["0x217"], "width": 1, "store": "0x60a4099",
     "note": "wal_compression."},
    {"dst": "0x197", "src": ["0x218", "0x219", "0x138", "0x21a"],
     "width": 4, "store": "0x60a40c3",
     "note": "Byte order (low byte first): +0x197 <- DBOptions+0x218 "
             "(atomic_flush), +0x198 <- +0x219 "
             "(avoid_unnecessary_blocking_io), +0x199 <- +0x138 "
             "(persist_stats_to_disk), +0x19a <- +0x21a "
             "(write_dbid_to_manifest). The map offsets match these "
             "destinations exactly. The assembler loads +0x21a first "
             "and shifts it to the top byte; edx still holds +0x138 "
             "from 0x60a4077 when it is or-ed in second."},
    # The EnvOptions bool cluster pack.
    {"dst": "0x108", "src": ["0x128", "0x129", "0x12a", "0x12b"],
     "width": 4, "store": "0x60a3e5f",
     "note": "allow_mmap_reads, allow_mmap_writes, use_direct_reads, "
             "use_direct_io_for_flush_and_compaction."},
    {"dst": "0x10c", "src": ["0x12c", "0x12d"], "width": 2,
     "store": "0x60a3e73",
     "note": "allow_fallocate, is_fd_close_on_exec."},
    {"dst": "0x10e", "src": ["0x148"], "width": 1, "store": "0x60a3e88",
     "note": "advise_random_on_open."},
]

# BuildDBOptions (0x60c2e20): MutableDBOptions (r12) -> DBOptions (rbx).
# The nine group-A map offsets, verified against the map.
BUILDDBOPTIONS = [
    {"mutable": "0x4", "read": "0x60c2fa4",
     "name": "max_background_compactions"},
    {"mutable": "0x8", "read": "0x60c2fd3",
     "name": "max_subcompactions"},
    {"mutable": "0x20", "read": "0x60c2f19",
     "name": "max_total_wal_size"},
    {"mutable": "0x28", "read": "0x60c2f8e",
     "name": "delete_obsolete_files_period_micros"},
    {"mutable": "0x40", "read": "0x60c2f0b",
     "name": "max_open_files",
     "note": "mov 0x40(%r12),%eax at 0x60c2f0b; mov %eax,0x44(%rbx) "
             "at 0x60c2f10. ImmutableDBOptions+0x40 is info_log_level, "
             "a different struct -- #4146's second unknown was a "
             "category error."},
    {"mutable": "0x48", "read": "0x60c2faf",
     "name": "bytes_per_sync"},
    {"mutable": "0x50", "read": "0x60c2fbb",
     "name": "wal_bytes_per_sync"},
    {"mutable": "0x58", "read": "0x60c2fc7",
     "name": "strict_bytes_per_sync"},
    {"mutable": "0x68", "read": "0x60c2fde",
     "name": "max_background_flushes"},
]

# DBOptions default ctor (0x60b2db0) value stores that confirm field
# identities (defaults per the RocksDB 8.1.1 header).
DEFAULT_CTOR = [
    {"offset": "0x128", "store": "0x60b2f0c", "value": "0x0", "width": 4,
     "note": "allow_mmap_reads, allow_mmap_writes, use_direct_reads, "
             "use_direct_io_for_flush_and_compaction all false."},
    {"offset": "0x12c", "store": "0x60b2f25", "value": "0x0101",
     "width": 2,
     "note": "%ecx = 0x101 (0x60b2e07): allow_fallocate = true, "
             "is_fd_close_on_exec = true."},
    {"offset": "0x138", "store": "0x60b2f42", "value": "0x0", "width": 1,
     "note": "persist_stats_to_disk = false."},
    {"offset": "0x148", "store": "0x60b2f54", "value": "0x1", "width": 1,
     "note": "advise_random_on_open = true."},
    {"offset": "0x1d0", "store": "0x60b2fa6", "value": "0x01010000",
     "width": 4,
     "note": "enable_pipelined_write = false, unordered_write = false, "
             "allow_concurrent_memtable_write = true, "
             "enable_write_thread_adaptive_yield = true -- confirms the "
             "+0x158 pack field identities."},
    {"offset": "0x210", "store": "0x60b2fd0", "value": "0x0", "width": 8,
     "note": "Zeroes DBOptions+0x210..0x217, incl. wal_compression "
             "(kNoCompression = 0) at +0x217."},
    {"offset": "0x218", "store": "0x60b2fdb", "value": "0x0000",
     "width": 2,
     "note": "%esi was zeroed at 0x60b2dfa: atomic_flush = false, "
             "avoid_unnecessary_blocking_io = false."},
    {"offset": "0x21a", "store": "0x60b2fe2", "value": "0x0", "width": 1,
     "note": "write_dbid_to_manifest = false. No store touches "
             "+0x21b..+0x21f."},
    {"offset": "0x220", "store": "0x60b2fe9", "value": "0x0", "width": 8,
     "note": "log_readahead_size = 0 (8-byte size_t)."},
]

CORRECTIONS_TO_4146 = [
    {"pr": 4146, "claim": "DBOptions tail: wal_compression +0x218, "
     "atomic_flush +0x219, avoid_unnecessary_blocking_io +0x21a, "
     "write_dbid_to_manifest +0x21b",
     "correction": "All four are one byte lower: wal_compression +0x217, "
     "atomic_flush +0x218, avoid_unnecessary_blocking_io +0x219, "
     "write_dbid_to_manifest +0x21a. The map offsets (0x196-0x19a) "
     "were correct; the DBOptions source offsets in #4146 were read "
     "off by one. Proof: the ImmutableDBOptions ctor pack "
     "(0x60a4092-0x60a40c3) lands DBOptions+0x217 at +0x196, +0x218 "
     "at +0x197, +0x219 at +0x198, +0x21a at +0x19a."},
    {"pr": 4146, "claim": "max_open_files map offset 0x40 conflicts with "
     "ImmutableDBOptions+0x40 = info_log_level",
     "correction": "No conflict: 0x40 is a MutableDBOptions offset. "
     "BuildDBOptions reads MutableDBOptions+0x40 (0x60c2f0b) and "
     "stores it at DBOptions+0x44 (0x60c2f10)."},
    {"pr": 4146, "claim": "DBOptions+0x21b (write_dbid_to_manifest) is "
     "never stored or read",
     "correction": "The field is at +0x21a, not +0x21b. DBOptions+0x21b "
     "itself is alignment padding (+0x21b..+0x21f) before the "
     "8-byte-aligned log_readahead_size at +0x220; see padding_21b."},
]

NESTED_ENTRIES = [
    {"name": "env", "string_addr": "0x44feff", "offset": "0x8",
     "flags": "0x2001", "temp": "-0x7e50", "block": 89,
     "note": "Built interleaved in block 89; DBOptions+0x8 is the env "
             "Env* pointer, which fits. Construction path via the "
             "once-called helpers 0x60a0180/0x60a63d0/0x60a6450 is not "
             "fully resolved."},
    {"name": "file_checksum_gen_factory", "string_addr": "0x434210",
     "offset": "0x1a8", "flags": "0x1400", "temp": "-0x4550",
     "block": 90,
     "note": "Built in block 90's teardown temp; the pair-constructor "
             "call in that block consumes the listeners temp, so this "
             "entry's insertion path is unresolved."},
    {"name": "statistics", "string_addr": "0x44ff03", "offset": "0x48",
     "flags": "0x3401", "temp": "-0x4550", "block": 90,
     "note": "Same teardown temp as file_checksum_gen_factory; "
             "insertion path unresolved."},
    {"name": "wal_filter", "string_addr": "0x4454b1", "offset": "0x188",
     "flags": "0x1201", "temp": "-0x4550", "block": 27,
     "note": "UNATTRIBUTED: the teardown temp in block 27 carries "
             "offset 0x188 and flags 0x1201 with a live std::function "
             "manager, but the string-to-temp link is not proven; "
             "recorded as uncertain, not as a wal_filter fact."},
]

OPEN_UNKNOWNS = [
    "15 entries have offset 0 and null std::function members "
    "(allow_os_buffer, base_background_compactions, max_background_jobs, "
    "use_direct_writes, create_if_missing, disableDataSync, "
    "disable_data_sync, experimental_allow_mempurge, "
    "experimental_mempurge_policy, experimental_mempurge_threshold, "
    "skip_log_error_on_recovery, new_table_reader_for_compaction_inputs, "
    "preserve_deletes, concurrent_prepare, seq_per_batch): their access "
    "path is unresolved -- offset 0 cannot address a struct field and no "
    "parse function is installed. disableDataSync/disable_data_sync look "
    "like an alias pair (old camelCase + new snake_case).",
    "use_direct_writes (offset 0) and allow_2pc (offset 0x173) do not fit "
    "the EnvOptions bool cluster (+0x108..+0x10e, seven consecutive bytes "
    "incl. is_fd_close_on_exec at +0x10d). allow_2pc at +0x173 would be "
    "the top byte of the int the ctor copies from DBOptions+0x1f0 "
    "(0x20000) to +0x170 -- that word is not four bools, so the "
    "attribution is open.",
    "Exact map-insert mechanics: which global map object each pair range "
    "goes to, and the arguments of the once-called helpers "
    "(0x60a76c0/0x60a7c90/0x60a8260/0x60a8830 prologue, 0x60a66b0/0x60a65c0/"
    "0x60a64d0 blocks ~67-69, 0x60a63d0/0x60a6450/0x60a0180 block 89, "
    "0x609f1c0 block 88, 0x609f1f0/0x609f220 block 90, 0x60a67a0 block "
    "91/92 boundary). The 0x5e32b10 (7 calls) / 0x5e332c0 (4 calls) "
    "helpers are std::function move constructors, likely part of the "
    "nested-entry insertion.",
    "The pair-copy 4-byte quirk: the pair constructor 0x5d400f0 copies "
    "only the low 4 bytes of temp+0x00; the +0x04 padding dword is never "
    "written by the builder or the copy helper (already noted by a prior "
    "contributor in tools/optiontypeinfo_slicetransform_115.py). "
    "Recorded as observed, not explained.",
    "The +0xa8 (type/verification) values are NOT recorded: they are "
    "loaded into registers whose values the initializer does not set in "
    "the same block (stale r12/r13/r14/rax), so register tracking is "
    "unreliable for them. Only name, offset (immediate) and flags "
    "(immediate) are claimed per entry.",
]


def load_entries():
    rows = []
    with open(HERE / "entries.tsv") as f:
        header = f.readline()
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 6 or parts[5] != "ok":
                continue
            block = int(parts[0])
            group = ("A" if block <= 18 else "B" if block <= 26 else "C")
            rows.append({
                "block": block,
                "name": parts[1],
                "offset": parts[3],
                "flags": parts[4],
                "group": group,
            })
    return rows


def load_census_21b():
    sites = []
    with open(HERE / "census-21b.tsv") as f:
        f.readline()
        for line in f:
            parts = line.rstrip("\n").split("\t")
            sites.append({
                "address": parts[0],
                "register": parts[1],
                "enclosing_fde": parts[2],
            })
    return sites


def main():
    entries = load_entries()
    sites_21b = load_census_21b()
    records = {
        "task": "RE-001",
        "artifact": {
            "binary": "work/hl-node-115.bin",
            "sha256": ARTIFACT_SHA256,
            "provenance": "provenance/artifacts.json "
                          "artifacts/node/115/hl-node",
        },
        "bounded_question": "What is the full DBOptions OptionTypeInfo "
                            "map on node #115, and what are #4146's three "
                            "open unknowns (the avoid offset mismatch, the "
                            "max_open_files offset mismatch, DBOptions"
                            "+0x21b)?",
        "answer": {
            "map_entries": len(entries),
            "avoid_unnecessary_blocking_io": "Map offset 0x198 is "
                "correct; #4146's DBOptions source offset was off by one "
                "(+0x21a -> +0x219).",
            "max_open_files": "Map offset 0x40 is a MutableDBOptions "
                "offset, not ImmutableDBOptions; BuildDBOptions reads it "
                "at 0x60c2f0b.",
            "dboptions_0x21b": "Alignment padding (+0x21b..+0x21f) "
                "before log_readahead_size at +0x220; no DBOptions/"
                "ImmutableDBOptions function touches it.",
        },
        "map": entries,
        "groups": GROUPS,
        "ctor_pack": CTOR_PACK,
        "builddboptions": BUILDDBOPTIONS,
        "default_ctor": DEFAULT_CTOR,
        "padding_21b": {
            "sites": sites_21b,
            "rsp_stack_slots": len([s for s in sites_21b
                                    if s["register"] == "rsp"]),
            "struct_field_uses": len([s for s in sites_21b
                                      if s["register"] != "rsp"]),
            "note": "All five struct-field uses are %rbx in one function "
                    "(FDE 0x5a897e0..0x5a8a1cc), which operates on a "
                    "different struct: it stores std::strings at "
                    "+0x18/+0x28/+0x38/+0x40 (where DBOptions holds "
                    "numbers), writes a 'D' tag byte at +0x110 (where "
                    "DBOptions holds db_write_buffer_size), and writes "
                    "+0x220 as a single byte = 2 (where DBOptions holds "
                    "the 8-byte log_readahead_size). One -0x21b(%rbp) "
                    "stack local (0x5fac529) is a false positive and is "
                    "excluded from the site list. Census method: "
                    "displacement text; computed-address accesses "
                    "(base+index) would not appear.",
        },
        "corrections_to_4146": CORRECTIONS_TO_4146,
        "nested_entries": NESTED_ENTRIES,
        "open_unknowns": OPEN_UNKNOWNS,
    }
    with open(OUT, "w") as f:
        json.dump(records, f, indent=2)
        f.write("\n")
    print(f"wrote records.json: {len(entries)} map entries, "
          f"{len(sites_21b)} +0x21b sites")
    return 0


if __name__ == "__main__":
    sys.exit(main())
