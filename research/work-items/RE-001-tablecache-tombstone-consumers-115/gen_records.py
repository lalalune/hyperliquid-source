"""Generate records.json for the
RE-001-tablecache-tombstone-consumers-115 packet.

Semantic records only: branch site -> target pairs, caller/callee
roles, gate order, layout offsets and relocation facts. No
per-instruction mnemonic list: instruction-level detail lives only
in the verbatim whole-function excerpt text files.
"""

import json
import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)


def sha256_of_binary():
    out = subprocess.run(
        ["sha256sum", str(BINARY)], capture_output=True, text=True,
        check=True).stdout
    return out.split()[0]


def caller_sites(target):
    rows = []
    with open(PACKET / "callers.tsv") as f:
        next(f)
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) == 4 and int(parts[0], 16) == target:
                rows.append({"site": parts[1], "kind": parts[2],
                             "containing_fde": parts[3]})
    return rows


def main():
    digest = sha256_of_binary()
    assert digest == ARTIFACT_SHA256, digest
    records = {
        "task_id": "RE-001",
        "bounded_question": (
            "How does TableCache consult the fragmented range "
            "tombstones when serving a Get and when refreshing "
            "cached seqnums?"),
        "target": {
            "artifact": "artifacts/node/115/hl-node",
            "sha256": ARTIFACT_SHA256,
            "node": 115,
        },
        "hosts": {
            "update_range_tombstone_seqnums": {
                "address": "0x5f3d4f0",
                "fde": "0x5f3d4f0..0x5f3d64a",
                "size_bytes": 346,
                "role": (
                    "For each level in [struct+0x08, struct+0x10) "
                    "whose bit is CLEAR in the combined mask "
                    "(struct+0x18 | struct+0x20 | base+0xf08), "
                    "raise the cached max covering seqnum and "
                    "refresh the covering-key string."),
                "callers": caller_sites(0x5F3D4F0),
                "iterator_build": {
                    "site": "0x5f3d516",
                    "slot": "0x18",
                    "receiver": "arg3 (rdx)",
                    "arg": "arg2 (rsi)",
                    "canonical_guard": {
                        "site": "0x5f3d4fb",
                        "got_slot": "0x64ed6e8",
                        "canonical": "0x5eba930",
                        "on_canonical": "return immediately, no update",
                    },
                    "null_iterator": {
                        "site": "0x5f3d51e",
                        "on_null": "return immediately, no update",
                    },
                },
                "level_loop": {
                    "start": "struct+0x08",
                    "end": "struct+0x10",
                    "base": "struct+0x00",
                    "mask_words": ["struct+0x18", "struct+0x20",
                                   "base+0xf08"],
                    "skip_rule": "bit SET in the combined mask -> skip",
                    "per_level_table": "base + level*8 + 0xe00",
                    "subobject": "per-level-record + 0x98",
                    "key_slice": "per-level-record + 0x10",
                },
                "iterator_release": {
                    "site": "0x5f3d620",
                    "slot": "0x8",
                    "kind": "tail_jump",
                },
            },
            "tablecache_get": {
                "address": "0x5f40070",
                "fde": "0x5f40070..0x5f40a8d",
                "size_bytes": 2589,
                "role": (
                    "Point lookup: consult the range tombstones "
                    "first (when gated in), then perform the table "
                    "Get via vtable slot 0x58. This packet pins the "
                    "tombstone consultation; the value lookup itself "
                    "is cited by contract."),
                "callers": caller_sites(0x5F40070),
                "gate_order": [
                    {"step": 1, "site": "0x5f40176",
                     "check": "cached max slot *(r13+0x1b0) is null",
                     "on_true": "skip to the table Get (0x5f40199)"},
                    {"step": 2, "site": "0x5f4018f",
                     "check": "byte at arg3+0x35 is nonzero",
                     "on_true": "skip to the table Get (0x5f40199)"},
                    {"step": 3, "site": "0x5f40504",
                     "check": "slot 0x18 equals the GOT 0x64ed6e8 "
                              "canonical (0x5eba930)",
                     "on_true": "skip to the table Get (0x5f40199)"},
                    {"step": 4, "site": "0x5f40527",
                     "check": "slot-0x18 build returns null",
                     "on_true": "skip to the status check (0x5f405c2)"},
                    {"step": 5, "site": "0x5f4055e",
                     "check": "MaxCoveringTombstoneSeqnum runs; "
                              "raise-and-refresh when greater",
                     "on_true": "release iterator via slot 0x8, then "
                                "the table Get (0x5f40199)"},
                ],
                "user_key_slice": {
                    "note": "built on the stack from the internal key: "
                            "ptr = *(rcx), len = *(rcx+8) - 8 (the "
                            "8-byte seqnum/type trailer is stripped)",
                    "site": "0x5f4053e",
                },
                "iterator_build": {
                    "site": "0x5f4051b",
                    "slot": "0x18",
                    "receiver": "*(arg5) (r14)",
                    "arg": "arg3 (rdx)",
                },
                "iterator_release": {
                    "site": "0x5f405bf",
                    "slot": "0x8",
                    "kind": "call (returns to 0x5f405c2)",
                },
                "table_get": {
                    "site": "0x5f401db",
                    "slot": "0x58",
                    "role": "the table reader's Get (cited by contract)",
                },
                "get_fallback_null_reader": {
                    "site": "0x5f40636",
                    "target": "0x5f3f6c0",
                    "role": "Get helper used when the reader is null "
                            "(cited by contract)",
                },
                "get_tail_marker": {
                    "site": "0x5f407bc",
                    "target": "0x616fb90",
                    "role": "writes +0x108 = 1 and clears the byte at "
                            "*(+0x1a0) when the status code is 7 and "
                            "*(rcx+0x28) == 1 (cited by contract)",
                },
                "not_ready_path": {
                    "sites": ["0x5f4082a", "0x5f40847"],
                    "targets": ["0x5f3cd50", "0x5f3d0d0"],
                    "role": "lookup helpers used when the file is not "
                            "yet opened (cited by contract)",
                },
            },
            "get_cleanup_fragment": {
                "address": "0x5f4000e",
                "fde": "0x5f4000e..0x5f40070",
                "size_bytes": 98,
                "role": "Exception-cleanup fragment FDE for Get: the "
                        "landing pads at 0x5f40a69/0x5f40a75/0x5f40a81 "
                        "jump here (0x5f40027/0x5f4000e/0x5f4001b).",
            },
        },
        "shared_update": {
            "cached_max_slot": "+0x1b0 (a u64* cell on the subobject)",
            "covering_key_string": "+0x190 (a std::string* on the subobject)",
            "has_covering_key_flag": "+0x198 (byte, set to 1 on a raise)",
            "rule": (
                "Let m = MaxCoveringTombstoneSeqnum(iterator, key). "
                "If m <= *cached_max, change nothing. Else store m "
                "into *cached_max; when the +0x190 string slot is "
                "non-null, replace the string with the key-array "
                "Slice at the returned seqnum's index; set +0x198 = 1."),
            "fragment_index_arithmetic": (
                "index = (seq_ptr - seq_base) >> 3; entry = the "
                "16-byte Slice at key_base + index * 16. In the "
                "binary: (rax - *(rdx+0x18)) >> 3 << 4 + *(rdx+0x30), "
                "where rdx = iterator+0x68 (the list) and rax = "
                "iterator+0x90 (the seq pointer)."),
        },
        "null_stub": {
            "address": "0x5eba930",
            "fde": "0x5eba930..0x5eba937",
            "size_bytes": 7,
            "body": "endbr64; xor %eax,%eax; ret",
            "meaning": "the null-returning default for the slot-0x18 "
                       "iterator build: a reader with this slot has "
                       "no range tombstones to consult",
            "got_slot_compared": "0x64ed6e8",
            "relative_slots_with_same_addend": ["0x64d5ea8", "0x64d6768",
                                                "0x64ed6e8"],
            "vtable_installers": [
                {"vtable": "0x64d5e90",
                 "typeinfo": "N7rocksdb17CuckooTableReaderE",
                 "slot_0x00": "0x615b1b0", "slot_0x18": "0x5eba930"},
                {"vtable": "0x64d6750",
                 "typeinfo": "N7rocksdb16PlainTableReaderE",
                 "slot_0x00": "0x61a3cc0", "slot_0x18": "0x5eba930"},
            ],
        },
        "iterator_gate_memtable": {
            "address": "0x5f0b050",
            "fde": "0x5f0b050..0x5f0b073",
            "size_bytes": 35,
            "role": "MemTable-side iterator gate (cited; #3674/#3900 "
                    "ground): return null when the +0x35 byte of the "
                    "second argument is nonzero, or when the "
                    "MemTable's +0xa60 byte is nonzero; else "
                    "tail-jump to NewRangeTombstoneIteratorInternal "
                    "0x5f0a9c0. The +0x35 test is the same offset the "
                    "Get gate tests.",
            "callers": caller_sites(0x5F0B050),
        },
        "callee_contract": {
            "address": "0x5f32900",
            "fde": "0x5f32900..0x5f32a0a",
            "source_packet": "RE-001-fragmented-tombstone-iterator-115 (#3900)",
            "contract": (
                "SeekToCoveringTombstone; Valid check; return 0 when "
                "invalid, when seq_ptr == fragment range end, or "
                "when the fragment start key is greater than the key; "
                "else return *(+0x90)."),
            "direct_callers": caller_sites(0x5F32900),
        },
        "cache_chain_canonicals": {
            "note": (
                "Get's cleanup regions walk +0x38 chains comparing "
                "vtable slots 0x18/0x38/0x40 against GOT canonicals "
                "(8 levels unrolled, then a virtual call). The "
                "canonicals resolve to cache-wrapper vtable slots; "
                "the chain resolution itself is cited by contract."),
            "got_slots": {
                "0x64ecd48": {"target": "0x5d42220",
                              "role": "slot 0x18 canonical"},
                "0x64ecd18": {"target": "0x5d3f090",
                              "role": "slot 0x38 canonical"},
                "0x64ece10": {"target": "0x5d420a0",
                              "role": "slot 0x40 canonical"},
            },
            "vtable_owners": [
                {"vtable": "0x64c8da0",
                 "typeinfo": "N7rocksdb12CacheWrapperE",
                 "slots": {"0x18": "0x5d42220", "0x38": "0x5d3f090",
                           "0x40": "0x5d420a0"}},
                {"vtable": "0x64c8ea0",
                 "typeinfo": "N7rocksdb25CacheWithSecondaryAdapterE",
                 "slots": {"0x18": "0x5d42220", "0x38": "0x5d3f090"}},
                {"vtable": "0x64c9e00",
                 "typeinfo": "N7rocksdb12ChargedCacheE",
                 "slots": {"0x40": "0x5d420a0"}},
            ],
        },
        "literals": [
            {"address": "0x6504690",
             "role": "guard byte for the lazy static at 0x65046a0 "
                     "(the +0x38-chain object in Get)"},
            {"address": "0x65046a0",
             "role": "lazy-static 0x30-byte object: slot +0x00 = "
                     "0x5f3cb30 (deleter), +0x20 = 0xd, +0x28 = self"},
        ],
        "cited_only": [
            {"routine": "0x5f3f6c0", "fde": "0x5f3f6c0..0x5f4000d",
             "role": "Get helper when the reader is null; 10 call sites"},
            {"routine": "0x5f3cd50", "fde": "0x5f3cd50..0x5f3d0aa",
             "role": "not-ready lookup helper 1; 2 call sites"},
            {"routine": "0x5f3d0d0", "fde": "0x5f3d0d0..0x5f3d4de",
             "role": "not-ready lookup helper 2; 2 call sites"},
            {"routine": "0x5f0a9c0", "fde": "0x5f0a9c0..0x5f0b04c",
             "role": "NewRangeTombstoneIteratorInternal; #3674 ground"},
            {"routine": "0x5f3cb30", "fde": "0x5f3cb30..0x5f3cb69",
             "role": "0x20-byte deleter for the lazy static at 0x65046a0"},
            {"routine": "0x5f42f80", "fde": "0x5f42f80..0x5f44309",
             "role": "sole caller of UpdateRangeTombstoneSeqnums "
                     "(site 0x5f44279); a 5001-byte multi-level lookup; "
                     "its level-range struct is filled at 0x5f4308f/0x5f4309d"},
            {"routine": "0x5f733c0", "fde": "0x5f733c0..0x5f743d9",
             "role": "sole caller of TableCache::Get (site 0x5f738e8); "
                     "passes the per-file record (index*0x3c8) and the "
                     "+0x1118 struct as stack arguments"},
        ],
        "unknowns": [
            "The C++ names of the two hosts (described by behaviour).",
            "The semantic identity of the key-array Slice refreshed "
            "into +0x190 (fragment start key vs end key vs timestamp "
            "key) — carried open from #3900.",
            "The exact roles of the three mask words in the refresh "
            "loop (struct+0x18, struct+0x20, base+0xf08) beyond the "
            "observed skip rule.",
            "The class behind the slot-0x18 receiver in each host "
            "(the vtable is not named; only the canonical guard is "
            "pinned).",
            "The identity of the +0x35 flag's owner struct (the same "
            "offset is tested by the MemTable gate 0x5f0b050 and by "
            "Get; likely a ReadOptions field, not proven here).",
            "The full value-lookup behaviour of TableCache::Get "
            "beyond the tombstone consultation (slot-0x58 table Get, "
            "the +0x38/+0x40 cache chain-walks, the 0x5f3f6c0 "
            "fallback and the not-ready path are cited, not modelled).",
            "The landing-pad / LSDA tables of both hosts.",
        ],
        "census": {
            "method": "one objdump pass over the executable LOAD "
                      "segment, direct call/jump/lea census plus "
                      "8-byte qword scan and RELATIVE relocations; "
                      "see census.py",
            "callers_tsv_rows": 59,
            "dispatch_tsv_rows": 7132,
            "counts": {
                "0x5f32900": {"calls": 4},
                "0x5f3d4f0": {"calls": 1},
                "0x5f40070": {"calls": 1},
                "0x5f0b050": {"calls": 11},
                "0x5f0a9c0": {"calls": 1, "jumps": 1},
                "0x5eba930": {"qwords": 3, "relative": 3},
                "0x5f3f6c0": {"calls": 10},
                "0x616fb90": {"calls": 7},
            },
        },
    }
    (PACKET / "records.json").write_text(
        json.dumps(records, indent=2) + "\n")
    print("wrote records.json (%d bytes)"
          % (PACKET / "records.json").stat().st_size)


if __name__ == "__main__":
    main()
