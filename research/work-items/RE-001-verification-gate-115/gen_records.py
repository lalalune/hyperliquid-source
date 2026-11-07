#!/usr/bin/env python3
"""Build records.json for RE-001-verification-gate-115.

Reads the census outputs (callers.tsv, frames.txt, literals.tsv)
and the hand-verified semantic gate table below, cross-checks the
census-derived facts against the annotations, and writes
records.json (semantic records only -- no per-instruction mnemonic
lists; instruction detail lives in the raw excerpts).

The verification distribution over the 214 mapped entries is a
cross-packet fact, computed from the records.json files of the two
map packets that first published the entries:
  - RE-001-optiontypeinfo-maps-115 (#4237): DBOptions 81 + Mutable
    DBOptions 19 = 100 entries, verification {0: 83, 1: 1, 2: 1,
    3: 1, 4: 14}.
  - RE-001-cfoptions-maps-115 (#4263): 114 entries, verification
    {0: 83, 1: 6, 2: 2, 3: 1, 4: 19, 5: 3}.
Combined: 214 entries, {0: 166, 1: 7, 2: 3, 3: 2, 4: 33, 5: 3}.

Run from the repository root:
  python3 research/work-items/RE-001-verification-gate-115/gen_records.py
"""

import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

# The gate decision table, read from the apply (0x60bedc0) and the
# serializer (0x60bb9a0).  Status codes follow RocksDB's Status::Code:
# 0 kOk, 3 kNotSupported, 4 kInvalidArgument.
GATE = {
    "apply": {
        "function": "0x60bedc0..0x60bf5bc",
        "record_fields": {
            "offset": "record+0x0 (i64, signed) -- field offset into "
                      "the options struct",
            "type": "record+0xa8 (i32) -- OptionType enum, 0..24; "
                    "jump table at 0x9786b4",
            "verification": "record+0xac (i32) -- the gate field",
            "flags": "record+0xb0 (i32) -- bit flags; the type-21/22 "
                     "arm tests bits 0x2/0x4/0x8 of the high byte",
        },
        "early_return_verification_4": {
            "site": "0x60bedeb",
            "instruction": "cmpl $0x4,0xac(%rsi); je 0x60bf000",
            "outcome": "Status OK written to the out-param at "
                       "0x60bf000 (movl $0x0,(%rdi); mov %si,0x4(%rdi); "
                       "movq $0x0,0x8(%rdi)); the value is never "
                       "parsed and the options struct is untouched",
            "note": "verification 4 is checked BEFORE the type "
                    "dispatch, so it short-circuits every type",
        },
        "parse_dispatch": {
            "site": "0x60bf030..0x60bf057",
            "mechanism": "type jump table at 0x9786b4 (relative "
                         "int32 entries); each arm calls its "
                         "type-specific parse helper on "
                         "(options_base + record->offset, value)",
            "success": "helper returns nonzero -> 0x60bf287 writes "
                       "Status OK to the out-param and returns",
        },
        "parse_failure": {
            "site": "0x60bf070..0x60bf096",
            "type_21_22": {
                "site": "0x60bf078..0x60bf084",
                "instruction": "sub $0x15,%eax (type); cmp $0x1,%eax; "
                               "jbe 0x60bf1e0",
                "outcome": "types 21/22 fall to the 0x60bf1e0 arm, "
                           "which re-attempts the parse via 0x60b9d70 "
                           "and 0x6099e70 (the string at 0x445245 is "
                           "the find needle); the arm's exact error "
                           "outcome is NOT pinned by this item",
            },
            "verification_1_2_3": {
                "site": "0x60bf08a..0x60bf09c",
                "instruction": "mov 0xac(%rbp),%eax; sub $0x1,%eax; "
                               "cmp $0x2,%eax; fall through to "
                               "0x60bf09c",
                "outcome": "Status code 3 (kNotSupported), message "
                           "= 'Deserializing the option ' + <name> + "
                           "' is not supported' (built at 0x60bf09c.."
                           "0x60bf1bd from the literals at 0x4373e9 "
                           "(25 bytes) and 0x437403 (17 bytes), passed "
                           "to the Status ctor 0x61cf670 with code 3)",
                "note": "verifications 1, 2 and 3 are INDISTINGUISHABLE "
                        "in the binary: one range check covers all "
                        "three and they share the single path",
            },
            "verification_0_5": {
                "site": "0x60bf08a..0x60bf096",
                "instruction": "same range check; ja 0x60bf460 for "
                               "any value outside {1,2,3} (after the "
                               "verification-4 early return)",
                "outcome": "Status code 4 (kInvalidArgument), message "
                           "= 'Error parsing:' + <name> (the two "
                           "slices at 0x60bf460..0x60bf49d: the literal "
                           "at 0x4477ed (14 bytes) and the name, passed "
                           "to the Status ctor 0x61cf670 with code 4)",
                "note": "verification 0 and 5 share the path; any "
                        "other value would too, but only 0..5 occur "
                        "in the mapped entries",
            },
        },
    },
    "serialize": {
        "function": "0x60bb9a0..0x60bbdeb",
        "verification_4_skip": {
            "site": "0x60bb9d4..0x60bb9de",
            "instruction": "cmpl $0x4,0xac(%rsi); je 0x60bbae8",
            "outcome": "the option is skipped in the dump: 0x60bbae8 "
                       "writes Status OK to the out-param and returns; "
                       "nothing is emitted for the entry",
            "note": "the skip is checked right after the null-value "
                    "guard (r8 == 0 -> 0x60bbae8), before the "
                    "serialize-function/type dispatch",
        },
        "other_verifications": "verifications 0, 1, 2, 3 and 5 all "
                               "serialize normally: the record's "
                               "serialize function at record+0x38 if "
                               "non-null (call *0x40(%r13) at "
                               "0x60bba1b), else the type dispatch at "
                               "0x60bba28 (types 21/22/22 handled at "
                               "0x60bbbf0/0x60bbb78)",
    },
    "status_codes": {
        "0": "kOk",
        "3": "kNotSupported",
        "4": "kInvalidArgument",
    },
}

# Verification distribution over the 214 mapped entries (see the
# module docstring for provenance).
DISTRIBUTION = {
    "total_entries": 214,
    "dboptions": {"entries": 100,
                  "counts": {"0": 83, "1": 1, "2": 1, "3": 1, "4": 14}},
    "cfoptions": {"entries": 114,
                  "counts": {"0": 83, "1": 6, "2": 2, "3": 1, "4": 19,
                             "5": 3}},
    "combined": {"0": 166, "1": 7, "2": 3, "3": 2, "4": 33, "5": 3},
}

# Named verification-4 entries (the skip set): every entry whose
# verification is 4 is never parsed on apply and never dumped on
# serialize.  Names are from the two map packets' records, extracted
# verbatim (see the module docstring for provenance).
VERIFICATION_4_NAMES = {
    "dboptions": [
        "use_direct_writes", "disableDataSync", "disable_data_sync",
        "experimental_allow_mempurge", "experimental_mempurge_policy",
        "experimental_mempurge_threshold",
        "skip_log_error_on_recovery",
        "new_table_reader_for_compaction_inputs", "preserve_deletes",
        "concurrent_prepare", "seq_per_batch", "rate_limiter",
        "allow_os_buffer", "base_background_compactions",
    ],
    "cfoptions": [
        "ttl", "bottommost_temperature", "expanded_compaction_factor",
        "filter_deletes", "hard_rate_limit",
        "max_grandparent_overlap_factor", "memtable_prefix_bloom_bits",
        "memtable_prefix_bloom_huge_page_tlb_size",
        "memtable_prefix_bloom_probes", "min_partial_merge_operands",
        "snap_refresh_nanos", "soft_rate_limit",
        "source_compaction_factor", "verify_checksums_in_compaction",
        "compaction_measure_io_stats", "max_mem_compaction_level",
        "purge_redundant_kvs_while_flush",
        "rate_limit_delay_max_milliseconds",
        "table_properties_collectors",
    ],
}

# Verification-5 entries (CFOptions only): 0/5 share the
# kInvalidArgument path on parse failure.
VERIFICATION_5_NAMES = {
    "cfoptions": [
        "memtable", "block_based_table_factory", "plain_table_factory",
    ],
}

# Verification-1/2/3 entries (the kNotSupported set on parse failure):
# the factory/comparator/extractor options whose values cannot be
# deserialized from a string.
VERIFICATION_123_NAMES = {
    "dboptions": {
        "1": ["wal_filter"],
        "2": ["listeners"],
        "3": ["file_checksum_gen_factory"],
    },
    "cfoptions": {
        "1": ["comparator", "compaction_filter",
              "compaction_filter_factory", "memtable_factory",
              "table_factory", "sst_partitioner_factory"],
        "2": ["prefix_extractor",
              "memtable_insert_with_hint_prefix_extractor"],
        "3": ["merge_operator"],
    },
}


def read_tsv(name):
    rows = []
    with open(HERE / name) as f:
        f.readline()
        for line in f:
            line = line.rstrip("\n")
            if line:
                rows.append(line.split("\t"))
    return rows


def main():
    caller_rows = read_tsv("callers.tsv")
    by_target = {}
    for t, s in caller_rows:
        by_target.setdefault(t, []).append(s)
    assert len(by_target["0x60bedc0"]) == 13, by_target["0x60bedc0"]
    assert len(by_target["0x60bb9a0"]) == 16, by_target["0x60bb9a0"]

    literal_rows = read_tsv("literals.tsv")
    literals = {addr: lit for addr, lit in literal_rows}
    assert literals["0x4373e9"] == "Deserializing the option "
    assert literals["0x437403"] == " is not supported"
    assert literals["0x4477ed"] == "Error parsing:"

    # The distribution must add up.
    for part in ("dboptions", "cfoptions"):
        counts = DISTRIBUTION[part]["counts"]
        assert sum(counts.values()) == DISTRIBUTION[part]["entries"], part
        assert len(VERIFICATION_4_NAMES[part]) == counts.get("4", 0), part
        for v in ("1", "2", "3"):
            assert (len(VERIFICATION_123_NAMES[part].get(v, []))
                    == counts.get(v, 0)), (part, v)
    combined = Counter()
    for part in ("dboptions", "cfoptions"):
        combined.update({int(k): v for k, v in
                         DISTRIBUTION[part]["counts"].items()})
    assert dict(sorted(combined.items())) == {
        int(k): v for k, v in DISTRIBUTION["combined"].items()}, combined
    assert sum(combined.values()) == DISTRIBUTION["total_entries"]
    assert len(VERIFICATION_5_NAMES["cfoptions"]) == 3

    records = {
        "task": "RE-001",
        "work_item": "RE-001-verification-gate-115",
        "artifact": {
            "node": 115,
            "file": "work/hl-node-115.bin",
            "sha256": ARTIFACT_SHA256,
        },
        "question": "What does the OptionTypeInfo verification field "
                    "(record+0xac) decide?  Pin the gate in the "
                    "per-entry apply 0x60bedc0 and the per-entry "
                    "serializer 0x60bb9a0: which verification values "
                    "skip, which error each parse failure reports, "
                    "and how the 214 mapped entries distribute.",
        "gate": GATE,
        "distribution": DISTRIBUTION,
        "verification_4_names": VERIFICATION_4_NAMES,
        "verification_5_names": VERIFICATION_5_NAMES,
        "verification_123_names": VERIFICATION_123_NAMES,
        "messages": {
            "not_supported": "Deserializing the option <name> is not "
                             "supported",
            "parse_error": "Error parsing:<name>",
        },
        "callers": {
            "apply": {"function": "0x60bedc0",
                      "direct_callers": 13,
                      "sites": by_target["0x60bedc0"],
                      "address_taken": False},
            "serializer": {"function": "0x60bb9a0",
                           "direct_callers": 16,
                           "sites": by_target["0x60bb9a0"],
                           "address_taken": False},
        },
        "literals": literals,
        "open_unknowns": [
            "The exact error outcome of the type-21/22 fallback arm "
            "at 0x60bf1e0 (parse via 0x60b9d70 and 0x6099e70) when its "
            "own parse fails: the arm is cited, not modelled.",
            "The C++ enum names for the verification values 0..5: the "
            "binary pins the behavior per value, not the source names.",
            "Whether the type-21/22 arm is a fallback after a failed "
            "primary parse or the primary parse for those types (the "
            "jump table's 21/22 entries are not separately resolved).",
            "The serializer's type-21/22/22 arms at 0x60bbbf0 and "
            "0x60bbb78 are cited, not modelled.",
        ],
    }
    with open(HERE / "records.json", "w") as f:
        json.dump(records, f, indent=1)
        f.write("\n")
    print("records.json: gate + distribution over "
          f"{DISTRIBUTION['total_entries']} entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
