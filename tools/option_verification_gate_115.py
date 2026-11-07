"""Model of the OptionTypeInfo verification gate, node #115.

The gate lives in the per-entry apply (0x60bedc0..0x60bf5bc) and the
per-entry serializer (0x60bb9a0..0x60bbdeb).  The verification field
is record+0xac; the type field is record+0xa8.

Apply (0x60bedc0):
  * verification 4 is checked first (0x60bedeb) and returns Status OK
    immediately: the value is never parsed and the options struct is
    untouched.
  * Otherwise the value is parsed via the type jump table at
    0x9786b4; a successful parse returns Status OK.
  * On a failed parse, types 21/22 fall to the 0x60bf1e0 fallback arm
    (re-parse via 0x60b9d70 and 0x6099e70); this model reports that
    outcome as unpinned rather than guessing it.
  * On a failed parse, verifications 1, 2 and 3 all report Status
    code 3 (kNotSupported) with "Deserializing the option <name> is
    not supported".
  * On a failed parse, verifications 0 and 5 report Status code 4
    (kInvalidArgument) with "Error parsing:<name>".

Serialize (0x60bb9a0):
  * verification 4 skips the entry in the dump (0x60bb9d4 -> 0x60bbae8
    writes Status OK and returns); every other verification value
    serializes normally.

Status codes follow RocksDB's Status::Code: 0 kOk, 3 kNotSupported,
4 kInvalidArgument.
"""

# Verification distribution over the 214 mapped entries (DBOptions
# 100 from #4237 + CFOptions 114 from #4263).
DISTRIBUTION = {
    "total_entries": 214,
    "dboptions": {"entries": 100,
                  "counts": {0: 83, 1: 1, 2: 1, 3: 1, 4: 14}},
    "cfoptions": {"entries": 114,
                  "counts": {0: 83, 1: 6, 2: 2, 3: 1, 4: 19, 5: 3}},
    "combined": {0: 166, 1: 7, 2: 3, 3: 2, 4: 33, 5: 3},
}

# Entries whose verification is 4 (the skip set), from #4237/#4263.
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

# Entries whose verification is 5 (CFOptions only).
VERIFICATION_5_NAMES = {
    "cfoptions": [
        "memtable", "block_based_table_factory", "plain_table_factory",
    ],
}

# Entries whose verification is 1, 2 or 3 (the kNotSupported set).
VERIFICATION_123_NAMES = {
    "dboptions": {
        1: ["wal_filter"],
        2: ["listeners"],
        3: ["file_checksum_gen_factory"],
    },
    "cfoptions": {
        1: ["comparator", "compaction_filter",
            "compaction_filter_factory", "memtable_factory",
            "table_factory", "sst_partitioner_factory"],
        2: ["prefix_extractor",
            "memtable_insert_with_hint_prefix_extractor"],
        3: ["merge_operator"],
    },
}

STATUS_OK = 0
STATUS_NOT_SUPPORTED = 3
STATUS_INVALID_ARGUMENT = 4


def not_supported_message(name):
    return "Deserializing the option " + name + " is not supported"


def parse_error_message(name):
    return "Error parsing:" + name


def apply_outcome(verification, parse_ok, type_id, name):
    """Outcome of applying one option value.

    Returns a dict: status_code (0/3/4, or None when the type-21/22
    fallback arm owns the outcome), message (or None), parsed (was
    the value parsed), written (was the options struct written).
    """
    if verification == 4:
        return {"status_code": STATUS_OK, "message": None,
                "parsed": False, "written": False}
    if parse_ok:
        return {"status_code": STATUS_OK, "message": None,
                "parsed": True, "written": True}
    if type_id in (21, 22):
        return {"status_code": None, "message": None,
                "parsed": False, "written": False,
                "fallback_arm": "0x60bf1e0"}
    if verification in (1, 2, 3):
        return {"status_code": STATUS_NOT_SUPPORTED,
                "message": not_supported_message(name),
                "parsed": False, "written": False}
    return {"status_code": STATUS_INVALID_ARGUMENT,
            "message": parse_error_message(name),
            "parsed": False, "written": False}


def serialize_outcome(verification):
    """Outcome of serializing one option entry: 'skip' or 'emit'."""
    return "skip" if verification == 4 else "emit"


def verification_counts(part):
    """Distribution counts for 'dboptions' or 'cfoptions'."""
    return dict(DISTRIBUTION[part]["counts"])
