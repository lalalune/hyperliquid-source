"""Model of the vtable-slot method names behind ColumnFamilyOptions::Dump.

RE-001, node #115, artifact SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.

This module models the OBSERVABLE behavior pinned by the evidence
packet research/work-items/RE-001-dump-slot-method-names-115/:

* EnvLogger level gate and the two log helpers (0x5fceda0, 0x5fceea0):
  a level-L message is emitted iff L >= log_level_; a level-5
  (HEADER) message is emitted iff 1 >= log_level_ because LogHeader
  re-gates through Logv(INFO_LEVEL).
* AutoRollLogger LogHeader forwards to wrapped slot 4 when its
  wrapped logger is present. Downstream emission remains unresolved.
* Logger Close(): idempotent via the closed_ flag at +0x10.
* GetPrintableOptions() dispatch by concrete TableFactory / Cache
  class (dump lines 7 and 88), including the base-default empty
  string and the blob-cache devirtualization guard.
* Cache Name() dispatch (dump line 87).
* TablePropertiesCollectorFactory ToString() dispatch and the dump's
  devirtualization guard (dump line 62).
* The host gate: the dump runs iff NumberOfColumnFamilies() < 10.
* Configurable::GetOption's "id" special case (slot 15 = GetId).

All addresses and slot numbers come from the packet's vtables.tsv,
guards.tsv and records.json; the model contains no behavior the
packet does not evidence.
"""

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)

# InfoLogLevel values pinned by the binary (only 1 and 5 appear in the
# slot functions; the names are the v8.1.1 header names).
INFO_LEVEL = 1
HEADER_LEVEL = 5

# The host gate: ColumnFamilyData ctor dumps iff fewer than 10 CFs.
HOST_DUMP_MAX_CFS = 10

# Vtable addresses (typeinfo-verified class names in records.json).
VTABLES = {
    "EnvLogger": 0x64CDA68,
    "AutoRollLogger": 0x64D1F00,
    "BlockBasedTableFactory": 0x64D39B8,
    "CuckooTableFactory": 0x64D5CF0,
    "PlainTableFactory": 0x64D6628,
    "Cache": 0x64C8C60,
    "LRUCache": 0x64C89B8,
    "ShardedCache<LRUCacheShard>": 0x64C88B0,
    "ShardedCacheBase": 0x64C8B48,
    "CacheWrapper": 0x64C8DA0,
    "CacheWithSecondaryAdapter": 0x64C8EA0,
    "ChargedCache": 0x64C9E00,
    "CompactOnDeletionCollectorFactory": 0x64D9088,
}

# Slot -> function address, from vtables.tsv.
SLOTS = {
    "EnvLogger": {
        0: 0x5FCFB90, 1: 0x5FCFDE0, 2: 0x5FCC410, 3: 0x5FCC200,
        4: 0x5FCE280, 5: 0x5FCD400, 6: 0x5FCCED0, 7: 0x5FCE130,
        8: 0x5FCC220, 9: 0x5FCC230, 10: 0x5FCEAE0,
    },
    "AutoRollLogger": {
        0: 0x60576B0, 1: 0x6057D00, 2: 0x5FCC410, 3: 0x6057000,
        4: 0x6058770, 5: 0x5FCD400, 6: 0x6057590, 7: 0x6057440,
        8: 0x60552E0, 9: 0x6055280, 10: 0x60551D0,
    },
    "BlockBasedTableFactory": {
        2: 0x609D760, 3: 0x609DC40, 4: 0x60DA1F0, 5: 0x60DB570,
        6: 0x60D8B10, 7: 0x60D74E0, 8: 0x60956F0, 9: 0x609D0E0,
        10: 0x60D7D20, 11: 0x6095710, 12: 0x609DE80, 13: 0x609D980,
        14: 0x60B1D90, 15: 0x5D32A30,
    },
    "CuckooTableFactory": {
        2: 0x609D760, 3: 0x609DC40, 4: 0x615ACA0, 5: 0x6095E70,
        6: 0x6096790, 7: 0x5D2E090, 8: 0x60956F0, 9: 0x609D0E0,
        10: 0x60986B0, 11: 0x6095710, 12: 0x609DE80, 13: 0x609D980,
        14: 0x615AAE0, 15: 0x5D32A30,
    },
    "PlainTableFactory": {
        2: 0x609D760, 3: 0x609DC40, 4: 0x6192D70, 5: 0x6095E70,
        6: 0x6096790, 7: 0x5D2E090, 8: 0x60956F0, 9: 0x609D0E0,
        10: 0x60986B0, 11: 0x6095710, 12: 0x609DE80, 13: 0x609D980,
        14: 0x6192820, 15: 0x5D32A30,
    },
    # Cache classes: only slots 2 (Name) and 25 (GetPrintableOptions)
    # are pinned; slot 2 of the base Cache, ShardedCache,
    # ShardedCacheBase and CacheWrapper is __cxa_pure_virtual.
    "Cache": {25: 0x5D3F6C0},
    "LRUCache": {2: 0x5D3A950, 25: 0x5D3F210},
    "ShardedCache<LRUCacheShard>": {25: 0x5D3F210},
    "ShardedCacheBase": {25: 0x5D3F210},
    "CacheWrapper": {25: 0x5D3F6C0},
    "CacheWithSecondaryAdapter": {2: 0x5D42BB0, 25: 0x5D42460},
    "ChargedCache": {2: 0x5DB68C0, 25: 0x5D3F6C0},
    "CompactOnDeletionCollectorFactory": {
        2: 0x609D760, 3: 0x609DC40, 4: 0x5D32560, 5: 0x6095E70,
        6: 0x6096790, 7: 0x5D2E090, 8: 0x60956F0, 9: 0x609D0E0,
        10: 0x60986B0, 11: 0x6095710, 12: 0x609DE80, 13: 0x609D980,
        14: 0x61F9880, 15: 0x5D32A30, 16: 0x5D2E770, 17: 0x5D2CA00,
        18: 0x5D2CA10, 19: 0x61FB010, 20: 0x61FB370,
    },
}

# Shared Configurable implementations.
GET_OPTION = 0x609D760
ARE_EQUIVALENT = 0x609DC40
BASE_GET_PRINTABLE_OPTIONS = 0x5D3F6C0  # returns ""
BASE_TOSTRING = 0x60B1EA0

# Devirtualization guards in the dump.
GUARD_BLOB_CACHE_GOT = 0x64ECD20   # RELATIVE -> 0x5D3F6C0
GUARD_COLLECTOR_GOT = 0x64EDCA8    # RELATIVE -> 0x60B1EA0

# The dump and its sole host.
DUMP = 0x60B50C0
HOST_CTOR = 0x5D954B0
HELPER_LEVELLED = 0x5FCEDA0
HELPER_NOLEVEL = 0x5FCEEA0

# Name() literals.
NAMES = {
    "BlockBasedTableFactory": "BlockBasedTable",
    "LRUCache": "LRUCache",
    "ChargedCache": "ChargedCache",
    "CompactOnDeletionCollectorFactory": "CompactOnDeletionCollector",
}


def vtable_slot(class_name, slot):
    """Function address at `slot` of `class_name`'s vtable."""
    return SLOTS[class_name][slot]


def logger_gate(level, log_level):
    """True iff a level-`level` message passes the logger's gate.

    Slot 5 (0x5fcd400): `cmp 0x11(%rdi),%sil; jb ret` -- return
    without logging iff level < log_level_.
    """
    return level >= log_level


def helper_levelled(level, log_level):
    """Route of the leveled helper 0x5fceda0 for EnvLogger.

    Returns (path, emitted): path is "skip", "log_header" (slot 3)
    or "logv_levelled" (slot 5).  The helper pre-gates on slot 8
    (skip iff log_level_ > level); level 5 then goes through
    LogHeader, which re-gates through Logv(INFO_LEVEL=1).
    """
    if log_level > level:
        return ("skip", False)
    if level == HEADER_LEVEL:
        return ("log_header", logger_gate(INFO_LEVEL, log_level))
    return ("logv_levelled", True)


def helper_nolevel(log_level):
    """Route of the no-level helper 0x5fceea0 for EnvLogger: always slot 3.

    Returns (path, emitted).  LogHeader forwards to Logv(INFO_LEVEL),
    so the message is emitted iff 1 >= log_level_.
    """
    return ("log_header", logger_gate(INFO_LEVEL, log_level))


def autoroll_header_slot(has_wrapped_logger):
    """Selected forwarding slot after AutoRollLogger LogHeader dispatch.

    The body at 0x6057000 returns when this+0xb8 is null. Its non-null
    path calls wrapped slot 4 at 0x60570f8. Downstream emission and
    allocation, lock and formatting outcomes remain unresolved.
    """
    return 4 if has_wrapped_logger else None


def logger_close(closed):
    """Logger::Close() (slot 2, 0x5fcc410).

    Returns (action, new_closed): "close_impl" (calls slot 10) on
    the first call, "ok_noop" (returns Status OK) once closed_.
    """
    if closed:
        return ("ok_noop", True)
    return ("close_impl", True)


def get_printable_options(class_name):
    """GetPrintableOptions() dispatch (dump lines 7 and 88).

    Returns (function, result): result is "formatted" for the
    per-class formatters, "" for the base default, "delegated" for
    the secondary-adapter wrapper.
    """
    fn = SLOTS[class_name][4] if class_name in (
        "BlockBasedTableFactory", "CuckooTableFactory",
        "PlainTableFactory") else SLOTS[class_name][25]
    if fn == BASE_GET_PRINTABLE_OPTIONS:
        return (fn, "")
    if class_name == "CacheWithSecondaryAdapter":
        return (fn, "delegated")
    return (fn, "formatted")


def cache_name(class_name):
    """Name() dispatch (dump line 87).

    Raises ValueError for the base Cache: its slot 2 is
    __cxa_pure_virtual, so calling it aborts.
    """
    if class_name == "Cache":
        raise ValueError("base Cache::Name is __cxa_pure_virtual")
    if class_name == "CacheWithSecondaryAdapter":
        return "delegate"
    return NAMES[class_name]


def blob_cache_options(cache_slot25):
    """The dump's line-88 guard: slot 25 vs the base default.

    Returns "" when the cache installs the base GetPrintableOptions
    (0x5d3f6c0), "formatted" otherwise (the dump calls slot 25).
    """
    if cache_slot25 == BASE_GET_PRINTABLE_OPTIONS:
        return ""
    return "formatted"


def collector_to_string(factory_slot20):
    """The dump's line-62 guard: slot 20 vs the base ToString.

    Returns ("name_fast_path", "slot_14_name") when the factory installs
    the base ToString (the dump then uses the factory's own slot 14 =
    Name), else ("call_slot20", factory_slot20).
    """
    if factory_slot20 == BASE_TOSTRING:
        return ("name_fast_path", "slot_14_name")
    return ("call_slot20", factory_slot20)


def collector_to_string_for_class(class_name):
    """ToString() dispatch for a concrete collector factory class."""
    return collector_to_string(SLOTS[class_name][20])


def host_dump_gate(num_column_families):
    """The host ctor's gate: Dump runs iff fewer than 10 CFs."""
    return "dump" if num_column_families < HOST_DUMP_MAX_CFS else "skip"


def get_option_route(name):
    """Configurable::GetOption (0x609d760) routing by option name.

    Returns "get_id" when the name is exactly "id" (the function
    checks size == 2 and the bytes 'i','d', then calls slot 15 =
    GetId), else "generic".
    """
    if name == "id":
        return "get_id"
    return "generic"
