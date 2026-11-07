"""Model of the OptionTypeInfo type-21/22 arm on node #115.

Ground: research/work-items/RE-001-optiontypeinfo-type2122-arm-115/records.json
(apply 0x60bedc0, arm 0x60bf1e0, setter 0x6099e70, map parser 0x60c1190,
create-by-name 0x609b8a0, apply-created 0x609b700, custom parse 0x60809e0,
serializer 0x60bb9a0), bound to artifact sha256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.

Outcomes are ("ok", detail) / ("error", code, message) / ("delegate", address).
"delegate" records a call boundary whose return value was not supplied.
Callee Status tuples are explicit inputs and propagate unchanged. The map
parser covers printable ASCII without whitespace and at most one outer brace
pair. Other parser inputs raise ValueError for the model boundary.

Status codes: 1 kNotFound, 3 kNotSupported, 4 kInvalidArgument.
"""
from __future__ import annotations

# (map, name, type, verification, offset, flags) — the 15 type-22 entries;
# type 21 has NO entries in either map. Source: #4237 / #4263 maps packets.
TYPE22_ENTRIES = [
    ("DBOptions", "statistics", 22, 0, 0x48, 0x3401),
    ("DBOptions", "wal_filter", 22, 1, 0x188, 0x1201),
    ("DBOptions", "file_checksum_gen_factory", 22, 3, 0x1A8, 0x1400),
    ("MutableCFOptions", "prefix_extractor", 22, 2, 0x40, 0x1100),
    ("ImmutableCFOptions", "comparator", 22, 1, 0x8, 0x202),
    ("ImmutableCFOptions", "merge_operator", 22, 3, 0x20, 0x1402),
    ("ImmutableCFOptions", "compaction_filter", 22, 1, 0x30, 0x1200),
    ("ImmutableCFOptions", "compaction_filter_factory", 22, 1, 0x38, 0x1400),
    ("ImmutableCFOptions", "memtable", 22, 5, 0x68, 0x400),
    ("ImmutableCFOptions", "memtable_factory", 22, 1, 0x68, 0x400),
    ("ImmutableCFOptions", "block_based_table_factory", 22, 5, 0x78, 0x402),
    ("ImmutableCFOptions", "plain_table_factory", 22, 5, 0x78, 0x402),
    ("ImmutableCFOptions", "table_factory", 22, 1, 0x78, 0xC402),
    ("ImmutableCFOptions", "memtable_insert_with_hint_prefix_extractor", 22, 2, 0xC0, 0x0),
    ("ImmutableCFOptions", "sst_partitioner_factory", 22, 1, 0xF8, 0x1400),
]

# Entries whose record carries a non-empty parse function: the arm never sees
# them; the custom parse runs instead. The other 10 reach the arm.
CUSTOM_PARSE_ENTRIES = {
    "statistics", "wal_filter", "file_checksum_gen_factory",
    "prefix_extractor", "memtable_insert_with_hint_prefix_extractor",
}
REACHABLE_ENTRIES = {e[1] for e in TYPE22_ENTRIES} - CUSTOM_PARSE_ENTRIES

FLAG_BITS = 0x200 | 0x400 | 0x800  # the arm's flags gate
BSS_NULL_NAME = "<bss:0x6508980>"  # runtime string; contents are an open unknown

# (manager, invoker) of the custom parse pair installed for entries that
# never reach the arm. Source: records.json construction section.
PARSE_PAIRS = {
    "statistics": (0x606FA80, 0x60780A0),
    "wal_filter": (0x609F250, 0x609FC80),
    "file_checksum_gen_factory": (0x609F370, 0x60A2360),
    "prefix_extractor": (0x607D190, 0x60809E0),
    "memtable_insert_with_hint_prefix_extractor": (0x607D190, 0x60809E0),
}

MAP_ERRORS = {
    "mismatched": (4, "Mismatched key value pair, '=' expected"),
    "unexpected": (4, "Unexpected char in key"),
    "empty_key": (4, "Empty key found"),
}


def entry_by_name(name):
    for e in TYPE22_ENTRIES:
        if e[1] == name:
            return {"map": e[0], "name": e[1], "type": e[2],
                    "verification": e[3], "offset": e[4], "flags": e[5]}
    return None


def reaches_arm(name):
    """True iff the entry's parse function is empty, so apply dispatches it
    to the type-21/22 arm at 0x60bf1e0."""
    return name in REACHABLE_ENTRIES


def effective_flags(name):
    """Stored flags with the type-22 helper's forced 0x400 applied: the
    helper ORs 0x400 into the flags of prefix_extractor and
    memtable_insert_with_hint_prefix_extractor (or $0x4,%ch at 0x6083a99)."""
    e = entry_by_name(name)
    if e is None:
        raise KeyError(name)
    flags = e["flags"]
    if name in ("prefix_extractor", "memtable_insert_with_hint_prefix_extractor"):
        flags |= 0x400
    return flags


def parse_map(value):
    """Model of the map parser 0x60c1190.

    The supported domain is printable ASCII without whitespace, with at most
    one outer brace pair around a flat map. Whitespace trimming and nested
    delimiter handling in 0x61d11f0 / 0x60b97f0 require separate evidence.
    ValueError identifies inputs outside this model's domain.
    Returns (True, {k: v}) or (False, (code, message)).
    A trailing ';' ends the scan cleanly at 0x60c1321.
    """
    if any(ord(char) < 33 or ord(char) > 126 for char in value):
        raise ValueError("map model requires printable ASCII without whitespace")
    if len(value) > 2 and value.startswith("{") and value.endswith("}"):
        value = value[1:-1]
    if "{" in value or "}" in value:
        raise ValueError("map model supports a single outer brace pair and flat values")
    result = {}
    pos = 0
    while pos < len(value):
        # find_first_of("={};") from pos
        cut = len(value)
        hit = None
        for i in range(pos, len(value)):
            if value[i] in "={};":
                cut, hit = i, value[i]
                break
        if hit is None:
            return False, MAP_ERRORS["mismatched"]
        if hit != "=":
            return False, MAP_ERRORS["unexpected"]
        key = value[pos:cut]
        if key == "":
            return False, MAP_ERRORS["empty_key"]
        # value runs to the next ';' or the end
        end = value.find(";", cut + 1)
        if end == -1:
            end = len(value)
        result[key] = value[cut + 1:end]
        pos = end + 1
    return True, result


def custom_parse(name, value):
    """Model of the custom parse 0x60809e0 (helper entries only)."""
    if name == "id" and value == "":
        return ("ok", "shared_ptr reset to null")
    return ("delegate", "0x61ca3d0")


def equals_path(value, config_byte3=0, slot40_is_empty_stub=True, *,
                configure_status=None, slot40_status=None, prepare_status=None):
    """Project setter 0x6099e70 with explicit callee Status inputs.

    Missing callee results yield a delegate event. A failed slot 0x40 result
    stops before PrepareOptions. A successful result continues through the
    ConfigOptions+0x3 gate, including when slot 0x40 is a real function.
    """
    if ";" in value or "=" in value:
        ok, parsed = parse_map(value)
        if not ok:
            return ("error",) + parsed
        if configure_status is None:
            return ("delegate", {"target": "0x6097110", "slot": "0x48",
                                 "configure_options_map": parsed})
        return configure_status
    status = ("ok", "empty Status")
    # The empty-value branch at 0x6099eae skips slot 0x40.
    if value and not slot40_is_empty_stub:
        if slot40_status is None:
            return ("delegate", "slot 0x40")
        if slot40_status[0] != "ok":
            return slot40_status
        status = slot40_status
    if config_byte3 != 0:
        if prepare_status is None:
            return ("delegate", "slot 0x28")
        return prepare_status
    return status


def no_equals_path(name, registry, entry_type=22, *, parse_status=None):
    """Project a successful nested lookup for record types 19, 21 and 22.

    registry supplies the lookup outcome. GetOptionName's return is ignored.
    Other record types also depend on a separate name-comparison boundary.
    """
    found = registry.get(name)
    if found is None:
        return ("error", 1, "Could not find option: " + name)
    if entry_type == 22:
        return ("delegate", "0x609a740")
    if entry_type not in (19, 21):
        raise ValueError("lookup model supports record types 19, 21 and 22")
    if parse_status is None:
        return ("delegate", "slot 0x50")
    return parse_status


def apply_arm(name, value, object_present, config_byte3=0,
              slot40_is_empty_stub=True, registry=None, *, configure_status=None):
    """Model of the type-21/22 arm at 0x60bf1e0 for one entry.

    registry supplies the nested lookup. The arm clears byte +0x3 in its
    ConfigOptions copy at 0x60bf23e before calling the setter.
    """
    entry = entry_by_name(name)
    if entry is None:
        return ("error", 1, "Could not find option: " + name)
    if entry["verification"] == 4:
        # Verification 4 returns Status OK before the type dispatch (#4311).
        return ("ok", "verification 4: never parsed")
    if not reaches_arm(name):
        manager, invoker = PARSE_PAIRS[name]
        return ("delegate", "custom parse 0x%x/0x%x" % (manager, invoker))
    flags = effective_flags(name)
    if flags & FLAG_BITS:
        if value == "":
            return ("ok", "empty value")
        if not object_present:
            return ("error", 1, "Could not find configurable: " + name)
    else:
        if value == "":
            return ("ok", "empty value")
    # Main body 0x60bf212: ConfigOptions copy, then split on '='.
    if "=" in value:
        return equals_path(value, 0, slot40_is_empty_stub,
                           configure_status=configure_status)
    return no_equals_path(name, registry or {}, entry["type"])


def serialize_type22(name, object_present, config_byte4=0, config_u32_28=0,
                     object_name="BasicStatistics", object_options=None):
    """Model of the serializer's type-22 arm (entry 0x60bbbf0).

    config_byte4 / config_u32_28 are ConfigOptions+0x4 / +0x28 (C++ names open).
    object_options supplies the complete string returned by 0x60971c0.
    When omitted, that call yields a delegate event. The helper receives a
    semicolon ConfigOptions delimiter; its internals remain a call boundary.
    Returns ("ok", emitted_string).
    """
    entry = entry_by_name(name)
    if entry is None:
        return ("error", 1, "Could not find option: " + name)
    flags = effective_flags(name)
    if flags & FLAG_BITS:
        if not object_present:
            if flags & 0x100:
                return ("ok", BSS_NULL_NAME)
            if config_byte4 != 0:
                return ("ok", "")
            return ("ok", BSS_NULL_NAME)
        # Non-null object: the 0x60bbc15 branch.
        if not (flags & 0x8000) or config_u32_28 == 2:
            if object_options is None:
                return ("delegate", "0x60971c0")
            # The caller clears copied byte +4 for flags 0x100, then checks
            # the helper output for '=' at 0x60bbd56 when that byte is set.
            if not (flags & 0x100) and config_byte4 != 0 and "=" not in object_options:
                return ("ok", "")
            return ("ok", object_options)
        if config_byte4 == 0:
            return ("ok", object_name)
        if not (flags & 0x100):
            return ("ok", "")
        return ("ok", object_name)
    raise ValueError("stored type-22 entries all carry an effective flag-gate bit")
