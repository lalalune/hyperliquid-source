"""Model of the OptionTypeInfo type-21/22 arm on node #115.

Ground: research/work-items/RE-001-optiontypeinfo-type2122-arm-115/records.json
(apply 0x60bedc0, arm 0x60bf1e0, setter 0x6099e70, map parser 0x60c1190,
create-by-name 0x609b8a0, apply-created 0x609b700, custom parse 0x60809e0,
serializer 0x60bb9a0), bound to artifact sha256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.

Outcomes are ("ok", detail) / ("error", code, message) / ("delegate", address).
"delegate" means the binary hands the value to a routine whose internals are
an open unknown (0x609a740, 0x61ca3d0, 0x60971c0); the model records the
handoff, it does not invent the delegate's result.

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

    Braces: a value starting with '{' and ending with '}' has both stripped.
    Pairs are split on ';'; each pair is scanned with find_first_of("={};").
    Returns (True, {k: v}) or (False, (code, message)).
    A trailing ';' ends the scan cleanly: the loop-end check at 0x60c1321
    (position >= length -> done) runs before the next find_first_of.
    """
    if value.startswith("{") and value.endswith("}") and len(value) >= 2:
        value = value[1:-1]
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


def equals_path(value, config_byte3=0, slot40_is_empty_stub=True):
    """Model of the '=' path setter 0x6099e70.

    config_byte3: ConfigOptions+0x3; slot40_is_empty_stub: whether the
    object's vtable slot 0x40 is the empty-Status stub 0x60956f0.
    Returns ("ok", detail) / ("error", code, message).
    """
    if ";" in value or "=" in value:
        ok, parsed = parse_map(value)
        if not ok:
            return ("error",) + parsed
        # 0x6097110 tail-calls ConfigureOptions slot 0x48 (0x609d0e0).
        return ("ok", {"configure_options_map": parsed, "slot": "0x48"})
    if not slot40_is_empty_stub:
        return ("ok", {"slot40_called": True})
    if config_byte3 == 0:
        return ("ok", {"slot40": "empty stub", "prepare_options": "skipped"})
    # PrepareOptions slot 0x28 (0x6095e70).
    return ("ok", {"slot40": "empty stub", "prepare_options": "slot 0x28"})


def no_equals_path(name, registry, entry_type=22):
    """Model of the no-'=' path (0x609ba30 -> 0x609b8a0 -> 0x609b700).

    registry: mapping of nested option name -> (entry_type, found_record).
    GetOptionName (slot 0x68) is called but its return is ignored.
    """
    found = registry.get(name)
    if found is None:
        return ("error", 1, "Could not find option: " + name)
    if entry_type == 22:
        return ("delegate", "0x609a740")
    # types 19/21/22 with a name match call ParseOption slot 0x50 (0x60986b0).
    return ("ok", {"parse_option": "slot 0x50", "record": found})


def apply_arm(name, value, object_present, config_byte3=0,
              slot40_is_empty_stub=True, registry=None):
    """Model of the type-21/22 arm at 0x60bf1e0 for one entry.

    registry is used only by the no-'=' path (nested-option lookup).
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
        return equals_path(value, config_byte3, slot40_is_empty_stub)
    return no_equals_path(name, registry or {}, entry["type"])


def serialize_type22(name, object_present, config_byte4=0, config_u32_28=0,
                     object_name="BasicStatistics", object_options=""):
    """Model of the serializer's type-22 arm (entry 0x60bbbf0).

    config_byte4 / config_u32_28 are ConfigOptions+0x4 / +0x28 (C++ names open).
    object_options is what 0x60971c0 would emit for the object (open unknown);
    the model records the shape, not its contents.
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
            return ("ok", object_name + ";" + object_options)
        if config_byte4 == 0:
            return ("ok", object_name)
        if not (flags & 0x100):
            return ("ok", "")
        return ("ok", object_name)
    # No flag bit set: main body 0x60bba66.
    return ("ok", object_name + ";" + object_options)
