#!/usr/bin/env python3
"""Model of the four TTL OptionTypeInfo map entries (node #115).

The static initializer 0x6206ef0 inserts exactly one entry into each of
four static OptionTypeInfo maps. The pack's low 32 bits are the type (22)
and its high 32 bits are the verification: 0x100000016 = type 22 /
verification 1, 0x300000016 = type 22 / verification 3. All four entries
carry type 22; only 'user_filter_factory' carries verification 3, and
only 'user_filter' carries flags 0x1200 (the others 0x400).

The 'ttl' entry is the odd one: its block sets no pack and no flags of
its own -- the byte-scan in the packet's census.py finds no store to
the record's pack (-0x68(%rbp)) or flags (-0x60(%rbp)) slot between the
end of the 'user_operator' block (0x62070f9) and the ttl insert
(0x620726b), so the ttl entry reuses the preceding block's pack (from
GOT slot 0x458f68) and flags 0x400.

A fifth map, 0x65094c0, is zeroed at the initializer entry (0x6206ef5)
and atexit-registered, but the initializer inserts nothing into it.
"""
from __future__ import annotations

# The four map entries inserted by the initializer 0x6206ef0.
# map address -> (key, key literal, pack, flags, insert site, atexit site)
MAP_ENTRIES = {
    0x6509480: ("user_operator", 0x44C438, 0x100000016, 0x400,
                0x62070C2, 0x62070F4),
    0x6509440: ("ttl", 0x4322BE, 0x100000016, 0x400,
                0x620726B, 0x62072D4),
    0x6509400: ("user_filter_factory", 0x44FFE6, 0x300000016, 0x400,
                0x620740B, 0x620743B),
    0x65093C0: ("user_filter", 0x4385BB, 0x100000016, 0x1200,
                0x6207575, 0x62075BE),
}

# The fifth map: zeroed at the initializer entry (0x6206ef5) and
# atexit-registered, no insert in the initializer.
EMPTY_MAP = 0x65094C0

INITIALIZER = 0x6206EF0
INSERT_HELPER = 0x5D405B0
PACK_GOT_SLOT_TYPE22_VER1 = 0x458F68
PACK_GOT_SLOT_TYPE22_VER3 = 0x4594E8


def entry_for(map_addr: int) -> dict | None:
    """The single entry of the map, or None if the map is empty."""
    if map_addr not in MAP_ENTRIES:
        return None
    key, literal, pack, flags, insert, atexit = MAP_ENTRIES[map_addr]
    return {
        "key": key,
        "key_literal": literal,
        "pack": pack,
        "type": pack & 0xFFFFFFFF,
        "verification": pack >> 32,
        "flags": flags,
        "insert_site": insert,
        "atexit_site": atexit,
    }


def pack_source(map_addr: int) -> str:
    """Where the entry's pack comes from: the 'ttl' entry inherits it."""
    if map_addr == 0x6509440:
        return "inherited"
    if map_addr == 0x6509400:
        return "got:0x4594e8"
    if map_addr in MAP_ENTRIES:
        return "got:0x458f68"
    raise KeyError(f"unknown map {map_addr:#x}")


def lookup(map_addr: int, key: str) -> bool:
    """Whether `key` is the entry the initializer inserted into the map."""
    entry = entry_for(map_addr)
    return entry is not None and entry["key"] == key


def ttl_reuses_preceding_block() -> bool:
    """The ttl entry reuses the preceding block's pack and flags."""
    entry = entry_for(0x6509440)
    assert entry is not None
    return (entry["pack"] == MAP_ENTRIES[0x6509480][2]
            and entry["flags"] == MAP_ENTRIES[0x6509480][3])
