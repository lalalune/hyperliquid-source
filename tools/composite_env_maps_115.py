"""Model of the three CompositeEnvWrapper OptionTypeInfo maps (node #115).

Resolves merged PR #3950's open unknown: the contents of the three .bss
maps the CompositeEnvWrapper ctor registers with empty names. The static
initializer 0x5fe0760 inserts exactly one entry into each map; the record
pack at record+0xa0 carries (OptionType, OptionVerification) and the
flags live at record+0xa8.
"""
from __future__ import annotations

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# map address -> (group base, key, pack, flags, insert site, atexit site)
MAPS = {
    0x6504C60: {
        "group_base": "object+0x48 (Env*)",
        "key": "target",
        "key_literal": 0x44A390,
        "pack": 0x10000001A,
        "flags": 0x2000,
        "insert_site": 0x5FE0B4A,
        "atexit_site": 0x5FE0BEE,
    },
    0x6504C20: {
        "group_base": "object+0x28 (FileSystem shared_ptr)",
        "key": "file_system",
        "key_literal": 0x44B349,
        "pack": 0x100000016,
        "flags": 0x400,
        "insert_site": 0x5FE0D4B,
        "atexit_site": 0x5FE0D7F,
    },
    0x6504BE0: {
        "group_base": "object+0x38 (SystemClock shared_ptr)",
        "key": "clock",
        "key_literal": 0x4496D9,
        "pack": 0x100000016,
        "flags": 0x400,
        "insert_site": 0x5FE0ED1,
        "atexit_site": 0x5FE0F1A,
    },
}

# The #3950 registration triples these maps belong to.
REGISTRATIONS_3950 = [
    {"call_site": 0x5FD73CB, "name": "", "base": "object+0x48 (Env*)",
     "map": 0x6504C60},
    {"call_site": 0x5FD73F1, "name": "", "base": "object+0x28 (FileSystem shared_ptr)",
     "map": 0x6504C20},
    {"call_site": 0x5FD7417, "name": "", "base": "object+0x38 (SystemClock shared_ptr)",
     "map": 0x6504BE0},
]

# Shared std::function callback pairs (GOT slot -> resolved target).
CALLBACK_PAIRS = [
    {"got_slots": (0x64ED8D0, 0x64ED958),
     "resolved": (0x5FCC660, 0x5FD4C30)},
    {"got_slots": (0x64ED8C8, 0x64ED960),
     "resolved": (0x5FD5460, 0x5FD7470)},
]

INSERT_HELPER = 0x5D405B0
MAP_DESTRUCTOR = 0x5D3F820
INITIALIZER = 0x5FE0760


def decode_pack(pack: int) -> tuple[int, int]:
    """Split a record pack into (OptionType, OptionVerification)."""
    return pack & 0xFFFFFFFF, pack >> 32


def option_type(map_addr: int) -> int:
    return decode_pack(MAPS[map_addr]["pack"])[0]


def verification(map_addr: int) -> int:
    return decode_pack(MAPS[map_addr]["pack"])[1]


def lookup(map_addr: int, key: str):
    """Return the entry dict for key in map, or None (one entry per map)."""
    entry = MAPS.get(map_addr)
    if entry is None or entry["key"] != key:
        return None
    return entry


def all_keys() -> list[str]:
    return [m["key"] for m in MAPS.values()]
