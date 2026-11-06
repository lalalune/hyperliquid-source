"""Python model of the node #115 options default-init pair.

Routines (all in work/hl-node-115.bin, digest pinned in the
RE-001-options-default-init-115 packet):
  * 0x60b3c30  base init: writes the +0x00..+0x1e8 fields.
  * 0x60b3fb0  main init: writes the +0x1e8..+0x2f8 fields, builds
    a stack temp and calls the table-options copy 0x60db710.
  * 0x606ead0  small-limits preset: overwrites five fields.
  * 0x61be810  function-local singleton getter (opaque pointer).
  * 0x60db710  table-options copy: copies the stack temp into
    the 0x260-byte heap object at options+0x2b8.
  * 0x60dbd80  allocator wrapper: new 0x260 bytes + table copy.

Field values are ints (the exact stored value), ("ptr", label)
tokens for heap/singleton pointers, or ("bytes", hex) for
16-byte constant blocks. Offsets are relative to the options
object. The model pins only what the disassembly shows; the
RocksDB field names are NOT claimed (the packet records them
as unknown).
"""

import struct

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# The options object spans at least +0x00..+0x2f8. The base init
# writes +0x00..+0x1e8, the main init +0x1e8..+0x2f8.
BASE_FIELDS = {
    0x00: 0x100000002,
    0x08: 0,
    0x10: 0,
    0x18: 0,
    0x20: 0x2710,
    0x28: 0,
    0x30: 0,
    0x38: 0,
    0x40: 0,
    0x48: 0,
    0x50: ("bytes", "00000000000000000000000000000000"),
    0x60: 0,
    0x68: 0,
    0x70: ("bytes", "00000000000000000000000000000000"),
    0x80: 0,
    0x88: 0x1400000007,
    0x90: 0x24,
    0x98: 0x4000000,
    0xA0: 0x1,
    0xA4: 0x100,
    0xA8: 0x4024000000000000,
    0xB0: ("ptr", "heap1c"),
    0xB8: ("ptr", "heap1c+0x1c"),
    0xC0: ("ptr", "heap1c+0x1c"),
    0xC8: 0,
    0xD0: 0x1,
    0xD8: ("bytes", "00000000100000000000000040000000"),
    0xE8: 0x300,
    0xEC: ("bytes", "0100000002000000ffffffffc8000000"),
    0xFC: 0x1FFFFFFFF,
    0x104: 0,
    0x108: 0x40000000,
    0x110: 0,
    0x118: ("bytes", "00000000000000000800000000000000"),
    0x128: ("ptr", "heap28"),
    0x130: ("ptr", "heap18a"),
    0x138: ("bytes", "00000000000000000000000000000000"),
    0x148: 0,
    0x150: 0,
    0x158: 0x1000100,
    0x15C: 0,
    0x160: ("bytes", "fefffffffffffffffeffffffffffffff"),
    0x170: 0,
    0x178: 0,
    0x180: ("bytes", "00000000000000000000000000000000"),
    0x190: 0,
    0x198: ("bytes", "00000000000000000000001000000000"),
    0x1A8: 0,
    0x1B0: ("bytes", "000000000000d03f000000000000f03f"),
    0x1C0: 0,
    0x1C8: 0,
    0x1D0: ("bytes", "00000000000000000000000000000000"),
    0x1E0: 0,
    0x1E4: 0,
}

MAIN_FIELDS = {
    0x1E8: ("ptr", "singleton61be810"),
    0x1F0: 0,
    0x1F8: 0,
    0x200: 0,
    0x208: 0,
    0x210: 0,
    0x218: 0x4000000,
    0x220: 0xFF01,
    0x228: 0x7FFFFFFFFFF2,
    0x230: 0,
    0x238: 0x100000000,
    0x240: 0,
    0x248: 0,
    0x250: 0x1,
    0x258: 0x7FFFFFFFFFF2,
    0x260: 0,
    0x268: 0x100000000,
    0x270: 0,
    0x278: 0,
    0x280: 0x1,
    0x288: 0x4,
    0x290: ("bytes", "00000000000000000000000000000000"),
    0x2A0: ("bytes", "00000010000000000000000000000000"),
    0x2B0: 0,
    0x2B8: ("ptr", "heap260"),
    0x2C0: ("ptr", "heap18b"),
    0x2C8: ("bytes", "00000000000000000000000000000000"),
    0x2D8: ("bytes", "00000000000000000000000000000000"),
    0x2E8: ("bytes", "00000000000000000000000000000000"),
    0x2F8: 0,
}

# The preset overwrites five fields (offsets relative to the
# options object). +0x220 is a single-byte store, so only the
# low byte of the 0xff01 word changes: 0xff01 -> 0xff00.
PRESET_OVERRIDES = {
    0x218: 0x200000,
    0x98: 0x200000,
    0x2A0: 0xA00000,
    0x220: 0xFF00,
    0xD8: ("bytes", "00000010000000000000004000000000"),
}

# The stack temp the main init builds for the table-options
# copy (0x60db710). The temp is zeroed first (232 bytes), then
# these stores land. Values are (offset, size, value); sizes
# are 1, 2, 4, 8, or 16 bytes.
TEMP_STORES = [
    (0x11, 4, 0x10001),
    (0x2E, 4, 0x43FE8),
    (0x59, 8, 0x0A00000000000010),
    (0x64, 8, 0x0000000100000010),
    (0x71, 8, 0x0200000000000010),
    (0x98, 8, ("ptr", "temp+0x88")),
    (0xA0, 8, ("ptr", "temp+0x88")),
    (0xB2, 1, 0x1),
    (0xC8, 1, 0x1),
    (0xD0, 4, 0x5),
    (0xD4, 1, 0x1),
    (0xD6, 1, 0x1),
    (0xD8, 8, 0x40000),
    (0xE8, 16, ("bytes", "00200000000000000200000000000000")),
]

# Deterministic prefix of the table-options copy (0x60db710):
# (heap offset, temp offset, size, kind) where kind is "copy"
# (verbatim), "u32"/"u16"/"u8" (narrow copy), "double" (the
# temp qword read as a double), or "zero" (16 zero bytes).
TABLE_COPY = [
    (0x20, 0x00, 8, "copy"),
    (0x28, 0x08, 8, "copy"),
    (0x30, 0x10, 4, "u32"),
    (0x34, 0x14, 8, "copy"),
    (0x3C, 0x1C, 4, "u32"),
    (0x40, 0x20, 2, "u16"),
    (0x48, 0x28, 8, "double"),
    (0x50, 0x30, 2, "u16"),
    (0x58, 0x38, 16, "copy"),
    (0x68, 0x48, 16, "copy"),
    (0x78, 0x58, 8, "copy"),
    (0x80, 0x60, 8, "copy"),
    (0x88, 0x68, 4, "u32"),
    (0x90, 0x70, 8, "copy"),
    (0x98, 0x78, 4, "u32"),
    (0xA8, None, 4, "zero32"),
    (0xB0, None, 8, "zero"),
    (0xB8, None, 8, "self+0xa8"),
    (0xC0, None, 8, "self+0xa8"),
    (0xC8, 0xA8, 8, "copy"),
    (0xD0, 0xB0, 2, "u16"),
    (0xD2, 0xB2, 1, "u8"),
    (0xD8, 0xB8, 16, "copy"),
    (0xE8, 0xC8, 2, "u16"),
    (0xEA, 0xCA, 1, "u8"),
    (0xEC, 0xCC, 8, "copy"),
    (0xF4, 0xD4, 2, "u16"),
    (0xF6, 0xD6, 1, "u8"),
    (0xF8, 0xD8, 8, "copy"),
    (0x100, 0xE0, 1, "u8"),
    (0x108, 0xE8, 16, "copy"),
    (0x118, None, 16, "zero"),
    (0x250, None, 16, "zero"),
]

# Direct call sites of the init (13) and the preset (3).
# The pair (init immediately followed by preset on the same
# object) holds at exactly three sites.
INIT_CALLS = [
    0x5D35686, 0x5D74D31, 0x5D96CA4, 0x5E3480C, 0x5E35444,
    0x5E5A9A1, 0x5E61CD3, 0x5FA4A97, 0x60A43FF, 0x60CDBA6,
    0x60CF671, 0x60CF699, 0x6203E0A,
]
PRESET_CALLS = [0x5E5A9A9, 0x5E61CDB, 0x5FA4A9F]
PAIR_SITES = [
    (0x5E5A9A1, 0x5E5A9A9, 0x5E5A8C0),
    (0x5E61CD3, 0x5E61CDB, 0x5E61AD0),
    (0x5FA4A97, 0x5FA4A9F, 0x5FA47E0),
]
INIT_ONLY_SITES = [c for c in INIT_CALLS
                   if c not in [p[0] for p in PAIR_SITES]]

# The 0x18-byte object at options+0x2c0: {vtable 0x64d37b8,
# +0x08 = 0x100000001, +0x10 = the table-options heap object}.
HEAP18B_VTABLE = 0x64D37B8
# The table-options heap object vtable (0x64d39a8 + 0x10).
TABLE_VTABLE = 0x64D39B8


def base_init():
    """Apply the base init 0x60b3c30 to a fresh options dict."""
    return dict(BASE_FIELDS)


def main_init(opts):
    """Apply the main init 0x60b3fb0 on top of the base fields."""
    opts.update(MAIN_FIELDS)
    return opts


def apply_preset(opts):
    """Apply the preset 0x606ead0 on top of a default-init."""
    opts.update(PRESET_OVERRIDES)
    return opts


def default_init():
    """base + main, the state every init call site produces."""
    return main_init(base_init())


def build_table_temp():
    """The stack temp the main init builds for 0x60db710:
    a 232-byte zeroed buffer with the pinned stores applied.
    Returns a dict offset -> int for every stored byte range,
    plus the ("ptr", ...) markers."""
    temp = {}
    for off, size, value in TEMP_STORES:
        if isinstance(value, tuple):
            temp[off] = value
        else:
            temp[off] = (value, size)
    return temp


def temp_bytes(off, size):
    """Raw little-endian bytes of the temp at [off, off+size)."""
    buf = bytearray(size)
    for store_off, store_size, value in TEMP_STORES:
        if isinstance(value, tuple):
            if value[0] != "bytes":
                continue
            raw = bytes.fromhex(value[1])
            for i in range(store_size):
                pos = store_off + i
                if off <= pos < off + size:
                    buf[pos - off] = raw[i]
            continue
        for i in range(store_size):
            pos = store_off + i
            if off <= pos < off + size:
                buf[pos - off] = (value >> (8 * i)) & 0xFF
    return bytes(buf)


def temp_u64(off):
    """The temp qword at off (pointer stores read as zero)."""
    raw = temp_bytes(off, 8)
    return struct.unpack("<Q", raw)[0]


def temp_double(off):
    """The temp qword at off read as a double."""
    return struct.unpack("<d", temp_bytes(off, 8))[0]


def table_copy(temp=None):
    """The deterministic prefix of the table-options copy:
    heap offset -> value, from the default temp."""
    heap = {0x00: ("ptr", "vtable64d39b8")}
    for heap_off, temp_off, size, kind in TABLE_COPY:
        if kind == "zero":
            heap[heap_off] = ("bytes", "00" * size)
        elif kind == "zero32":
            heap[heap_off] = 0
        elif kind == "self+0xa8":
            heap[heap_off] = ("ptr", "heap+0xa8")
        elif kind == "double":
            heap[heap_off] = temp_double(temp_off)
        elif kind == "u32":
            heap[heap_off] = temp_u64(temp_off) & 0xFFFFFFFF
        elif kind == "u16":
            heap[heap_off] = temp_u64(temp_off) & 0xFFFF
        elif kind == "u8":
            heap[heap_off] = temp_u64(temp_off) & 0xFF
        elif size == 16:
            heap[heap_off] = ("bytes", temp_bytes(temp_off, 16).hex())
        else:
            heap[heap_off] = temp_u64(temp_off)
    return heap
