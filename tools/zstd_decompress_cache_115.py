"""Python model of node #115's cached ZSTD decompress context
(rocksdb::CompressionContextCache::GetCachedZSTDUncompressData).

RE-001 work item; see research/work-items/RE-001-zstd-decompress-cache-115/
for the evidence packet. The model reproduces the binary behaviour
exactly as the excerpts show it; nothing here is an implementation
claim about the upstream reconstruction.

Layout
------
Table T (16 bytes, function-local static at 0x6508900, built once by
the getter 0x61c2120 via the static init 0x61c20d0 and the table ctor
0x61c1f30):
  T+0x0: entries pointer (array base; count stored at base-8)
  T+0x8: shift (dword)
Array: operator new[](count * 64 + 8); [count:8][entries: count * 64].
Each 64-byte entry: +0x0 object pointer (null until claimed),
+0x8 marker (-1 while the slot owns its object), +0x10 claim word
(the entry address itself while unclaimed, 0 once claimed).

Claim (0x61c1e10): pick the shard by CPUID (0x60d5cd0) or, when the
picker returns -1, by advancing the per-thread LCG seed (0x61c4080)
once; entry = base + index * 64; lock cmpxchg(entry+0x10,
expect=entry, new=0). First claimer wins the shared slot (lazy
ZSTD_createDCtx into the slot when empty); every later claimer of
the same slot gets a fresh private DCtx with index -1.

Create (0x628c0b0, ZSTD_createDCtx): malloc(0x176f8) + field init +
CPU feature probe. Free (0x628c1e0, ZSTD_freeDCtx) is by contract.
Teardown (0x61c1d60, __cxa_atexit): free owned slot objects, delete[]
the array, delete the 16-byte table.
"""

# ---------------------------------------------------------------------------
# Constants pinned by the excerpts.
# ---------------------------------------------------------------------------

ENTRY_SIZE = 0x40
TABLE_ALLOC_OVERHEAD = 0x8
DCTX_SIZE = 0x176F8
MARKER_OWNED = -1
KIND_ZSTD = 7
FACTORY_VTABLE = 0x64D7438 + 0x10
SEED_MULTIPLIER = 0x41A7
SEED_MODULUS = 0x7FFFFFFF


def mersenne_step(seed):
    """One 0x41a7 multiply mod (2**31 - 1), exactly as the binary does it.

    v = seed * 0x41a7; folded = (v & 0x7fffffff) + (v >> 31); when the
    32-bit sum overflows into bit 31, subtract 0x7fffffff once (the
    cmovs after the add, whose flags come from the add because lea
    does not touch flags). The result is the true modulus except that
    a true 0 is represented as 0x7fffffff. Same step as open PR #3613.
    """
    v = seed * 0x41A7
    folded = (v & 0x7FFFFFFF) + (v >> 31)
    folded &= 0xFFFFFFFF
    if folded & 0x80000000:
        folded = (folded - 0x7FFFFFFF) & 0xFFFFFFFF
    return folded


def cpuid_picker(max_leaf, leaf1_ebx):
    """0x60d5cd0: cpuid leaf 0; -1 when no leaf 1 exists, else EBX>>24."""
    if max_leaf == 0:
        return -1
    return (leaf1_ebx >> 24) & 0xFF


# ---------------------------------------------------------------------------
# Table construction (0x61c1f30).
# ---------------------------------------------------------------------------

def table_params(ncpu):
    """(shift, count, alloc_bytes) for the shard table.

    ncpu <= 8: shift 3, count 8, alloc 0x208. Otherwise the smallest
    e >= 4 with (1 << e) >= ncpu; alloc = count * 64 + 8. When
    count >> 57 is nonzero the new[] size is -1 and allocation throws.
    """
    if ncpu <= 8:
        shift, count = 3, 8
    else:
        shift = 4
        while (1 << shift) < ncpu:
            shift += 1
        count = 1 << shift
    if count >> 57:
        raise OverflowError("shard count overflows the new[] size")
    return shift, count, count * ENTRY_SIZE + TABLE_ALLOC_OVERHEAD


class Entry:
    """One 64-byte shard entry; `claim` is this entry while unclaimed."""

    __slots__ = ("obj", "marker", "claim")

    def __init__(self):
        self.obj = None
        self.marker = MARKER_OWNED
        self.claim = self


class Table:
    """The shard table T: entries + shift."""

    def __init__(self, ncpu):
        self.shift, self.count, self.alloc_bytes = table_params(ncpu)
        self.entries = [Entry() for _ in range(self.count)]
        self.alive = True

    @property
    def mask(self):
        return (1 << self.shift) - 1


def build_table(ncpu):
    """0x61c1f30: allocate and initialise the shard table."""
    return Table(ncpu)


# ---------------------------------------------------------------------------
# Claim (0x61c1e10) and the per-thread seed (0x61c4080).
# ---------------------------------------------------------------------------

class SeedState:
    """Per-thread LCG seed cell; None means "not yet seeded". """

    def __init__(self, seed=None):
        self.seed = seed

    def advance(self):
        """Advance once by *0x41a7 mod 0x7fffffff and store it back."""
        self.seed = mersenne_step(self.seed)
        return self.seed


def pick_index(cpu, seed_state, shift):
    """Shard index: CPUID value masked, or the advanced seed masked."""
    mask = (1 << shift) - 1
    if cpu >= 0:
        return cpu & mask
    return seed_state.advance() & mask


def claim(table, cpu, seed_state, create):
    """0x61c1e10 GetCachedZSTDUncompressData.

    `create` is the DCtx factory (0x628c0b0). Returns (obj, index):
    the shared slot object with its index, or a fresh private object
    with index -1 when the slot was already claimed. The out pair
    starts as (None, -1), exactly as the binary initialises it.
    """
    out_obj, out_index = None, -1
    index = pick_index(cpu, seed_state, table.shift)
    entry = table.entries[index]
    if entry.claim is entry:
        # lock cmpxchg(entry+0x10, expect=entry, new=0) succeeded.
        entry.claim = None
        if entry.obj is None:
            entry.obj = create()
            entry.marker = MARKER_OWNED
        out_obj, out_index = entry.obj, index
    else:
        # Contended: the slot is already claimed. A fresh private
        # DCtx goes to the caller, never into the slot.
        if out_obj is None:
            out_obj, out_index = create(), -1
    return out_obj, out_index


# ---------------------------------------------------------------------------
# DCtx create (0x628c0b0, ZSTD_createDCtx).
# ---------------------------------------------------------------------------

def cpu_feature_flag(max_leaf, leaf7_ebx):
    """+0x75e4: 0 when max leaf <= 6; else 1 iff leaf-7 EBX has both
    bits 3 and 8 set (BMI1 + BMI2), else 0."""
    if max_leaf <= 6:
        return 0
    return 1 if (leaf7_ebx & 0x108) == 0x108 else 0


def create_dctx(max_leaf, leaf7_ebx):
    """0x628c0b0: malloc(0x176f8) plus the pinned field initialisation.

    Returns the field map (offset -> value) of the fresh context;
    every other byte is untouched malloc memory, as in the binary.
    """
    fields = {
        0x75C0: 0, 0x75D8: 0, 0x74D8: 0, 0x75FC: 0,
        0x7620: 0, 0x7628: 0, 0x7648: 0, 0x761C: 0,
        0x7668: 0, 0x7670: 0, 0x767C: 0, 0x176E8: 0,
        0x75E0: 1, 0x75B0: 0, 0x75E8: 0, 0x7608: 0,
        0x7638: 0x8000001, 0x7680: 0, 0x7598: 0,
        0x7610: 0, 0x7614: 0,
        0x75E4: cpu_feature_flag(max_leaf, leaf7_ebx),
    }
    return {"size": DCTX_SIZE, "fields": fields}


# ---------------------------------------------------------------------------
# Teardown (0x61c1d60) and the kind-7 holder factory (0x61c1ce0).
# ---------------------------------------------------------------------------

def teardown(table, free):
    """0x61c1d60: free each owned slot object (marker == -1), then
    delete[] the array and delete the 16-byte table. Returns the
    list of freed objects, in the binary's last-to-first order."""
    freed = []
    if table is None or not table.alive:
        return freed
    for entry in reversed(table.entries):
        if entry.obj is not None and entry.marker == MARKER_OWNED:
            free(entry.obj)
            freed.append(entry.obj)
    table.entries = []
    table.alive = False
    return freed


def make_holder(kind, arg_a, arg_b, create):
    """0x61c1ce0: the kind-7 holder factory. Any kind other than 7
    returns None; kind 7 builds the 0x38-byte object with a fresh
    DCtx at +0x18."""
    if kind != KIND_ZSTD:
        return None
    return {
        "size": 0x38,
        "vtable": FACTORY_VTABLE,
        "kind_byte": KIND_ZSTD,
        "field_c": arg_a,
        "field_10": arg_b,
        "dctx": create(),
        "field_20": 0,
        "field_28": 0,
    }


# ---------------------------------------------------------------------------
# Static getter (0x61c2120 + 0x61c20d0): build once, return the table.
# ---------------------------------------------------------------------------

class Cache:
    """The function-local static: built once, torn down at exit."""

    def __init__(self):
        self.table = None
        self.built = False

    def get(self, ncpu):
        if not self.built:
            self.table = build_table(ncpu)
            self.built = True
        return self.table
