"""Model of node #115's SkipListFactory slot-19 factory.

Ground: research/work-items/RE-001-skiplist-rep-factory-115/ (this
packet). All addresses are node #115 virtual addresses; the target
digest is a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.

The pinned behaviour, end to end:
  * The owner (0x5f103f0..0x5f10cf8) dispatches on the factory at
    *(r13+0x2a8): it reads the factory vtable's slot 20 and compares
    it with the GOT canonical entry (0x64ed780 -> 0x5f04d90, the
    forwarder to slot 19). Canonical -> it calls slot 19
    (0x6063640) with (factory, owner, &owner+0xa0, *(r14+0x40),
    *(r13+0x220)) and stores the SkipListRep* at owner+0xa50.
    Non-canonical -> it calls slot 20 itself with one extra
    argument (r9 = the owner's stack argument) and stores the
    result at the same +0xa50.
  * It then builds a transient 0x28-byte SkipListFactory holder on
    the stack (ctor 0x6064440, a = 0, one record
    {"SkipListFactoryOptions", 0, 0x6505c40}) and calls the same
    factory 0x6063640 directly with (holder, owner, &owner+0xa0, 0);
    the second SkipListRep* lands at owner+0xa58.
  * The holder is then destroyed in place: its vptr is reset to
    the rocksdb::Configurable vtable 0x64d3430, each heap key of the
    record vector is freed (len+1 bytes), and the vector buffer is
    freed when non-null.
  * The factory 0x6063640 (SkipListFactory vtable slot 19) builds a
    0x58-byte rocksdb::(anonymous namespace)::SkipListRep (vtable
    0x64d26e8): +0x08/+0x18 = the arena address, +0x10 =
    0x200000000004000c (u16 count 12, u16 4, u32 0x20000000),
    +0x20 = owner, +0x28 = first allocation + 0x58, +0x30 = 1,
    +0x38 = second allocation, +0x40 = owner, +0x48 = the rcx
    argument, +0x50 = the factory record's `a` (holder+0x20).
    The first allocation (0x60 bytes via the arena's slot 3) gets
    12 written at +0x58 and is then zeroed over all 12 qwords; the
    second allocation (0xe8 bytes) gets u32 0 at +0x00, self+0x18
    at +0x08 and self+0x80 at +0x10. The second size is
    0x18 + 2 * (8 + 8 * count) with count = 12.
  * The arena at owner+0xa0 is a rocksdb::ConcurrentArena (vtable
    0x64cc5d8, 0x9b0 bytes per the sized deleting dtor 0x5f10d00):
    init 0x605e010 sets +0x40 = block size (rsi/8, capped at
    0x20000 when rsi >= 0x100000), +0x50 = shard bits (3 when
    hardware_concurrency <= 8, else the smallest ecx >= 4 with
    2**ecx >= hw), a 0x40-byte-per-shard array at +0x48 with each
    shard's +0x28 byte and +0x30/+0x38 qwords zeroed, then calls
    the +0x60 sub-init 0x605dd90 and copies the +0x918/+0x930/
    +0x940 stat triple into the +0x958/+0x960/+0x968 shadow,
    clearing the +0x950 lock byte.
  * The +0x60 sub-init installs the rocksdb::Arena vtable
    0x64d1fb8 and builds two block pairs: a 0x40-byte block A whose
    +24 slot holds a 0x200-byte block B, and a second 0x40/0x200
    pair C/D; it records the aligned block size at +0x810 (of the
    sub-object, i.e. arena+0x870), the pair pointers, +0x930 =
    +0x940 = 0x800, +0x938 = the rounded size (see round_up), and
    keeps &owner+0x80 at +0x948.
  * The arena's slot-3 AllocateAligned (0x5f117a0) and slot-2
    Allocate (0x5f11c40) are merged ground (PRs #2160 and #2170);
    this model only uses their call contract: (arena, size, 0, 0)
    -> an 8-aligned fresh region of the rounded size. The slow
    path 0x605d7b0 is merged ground (PR #2150) and the destructor
    pair 0x5f10180/0x5f10d00 with the member dtor 0x605cc30 is
    merged ground (PR #2133).
  * The +0x80 header (init 0x605e810) is {ptr, 0, u16 0}; the
    huge-page align helper 0x605cfa0 returns 0x1000 outside
    (0x1000, 0x1000 + 0x7ffff000) and otherwise rounds its argument
    up to a 16-byte boundary.
"""

# --- Constants pinned from the binary -------------------------------------

NODE115_DIGEST = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)

OWNER_START = 0x5F103F0
OWNER_END = 0x5F10CF8
OWNER_PRODUCT_A = 0xA50  # first SkipListRep* (virtual slot-19 call)
OWNER_PRODUCT_B = 0xA58  # second SkipListRep* (direct call, transient holder)
OWNER_ARENA_OFF = 0xA0   # ConcurrentArena sub-object
OWNER_HEADER_OFF = 0x80  # 0x18-byte {ptr, 0, u16 0} header
OWNER_ALIGNED_OFF = 0x78  # huge_align(*(owner+0x18))

FACTORY_ADDR = 0x6063640          # SkipListFactory vtable slot 19
FACTORY_SLOT19_OFF = 0x98
FACTORY_SLOT20_OFF = 0xA0
CANONICAL_SLOT20 = 0x5F04D90      # forwarder to slot 19
CANONICAL_SLOT20_GOT = 0x64ED780
HOLDER_CTOR = 0x6064440
HOLDER_SIZE = 0x28
HOLDER_RECORD_KEY = "SkipListFactoryOptions"
HOLDER_RECORD_B = 0x6505C40  # BSS address; no file bytes, no RELATIVE record
TEARDOWN_VTABLE = 0x64D3430       # rocksdb::Configurable vtable

SKIPLIST_REP_VTABLE = 0x64D26E8
SKIPLIST_REP_TYPEINFO = "*N7rocksdb12_GLOBAL__N_111SkipListRepE"
SKIPLIST_REP_TYPEINFO_DEMANGLED = (
    "rocksdb::(anonymous namespace)::SkipListRep"
)
SKIPLIST_REP_SIZE = 0x58
SKIPLIST_REP_COUNT = 12            # u16 at product+0x10 (max height)
SKIPLIST_REP_QWORD10 = 0x200000000004000C
ALLOC1_SIZE = 0x60                 # 12 qwords, the head-node block
ALLOC2_SIZE = 0xE8                 # 0x18 + 2 * (8 + 8 * 12)
ALLOC2_HEADER = 0x18

SKIPLIST_FACTORY_VTABLE = 0x64D27B0
SKIPLIST_FACTORY_TYPEINFO = "N7rocksdb15SkipListFactoryE"

CONCURRENT_ARENA_VTABLE = 0x64CC5D8
CONCURRENT_ARENA_TYPEINFO = "N7rocksdb15ConcurrentArenaE"
CONCURRENT_ARENA_SIZE = 0x9B0      # from the sized deleting dtor 0x5f10d00
ARENA_INIT = 0x605E010
ARENA_SUBINIT = 0x605DD90
ARENA_SHARD_SIZE = 0x40
ARENA_BLOCK_CAP = 0x20000          # +0x40 when rsi >= 0x100000
ARENA_BLOCK_CAP_INPUT = 0x100000
ARENA_STAT_PRIMARY = (0x918, 0x930, 0x940)
ARENA_STAT_SHADOW = (0x958, 0x960, 0x968)
ARENA_LOCK_OFF = 0x950
ARENA_SLOT2 = 0x5F11C40            # merged PR #2170
ARENA_SLOT3 = 0x5F117A0            # merged PR #2160
ARENA_SLOW_PATH = 0x605D7B0        # merged PR #2150
ARENA_STAT_VALUE = 0x800

EMBEDDED_ARENA_VTABLE = 0x64D1FB8  # rocksdb::Arena, at arena+0x60
EMBEDDED_ARENA_TYPEINFO = "N7rocksdb5ArenaE"
EMBEDDED_BLOCK_SMALL = 0x40
EMBEDDED_BLOCK_BIG = 0x200
EMBEDDED_BLOCK_LINK_OFF = 24       # *(small+24) = big block
EMBEDDED_ALIGNED_OFF = 0x810       # of the sub-object (arena+0x870)

SMALL_INIT = 0x605E810
HUGE_ALIGN = 0x605CFA0
ARENA_STAT_GETTER = 0x5F04DA0      # slot 4: returns *(arena+0x870)

# Vtable slot tables (offsets from the vtable address; values from
# the RELATIVE records in relocations.txt).
VTABLE_SLOTS = {
    SKIPLIST_REP_VTABLE: {
        0x00: 0x6063150, 0x08: 0x6065F80, 0x10: 0x6065F60,
        0x18: 0x6065EC0, 0x20: 0x6065FA0, 0x28: 0x6066680,
        0x30: 0x6066710, 0x38: 0x6066670, 0x40: 0x6066660,
        0x48: 0x6064930, 0x50: 0x5F04D50, 0x58: 0x5F04D60,
        0x60: 0x6065040, 0x68: 0x60646D0, 0x70: 0x6066F20,
        0x78: 0x6062FB0, 0x80: 0x6062FC0, 0x88: 0x6063010,
        0x90: 0x6063070, 0x98: 0x5F04D80, 0xA0: 0x5E572D0,
        0xA8: 0x5D483F0, 0xB0: 0x5F05DB0,
    },
    SKIPLIST_FACTORY_VTABLE: {
        0x00: 0x60633A0, 0x08: 0x6063430, 0x10: 0x609D760,
        0x18: 0x609DC40, 0x20: 0x5D32560, 0x28: 0x6095E70,
        0x30: 0x6096790, 0x38: 0x5D2E090, 0x40: 0x60956F0,
        0x48: 0x609D0E0, 0x50: 0x60986B0, 0x58: 0x6095710,
        0x60: 0x609DE80, 0x68: 0x609D980, 0x70: 0x6062F70,
        0x78: 0x6063970, 0x80: 0x5D2E770, 0x88: 0x5D2CA00,
        0x90: 0x6062F80, 0x98: 0x6063640, 0xA0: 0x5F04D90,
        0xA8: 0x6062F90, 0xB0: 0x6062FA0,
    },
    CONCURRENT_ARENA_VTABLE: {
        0x00: 0x5F10180, 0x08: 0x5F10D00, 0x10: 0x5F11C40,
        0x18: 0x5F117A0, 0x20: 0x5F04DA0,
    },
    EMBEDDED_ARENA_VTABLE: {
        0x00: 0x605CC30, 0x08: 0x605CF80, 0x10: 0x605D930,
        0x18: 0x605D7B0, 0x20: 0x605CC20,
    },
    TEARDOWN_VTABLE: {
        0x00: 0x60957A0, 0x08: 0x6095830, 0x10: 0x6099030,
        0x18: 0x60996A0, 0x20: 0x5D32560, 0x28: 0x6095E70,
        0x30: 0x6096790, 0x38: 0x60958C0, 0x40: 0x60956F0,
        0x48: 0x609D0E0, 0x50: 0x60986B0, 0x58: 0x6095710,
        0x60: 0x60985E0, 0x68: 0x6095A60,
    },
}

# Typeinfo pointers (vtable-0x08 -> typeinfo object) and typeinfo
# name pointers (typeinfo+0x08 -> name string), from relocations.txt.
TYPEINFO_POINTERS = {
    SKIPLIST_REP_VTABLE: 0x64D25F0,
    SKIPLIST_FACTORY_VTABLE: 0x64D25A8,
    CONCURRENT_ARENA_VTABLE: 0x64CC550,
    EMBEDDED_ARENA_VTABLE: 0x64D1F90,
    TEARDOWN_VTABLE: 0x64D3410,
}
TYPEINFO_NAME_POINTERS = {
    0x64D25F0: 0x975200,  # *N7rocksdb12_GLOBAL__N_111SkipListRepE
    0x64D25A8: 0x975160,  # N7rocksdb15SkipListFactoryE
    0x64CC550: 0x970910,  # N7rocksdb15ConcurrentArenaE
    0x64D1F90: 0x974E90,  # N7rocksdb5ArenaE
    0x64D3410: 0x977320,  # N7rocksdb12ConfigurableE
    0x64CC540: 0x9708F0,  # N7rocksdb9AllocatorE (base of both arenas)
    0x64CC530: 0x9708D0,  # N7rocksdb11MemTableRepE (base of SkipListRep)
    0x64D1FF0: 0x974EF0,  # N7rocksdb18MemTableRepFactoryE
}
TYPEINFO_BASE_POINTERS = {
    0x64D25F0: 0x64CC530,  # SkipListRep : MemTableRep
    0x64D25A8: 0x64D1FF0,  # SkipListFactory : MemTableRepFactory
    0x64CC550: 0x64CC540,  # ConcurrentArena : Allocator
    0x64D1F90: 0x64CC540,  # Arena : Allocator
}


# --- Simulated memory -------------------------------------------------------

class Memory:
    """A flat byte-addressable stand-in for the target's memory."""

    def __init__(self):
        self._bytes = {}
        self._next = 0x100000000

    def alloc(self, size, addr=None):
        if addr is None:
            addr = self._next
            self._next += max(size, 0x1000)
        for i in range(size):
            self._bytes.setdefault(addr + i, 0)
        return addr

    def write_qword(self, addr, value):
        for i in range(8):
            self._bytes[addr + i] = (value >> (8 * i)) & 0xFF

    def write_u16(self, addr, value):
        self._bytes[addr] = value & 0xFF
        self._bytes[addr + 1] = (value >> 8) & 0xFF

    def write_u32(self, addr, value):
        for i in range(4):
            self._bytes[addr + i] = (value >> (8 * i)) & 0xFF

    def write_byte(self, addr, value):
        self._bytes[addr] = value & 0xFF

    def read_qword(self, addr):
        return sum(self._bytes.get(addr + i, 0) << (8 * i) for i in range(8))

    def read_u16(self, addr):
        return self._bytes.get(addr, 0) | (self._bytes.get(addr + 1, 0) << 8)

    def read_u32(self, addr):
        return sum(self._bytes.get(addr + i, 0) << (8 * i) for i in range(4))

    def read_byte(self, addr):
        return self._bytes.get(addr, 0)


class ArenaAllocator:
    """Test double for the arena's slot-3 AllocateAligned contract
    (merged PR #2160): (arena, size, 0, 0) returns an 8-aligned
    fresh region of the size rounded up to a multiple of 8. The
    double records every call so tests can check the two sizes
    the factory requests (0x60 then 0xe8)."""

    def __init__(self, mem):
        self.mem = mem
        self.calls = []

    def allocate_aligned(self, arena, size):
        rounded = (size + 7) & ~7
        addr = self.mem.alloc(rounded)
        self.calls.append((arena, size, rounded, addr))
        return addr


# --- Pinned functions -------------------------------------------------------

def huge_align(value):
    """0x605cfa0: 0x1000 when value <= 0x1000 or value >=
    0x1000 + 0x7ffff000, else value rounded up to a 16-byte
    boundary (unchanged when already 16-aligned)."""
    if value <= 0x1000 or value >= 0x1000 + 0x7FFFF000:
        return 0x1000
    if value % 16 == 0:
        return value
    return (value & ~0xF) + 0x10


def shard_bits(hardware_concurrency):
    """0x605e010: 3 when hw <= 8, else the smallest ecx >= 4 with
    2**ecx >= hw."""
    if hardware_concurrency <= 8:
        return 3
    bits = 4
    while (1 << bits) < hardware_concurrency:
        bits += 1
    return bits


def arena_block_size(rsi):
    """0x605e010: rsi/8, capped at 0x20000 when rsi >= 0x100000."""
    if rsi >= ARENA_BLOCK_CAP_INPUT:
        return ARENA_BLOCK_CAP
    return rsi // 8


def arena_init(mem, arena, rsi, rdx, rcx, hardware_concurrency):
    """0x605e010: install the ConcurrentArena vtable, size the
    block/shard state, zero the shard array, run the +0x60
    sub-init and copy the stat triple into its shadow. Returns
    the (arena, shard_count, shard_array) triple. The +0x60
    sub-init is modelled by arena_subinit below; rdx/rcx are
    passed through to it."""
    mem.write_qword(arena, CONCURRENT_ARENA_VTABLE)
    block_size = arena_block_size(rsi)
    mem.write_qword(arena + 0x40, block_size)
    mem.write_qword(arena + 0x48, 0)
    bits = shard_bits(hardware_concurrency)
    mem.write_u32(arena + 0x50, bits)
    count = 1 << bits
    array = mem.alloc(ARENA_SHARD_SIZE * count)
    for i in range(count):
        shard = array + i * ARENA_SHARD_SIZE
        mem.write_byte(shard + 0x28, 0)
        mem.write_qword(shard + 0x30, 0)
        mem.write_qword(shard + 0x38, 0)
    mem.write_qword(arena + 0x48, array)
    arena_subinit(mem, arena + 0x60, rsi, rdx, rcx)
    for src, dst in zip(ARENA_STAT_PRIMARY, ARENA_STAT_SHADOW):
        mem.write_qword(arena + dst, mem.read_qword(arena + src))
    mem.write_byte(arena + ARENA_LOCK_OFF, 0)
    return arena, count, array


def round_up_to(value, unit):
    """The +0x938 rounding in 0x605dd90: ((value - 1) // unit + 1)
    * unit, applied only when 0 < unit < value."""
    return ((value - 1) // unit + 1) * unit


def arena_subinit(mem, sub, rsi, rdx, rcx):
    """0x605dd90: install the embedded Arena vtable at +0x60 and
    build the two block pairs plus the stat fields. `sub` is
    arena+0x60; rsi is the block-size input, rdx is &owner+0x80
    (kept at +0x948 of the arena), rcx is the rounding unit for
    +0x938. Returns the sub-object address."""
    mem.write_qword(sub, EMBEDDED_ARENA_VTABLE)
    aligned = huge_align(rsi)
    mem.write_qword(sub + EMBEDDED_ALIGNED_OFF, aligned)
    # Block pair A: 0x40-byte block, its +24 slot holds a 0x200 block.
    block_a = mem.alloc(EMBEDDED_BLOCK_SMALL)
    block_b = mem.alloc(EMBEDDED_BLOCK_BIG)
    mem.write_qword(block_a + EMBEDDED_BLOCK_LINK_OFF, block_b)
    mem.write_qword(sub + 0x818, block_a)
    mem.write_qword(sub + 0x820, 8)
    mem.write_qword(sub + 0x828, block_b)
    mem.write_qword(sub + 0x830, block_b)
    mem.write_qword(sub + 0x838, block_a + 24)
    mem.write_qword(sub + 0x840, block_b + 0x200)
    mem.write_qword(sub + 0x848, block_b)
    mem.write_qword(sub + 0x850, block_b)
    mem.write_qword(sub + 0x858, block_a + 24)
    mem.write_qword(sub + 0x860, block_b + 0x200)
    # Block pair B: same shape, second pair.
    block_c = mem.alloc(EMBEDDED_BLOCK_SMALL)
    block_d = mem.alloc(EMBEDDED_BLOCK_BIG)
    mem.write_qword(block_c + EMBEDDED_BLOCK_LINK_OFF, block_d)
    mem.write_qword(sub + 0x868, block_c)
    mem.write_qword(sub + 0x870, 8)
    mem.write_qword(sub + 0x878, block_d)
    mem.write_qword(sub + 0x880, block_d)
    mem.write_qword(sub + 0x888, block_c + 24)
    mem.write_qword(sub + 0x890, block_d + 0x200)
    mem.write_qword(sub + 0x898, block_d)
    mem.write_qword(sub + 0x8A0, block_d)
    mem.write_qword(sub + 0x8A8, block_c + 24)
    mem.write_qword(sub + 0x8B0, block_d + 0x200)
    mem.write_qword(sub + 0x8B8, 0)
    mem.write_qword(sub + 0x8C0, sub + EMBEDDED_ALIGNED_OFF)
    mem.write_qword(sub + 0x8C8, sub + 0x10)
    mem.write_qword(sub + 0x8D0, ARENA_STAT_VALUE)
    if 0 < rcx < aligned:
        rounded = round_up_to(aligned, rcx)
    else:
        rounded = rcx
    mem.write_qword(sub + 0x8D8, rounded)
    mem.write_qword(sub + 0x8E0, ARENA_STAT_VALUE)
    mem.write_qword(sub + 0x8E8, rdx)
    return sub


def small_init(mem, addr, ptr):
    """0x605e810: the 0x18-byte header {ptr, 0, u16 0}."""
    mem.write_qword(addr, ptr)
    mem.write_qword(addr + 0x08, 0)
    mem.write_u16(addr + 0x10, 0)
    return addr


def arena_stat(mem, arena):
    """0x5f04da0 (ConcurrentArena slot 4): *(arena+0x870)."""
    return mem.read_qword(arena + 0x870)


def build_holder(mem, holder, a):
    """0x6064440 (re-shipped from PR #3272): install the
    SkipListFactory vtable, zero the record vector triple, store
    `a` at +0x20 and register the single record
    {"SkipListFactoryOptions", a, 0x6505c40}. The record key is a
    22-char heap string; the vector triple holds one record, so
    begin/end/cap are (rec, rec + 0x30, rec + 0x30)."""
    mem.write_qword(holder, SKIPLIST_FACTORY_VTABLE)
    mem.write_qword(holder + 0x20, a)
    rec = mem.alloc(0x30)
    mem.write_qword(holder + 0x08, rec)
    mem.write_qword(holder + 0x10, rec + 0x30)
    mem.write_qword(holder + 0x18, rec + 0x30)
    return rec


def destroy_holder(mem, holder):
    """The owner-window teardown: reset the holder vptr to the
    Configurable vtable, free the heap key (len+1 bytes) and free
    the record-vector buffer when non-null. Returns the list of
    (address, size) frees, in order."""
    frees = []
    mem.write_qword(holder, TEARDOWN_VTABLE)
    begin = mem.read_qword(holder + 0x08)
    end = mem.read_qword(holder + 0x10)
    cap = mem.read_qword(holder + 0x18)
    rec = begin
    while rec != end:
        # A 22-char key is heap-allocated (SSO holds at most 15).
        frees.append((rec, len(HOLDER_RECORD_KEY) + 1))
        rec += 0x30
    if begin != 0:
        frees.append((begin, cap - begin))
    return frees


def skiplist_rep_factory(mem, factory, owner, arena_addr, rcx_arg,
                         allocator):
    """0x6063640 (SkipListFactory vtable slot 19): build the
    0x58-byte SkipListRep product and return its address. The
    factory's record `a` (factory+0x20) lands at product+0x50.
    Allocations go through the arena's slot 3 (AllocateAligned);
    the caller supplies an allocator honouring that contract."""
    product = mem.alloc(SKIPLIST_REP_SIZE)
    count = SKIPLIST_REP_COUNT
    mem.write_qword(product, SKIPLIST_REP_VTABLE)
    mem.write_qword(product + 0x08, arena_addr)
    mem.write_qword(product + 0x10, SKIPLIST_REP_QWORD10)
    mem.write_qword(product + 0x18, arena_addr)
    mem.write_qword(product + 0x20, owner)
    alloc1 = allocator.allocate_aligned(arena_addr, ALLOC1_SIZE)
    # *(alloc1+0x58) = 12, then all 12 qwords zeroed.
    mem.write_u32(alloc1 + 0x58, count)
    for i in range(count):
        mem.write_qword(alloc1 + i * 8, 0)
    mem.write_qword(product + 0x28, alloc1 + 0x58)
    mem.write_u32(product + 0x30, 1)
    size2 = ALLOC2_HEADER + 2 * (8 + 8 * count)
    alloc2 = allocator.allocate_aligned(arena_addr, size2)
    mem.write_u32(alloc2, 0)
    mem.write_qword(alloc2 + 0x08, alloc2 + 0x18)
    mem.write_qword(alloc2 + 0x10, alloc2 + 0x18 + (8 + 8 * count))
    mem.write_qword(product + 0x38, alloc2)
    mem.write_qword(product + 0x40, owner)
    mem.write_qword(product + 0x48, rcx_arg)
    mem.write_qword(product + 0x50, mem.read_qword(factory + 0x20))
    return product


def owner_dispatch(factory_slot20, factory):
    """The owner-window guard (0x5f104e2..0x5f104fc): canonical
    slot 20 (0x5f04d90) -> call slot 19 directly; anything else
    -> call slot 20 itself with the extra r9 argument. Returns
    "slot19" or "slot20"."""
    if factory_slot20 == CANONICAL_SLOT20:
        return "slot19"
    return "slot20"


def owner_build_products(mem, factory, owner, arena_addr, rcx_virtual,
                         r8_virtual, allocator):
    """The owner window end to end (0x5f104cd..0x5f105a0): the
    virtual slot-19 call stores its product at owner+0xa50, the
    transient holder (a = 0) is built and the direct call stores
    its product at owner+0xa58, then the holder is destroyed.
    `factory` is the real factory object (its slot 20 is assumed
    canonical here; see owner_dispatch). Returns
    (product_a, product_b, frees)."""
    product_a = skiplist_rep_factory(mem, factory, owner, arena_addr,
                                     rcx_virtual, allocator)
    mem.write_qword(owner + OWNER_PRODUCT_A, product_a)
    holder = mem.alloc(HOLDER_SIZE)
    build_holder(mem, holder, 0)
    product_b = skiplist_rep_factory(mem, holder, owner, arena_addr,
                                     0, allocator)
    mem.write_qword(owner + OWNER_PRODUCT_B, product_b)
    frees = destroy_holder(mem, holder)
    return product_a, product_b, frees
