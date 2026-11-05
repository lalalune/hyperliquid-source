"""Model of node #115's owner 0x5f103f0 tail phases.

Ground: research/work-items/RE-001-owner-tail-phases-115/ (this
packet). All addresses are node #115 virtual addresses; the target
digest is a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.

The pinned behaviour, end to end (the owner is the 0xd20-byte
object built by the two callers; #3286 pinned its dispatch and
product windows, this packet pins everything after 0x5f105a0):
  * Prologue helper 0x5f07230 (called once, 0x5f10461) copies
    option fields into the owner+0x18 sub-object: owner+0x18 =
    *(arg4+0x10), owner+0x20 = 8 * (int)((double)*(arg4) *
    *(double*)(arg4+0x18)), owner+0x28 = *(arg4+0x28), owner+0x30
    = u16 {low *(arg4+0x20), high *(options+0x298)}, owner+0x38
    = *(arg4+0x38), owner+0x40 = *(options+0x2a0), owner+0x48 =
    *(arg4+0x30), owner+0x50 = *(options+0x218), owner+0x58 =
    *(options+0x260), owner+0x60 = *(options+0x220), owner+0x68
    = byte *(options+0x1c8), owner+0x6c = *(arg4+0x1bc). The
    +0x31 byte and the +0x38 qword this establishes are the
    element-array gate and count below.
  * Phase A (0x5f105a0..0x5f10766) zero-initialises owner+0xa60..
    0xc38 with self-pointer fields (+0xaa0 = &+0xab0, +0xac0 =
    &+0xad0, +0xb48 = +0xb50 = &+0xb38, +0xbd0 = &+0xbe0, +0xbf8
    = &+0xc08), +0xa60 = 1, +0xa80 = *(arg4), +0xc20 = +0xc28 =
    arg9 (the owner's stack argument).
  * Phase B (0x5f1076c..0x5f10838) builds the 0xc40 element
    array: when *(owner+0x31) == 0 the triple is null
    (+0xc40 = +0xc48 = +0xc50 = 0); otherwise count =
    *(owner+0x38), and count > 0x249249249249249 throws
    length_error ("cannot create std::vector larger than
    max_size()") -- the constant is exactly the largest count
    whose 56*count stays below 2**63 (56 * 0x249249249249249 =
    0x7ffffffffffffff8). Otherwise 56*count bytes are allocated
    and each 0x38-byte element is constructed by 0x60d5880; the
    triple is (+0xc40 = begin, +0xc48 = end, +0xc50 = end) and
    count == 0 leaves it null with end 0.
  * The element ctor 0x60d5880 initialises a pthread_rwlock at
    element+0x00 (pthread_rwlock_init(element, NULL)); return
    codes 0, 0x10 and 0x6e are accepted, anything else prints
    "pthread init mutex: <strerror>" to stderr via
    __fprintf_chk and aborts.
  * Phase C (0x5f10838..0x5f1091d) initialises owner+0xc48..
    0xd08: +0xc48 = the array end (or 0), +0xc58 = *(arg4+0x40),
    +0xc60 = 0, +0xc68 = 0 (the once-flag, u32), +0xc70 =
    {*(options+0x210), *(options+0x300)}, +0xc80 = &+0xcb0,
    +0xc88 = 1, +0xc90 = +0xc98 = 0, +0xca0 = 0x3f800000 (1.0f),
    +0xca8 = +0xcb0 = 0, +0xcb8 = ffffffffffffffff00000000
    0000000000, +0xcc8 = ffffffffffffff000000000000000000,
    +0xcd8 = +0xce8 = +0xcf8 = 0, +0xd08 = 0; then it calls the
    +0xd10 table init 0x5f0b420 (merged ground, shared-table-
    resize) and the once-flag helper 0x5f07490.
  * The +0xd10 table (built by 0x5f0b420, merged ground) holds
    shared_ptr<FragmentedRangeTombstoneListCache> entries, 0x10
    bytes each, N = 1 << *(owner+0xd18) entries with the count N
    in the 8-byte header at table-8 and the log k = *(owner+0xd18)
    (RE-001-shared-table-resize-115, which left the table's owner
    field untraced; this packet pins it: rdi = &owner+0xd10).
  * The once-flag helper 0x5f07490 (owner+0xc68): returns at once
    when the flag is already nonzero; otherwise it runs the once
    predicate 0x5f07300 and, only when the predicate returns true,
    latches the flag to 1 with a lock cmpxchg.
  * The once predicate 0x5f07300: it calls SkipListRep slot 15
    (0x6062fb0, `endbr64; xor %eax,%eax; ret`) on both products
    (+0xa50, +0xa58) and stores the sum plus *(owner+0xa00) at
    +0xcd0 -- both calls return 0, so +0xcd0 = *(owner+0xa00).
    With H = *(owner+0x78), A = *(owner+0xa80), total = the
    +0xcd0 value and scaled = 0.6 * (double)H + (double)A (the
    0.6 constant at 0x4591d0; negative inputs go through the
    unsigned halving fixups): it returns false when scaled >
    (double)(H + total), true when (double)total > scaled, and
    otherwise sums *(base + i*64 + 0x38) over i in
    0..(1 << *(owner+0xf0)) - 1 with base = *(owner+0xe8) and
    returns (*(owner+0x9f8) + sum) < (H >> 2). The fields +0xe8,
    +0xf0, +0x9f8 and +0xa00 are read but never written by the
    owner function; their writers are outside this packet.
  * The small-install gate: the +0xc60 descriptor is rebuilt
    exactly when (+0x20 != 0) and (+0xc58 != 0 or +0x30 != 0).
    The rebuild allocates a fresh 0x10-byte block, fills it with
    0x61c26f0, installs it at +0xc60 and frees the old block with
    _ZdlPvm(old, 0x10) when non-null. The descriptor builder
    0x61c26f0(block, arena, owner+0x20, 6, owner+0x28,
    options+0x220) sets *(block+4) = 3, *(block+0) =
    4*ceil(owner+0x20 / 256), and *(block+8) = the 32-aligned
    start of a zeroed arena allocation of
    32*ceil(owner+0x20 / 256) + 31 bytes (via the arena's slot 3,
    AllocateAligned, merged PR #2160).
  * The main install loop always runs afterwards: it allocates a
    0x48-byte _Sp_counted_ptr_inplace<FragmentedRangeTombstone-
    ListCache> control (vtable 0x64cc718, counts 0x100000001,
    the 0x38-byte cache object at +0x10 zero-filled, no
    constructor runs), then for each of the N table entries it
    allocates a 0x20-byte _Sp_counted_ptr_inplace<const
    shared_ptr<Cache>> control (vtable 0x64cc750, counts
    0x100000001, +0x10 = &big+0x10, +0x18 = big), bumps the big
    control's use count by 1 and the small control's use count
    to 2, installs {&big+0x10, small} at the entry under a
    _Sp_locker guard, releases the old entry control (use--,
    dispose+destroy when its counts were exactly {1,1}, else
    the destroy dispatch 0x5d35070 when the decremented use
    reaches 0... see release()), and releases the small
    control's temporary second reference (use 2 -> 1).
  * The epilogue releases the big control once via the tail
    jump to the release helper 0x5d350c0, leaving its use count
    at N (one per table entry).
  * The two callers allocate the 0xd20-byte owner and call the
    owner with (new, base+0x40, base+0x368, arg2, *(base+0x8e0),
    arg3, *(base)): the small caller 0x5d8ca00 returns the new
    owner; the big caller 0x5ed01f0 stores it at -0x1068(%rbp)
    and continues. The big caller also calls the once predicate
    directly at 0x5ed1bbd.
  * Control vtables (5 slots: 0 = trivial complete dtor, 1 =
    deleting dtor, 2 = _M_dispose, 3 = _M_destroy, 4 =
    _M_get_deleter): the big _M_destroy frees 0x48 bytes, the
    small _M_destroy frees 0x20 bytes; the big _M_dispose
    (0x5f061b0) tears down the cache object (its internals are
    out of scope here); the small _M_dispose (0x5f0a290)
    releases the big control it holds. Both typeinfos derive
    from std::_Sp_counted_base<(_Lock_policy)2>.
"""

class LengthError(Exception):
    """The __throw_length_error the binary raises when the
    element count exceeds ELEM_MAX_COUNT."""


# --- Constants pinned from the binary -------------------------------------

import struct

NODE115_DIGEST = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)

OWNER_START = 0x5F103F0
OWNER_END = 0x5F10CF8
OWNER_SIZE = 0xD20
OWNER_PRODUCT_A = 0xA50
OWNER_PRODUCT_B = 0xA58
OWNER_ARENA_OFF = 0xA0
OWNER_HEADER_OFF = 0x80
OWNER_ALIGNED_OFF = 0x78

PROLOGUE_HELPER = 0x5F07230
ELEM_CTOR = 0x60D5880
ELEM_SIZE = 0x38
ELEM_RWLOCK_OK = (0, 0x10, 0x6E)
ELEM_MAX_COUNT = 0x249249249249249
ELEM_MAX_BYTES = 0x7FFFFFFFFFFFFFF8  # 56 * ELEM_MAX_COUNT
ELEM_GUARD_BYTE_OFF = 0x31
ELEM_COUNT_OFF = 0x38
ARRAY_BEGIN_OFF = 0xC40
ARRAY_END_OFF = 0xC48
ARRAY_CAP_OFF = 0xC50

ONCE_HELPER = 0x5F07490
ONCE_PRED = 0x5F07300
ONCE_FLAG_OFF = 0xC68
PRED_SCALE = 0.6
PRED_SCALE_ADDR = 0x4591D0
SLOT15 = 0x6062FB0
SLOT15_OFF = 0x78

SMALL_INSTALL = 0x61C26F0
SMALL_INSTALL_ARG = 6
SMALL_BLOCK_SIZE = 0x10
SMALL_FIELD_OFF = 0xC60

TABLE_INIT = 0x5F0B420            # merged RE-001-shared-table-resize-115
TABLE_PTR_OFF = 0xD10
TABLE_LOG_OFF = 0xD18
TABLE_ENTRY_SIZE = 0x10

BIG_CONTROL_SIZE = 0x48
SMALL_CONTROL_SIZE = 0x20
BIG_CONTROL_VTABLE = 0x64CC718
SMALL_CONTROL_VTABLE = 0x64CC750
CONTROL_COUNTS = 0x100000001      # {use=1, weak=1} from .rodata 0x459b20
CACHE_OBJECT_SIZE = 0x38           # at big control +0x10
BIG_TYPEINFO = 0x64CC598
SMALL_TYPEINFO = 0x64CC5B0
CONTROL_BASE_TYPEINFO = 0x64C81A8
BIG_TYPEINFO_NAME = (
    "St23_Sp_counted_ptr_inplaceIN7rocksdb33FragmentedRangeTombstone"
    "ListCacheESaIvELN9__gnu_cxx12_Lock_policyE2EE"
)
SMALL_TYPEINFO_NAME = (
    "St23_Sp_counted_ptr_inplaceIKSt10shared_ptrIN7rocksdb33"
    "FragmentedRangeTombstoneListCacheEESaIvELN9__gnu_cxx12_Lock_policyE2EE"
)
BASE_TYPEINFO_NAME = (
    "St16_Sp_counted_baseILN9__gnu_cxx12_Lock_policyE2EE"
)

SKIPLIST_REP_VTABLE = 0x64D26E8
SKIPLIST_REP_TYPEINFO = 0x64D25F0  # SkipListRep typeinfo object
SKIPLIST_REP_TYPEINFO_NAME = "N7rocksdb12_GLOBAL__N_111SkipListRepE"
# (stored with a leading "*" at 0x975200; demangles to
# rocksdb::(anonymous namespace)::SkipListRep)
MEMTABLE_REP_TYPEINFO = 0x64CC530  # SkipListRep's base typeinfo
MEMTABLE_REP_TYPEINFO_NAME = "N7rocksdb11MemTableRepE"

RELEASE_HELPER = 0x5D350C0        # cited (#3263, shared-table-resize)
DESTROY_DISPATCH = 0x5D35070      # cited (#3263, shared-table-resize)
RELEASE_LOOP_HELPER = 0x5F0A1DC   # cited (shared-table-resize)

CALLER_SMALL = 0x5D8CA00
CALLER_BIG = 0x5ED01F0
CALLER_BIG_WINDOW = (0x5ED086C, 0x5ED08C6)

# The two 16-byte constants phase C stores at +0xcb8/+0xcc8.
TAIL_CONST_CB8 = bytes.fromhex("ffffffffffffffff0000000000000000")
TAIL_CONST_CC8 = bytes.fromhex("ffffffffffffff000000000000000000")
LENGTH_ERROR_ADDR = 0x96B400
LENGTH_ERROR_TEXT = "cannot create std::vector larger than max_size()"
FPRINTF_FORMAT = "pthread %s: %s\n"
FPRINTF_ARG = "init mutex"

# Vtable slot tables (offsets from the vtable address; values from
# the RELATIVE records in relocations.txt).
VTABLE_SLOTS = {
    BIG_CONTROL_VTABLE: {
        0x00: 0x5F04E30, 0x08: 0x5F04E50, 0x10: 0x5F061B0,
        0x18: 0x5F04F70, 0x20: 0x5F057C0,
    },
    SMALL_CONTROL_VTABLE: {
        0x00: 0x5F04E20, 0x08: 0x5F04E60, 0x10: 0x5F0A290,
        0x18: 0x5F04F60, 0x20: 0x5F05380,
    },
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
}

# Typeinfo pointers (vtable-0x08 -> typeinfo object), typeinfo
# name pointers (typeinfo+0x08 -> name string) and base pointers
# (typeinfo+0x10 -> base typeinfo), from relocations.txt.
TYPEINFO_POINTERS = {
    BIG_CONTROL_VTABLE: BIG_TYPEINFO,
    SMALL_CONTROL_VTABLE: SMALL_TYPEINFO,
    SKIPLIST_REP_VTABLE: SKIPLIST_REP_TYPEINFO,
}
TYPEINFO_NAME_POINTERS = {
    BIG_TYPEINFO: 0x9709A0,
    SMALL_TYPEINFO: 0x970A20,
    SKIPLIST_REP_TYPEINFO: 0x975200,
    MEMTABLE_REP_TYPEINFO: 0x9708D0,
    CONTROL_BASE_TYPEINFO: 0x96C540,
}
TYPEINFO_BASE_POINTERS = {
    BIG_TYPEINFO: CONTROL_BASE_TYPEINFO,
    SMALL_TYPEINFO: CONTROL_BASE_TYPEINFO,
    SKIPLIST_REP_TYPEINFO: MEMTABLE_REP_TYPEINFO,
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

    def write_bytes(self, addr, blob):
        for i, byte in enumerate(blob):
            self._bytes[addr + i] = byte

    def read_qword(self, addr):
        return sum(self._bytes.get(addr + i, 0) << (8 * i) for i in range(8))

    def read_u16(self, addr):
        return self._bytes.get(addr, 0) | (self._bytes.get(addr + 1, 0) << 8)

    def read_u32(self, addr):
        return sum(self._bytes.get(addr + i, 0) << (8 * i) for i in range(4))

    def read_byte(self, addr):
        return self._bytes.get(addr, 0)

    def read_bytes(self, addr, size):
        return bytes(self._bytes.get(addr + i, 0) for i in range(size))


class Control:
    """A test double for one _Sp_counted_ptr_inplace control block:
    vtable, use/weak counts, and the inline object. `dispose`
    records the _M_dispose call; `destroy` records _M_destroy."""

    def __init__(self, mem, addr, vtable, size, inline_size):
        self.mem = mem
        self.addr = addr
        self.vtable = vtable
        self.size = size
        self.disposed = False
        self.destroyed = False
        mem.write_qword(addr, vtable)
        mem.write_qword(addr + 0x08, CONTROL_COUNTS)
        for i in range(0x10, size):
            mem.write_byte(addr + i, 0)

    @property
    def use(self):
        return self.mem.read_u32(self.addr + 0x08)

    @property
    def weak(self):
        return self.mem.read_u32(self.addr + 0x0C)

    def bump_use(self):
        self.mem.write_u32(self.addr + 0x08, self.use + 1)

    def release(self):
        """The shared release: counts exactly {1,1} take the
        inline dispose+destroy path; otherwise the use count is
        decremented and a drop to 0 use calls the destroy
        dispatch. Returns "disposed", "dispatch" or "kept"."""
        counts = self.mem.read_qword(self.addr + 0x08)
        if counts == CONTROL_COUNTS:
            self.mem.write_qword(self.addr + 0x08, 0)
            self.dispose()
            self.destroy()
            return "disposed"
        old_use = self.use
        self.mem.write_u32(self.addr + 0x08, (old_use - 1) & 0xFFFFFFFF)
        if old_use == 1:
            return "dispatch"
        return "kept"

    def dispose(self):
        self.disposed = True

    def destroy(self):
        self.destroyed = True


def _double_from_u64(value):
    """cvtsi2sd of an unsigned 64-bit value (the predicate's
    unsigned fixups halve, convert and double; float() of the
    unsigned value rounds the same way)."""
    return float(value & 0xFFFFFFFFFFFFFFFF)


def _double_from_i64(value):
    """cvtsi2sd of a signed 64-bit value, via the unsigned
    fixup the binary uses when the input is negative."""
    signed = value - (1 << 64) if value >= (1 << 63) else value
    if signed >= 0:
        return float(signed)
    return _double_from_u64(value)


# --- Pinned functions -------------------------------------------------------

def prologue_helper(mem, dest, options, arg4):
    """0x5f07230: copy option fields into the owner+0x18
    sub-object at `dest` (owner+0x18). `options` and `arg4` are
    dicts of the fields the helper reads, keyed by offset.
    Returns the list of (offset, value) writes, relative to dest."""
    writes = []
    mem.write_qword(dest + 0x00, arg4[0x10])
    writes.append((0x00, arg4[0x10]))
    factor = struct.unpack("<d", struct.pack("<Q", arg4[0x18]))[0]
    product = _double_from_i64(arg4[0x00]) * factor
    scaled = int(product)  # cvttsd2si truncates toward zero
    value20 = (scaled << 3) & 0xFFFFFFFF
    mem.write_u32(dest + 0x08, value20)
    writes.append((0x08, value20))
    mem.write_qword(dest + 0x10, arg4[0x28])
    writes.append((0x10, arg4[0x28]))
    low = arg4[0x20] & 0xFF
    high = options[0x298] & 0xFF
    mem.write_u16(dest + 0x18, low | (high << 8))
    writes.append((0x18, low | (high << 8)))
    mem.write_qword(dest + 0x20, arg4[0x38])
    writes.append((0x20, arg4[0x38]))
    mem.write_qword(dest + 0x28, options[0x2A0])
    writes.append((0x28, options[0x2A0]))
    mem.write_qword(dest + 0x30, arg4[0x30])
    writes.append((0x30, arg4[0x30]))
    mem.write_qword(dest + 0x38, options[0x218])
    mem.write_qword(dest + 0x40, options[0x260])
    writes.append((0x38, options[0x218]))
    writes.append((0x40, options[0x260]))
    mem.write_qword(dest + 0x48, options[0x220])
    writes.append((0x48, options[0x220]))
    mem.write_byte(dest + 0x50, options[0x1C8] & 0xFF)
    writes.append((0x50, options[0x1C8] & 0xFF))
    mem.write_u32(dest + 0x54, arg4[0x1BC])
    writes.append((0x54, arg4[0x1BC]))
    return writes


def region_init(mem, owner, arg4_first, arg9):
    """Phase A (0x5f105a0..0x5f10766): zero owner+0xa60..0xc38
    with the self-pointer fields, +0xa60 = 1, +0xa80 =
    *(arg4), +0xc20 = +0xc28 = arg9."""
    mem.write_byte(owner + 0xA60, 1)
    for off in range(0xA68, 0xA80):
        mem.write_byte(owner + off, 0)
    mem.write_qword(owner + 0xA80, arg4_first)
    for off in range(0xA88, 0xAA0):
        mem.write_byte(owner + off, 0)
    mem.write_qword(owner + 0xAA0, owner + 0xAB0)
    mem.write_qword(owner + 0xAA8, 0)
    mem.write_byte(owner + 0xAB0, 0)
    for off in range(0xAB1, 0xAC0):
        mem.write_byte(owner + off, 0)
    mem.write_qword(owner + 0xAC0, owner + 0xAD0)
    mem.write_qword(owner + 0xAC8, 0)
    mem.write_byte(owner + 0xAD0, 0)
    for off in range(0xAD1, 0xB38):
        mem.write_byte(owner + off, 0)
    mem.write_u32(owner + 0xB38, 0)
    mem.write_qword(owner + 0xB40, 0)
    mem.write_qword(owner + 0xB48, owner + 0xB38)
    mem.write_qword(owner + 0xB50, owner + 0xB38)
    for off in range(0xB58, 0xBC0):
        mem.write_byte(owner + off, 0)
    mem.write_qword(owner + 0xBC0, 0)
    mem.write_u32(owner + 0xBC8, 0)
    mem.write_u16(owner + 0xBCC, 0)
    mem.write_qword(owner + 0xBD0, owner + 0xBE0)
    mem.write_qword(owner + 0xBD8, 0)
    mem.write_byte(owner + 0xBE0, 0)
    for off in range(0xBE1, 0xBF0):
        mem.write_byte(owner + off, 0)
    mem.write_byte(owner + 0xBF0, 0)
    mem.write_u32(owner + 0xBF4, 0)
    mem.write_qword(owner + 0xBF8, owner + 0xC08)
    mem.write_qword(owner + 0xC00, 0)
    mem.write_byte(owner + 0xC08, 0)
    for off in range(0xC09, 0xC18):
        mem.write_byte(owner + off, 0)
    mem.write_qword(owner + 0xC18, 0)
    mem.write_qword(owner + 0xC20, arg9)
    mem.write_qword(owner + 0xC28, arg9)
    mem.write_qword(owner + 0xC30, 0)
    mem.write_qword(owner + 0xC38, 0)
    return owner


def elem_ctor_ok(rc):
    """0x60d5880: pthread_rwlock_init return codes 0, 0x10 and
    0x6e are accepted; anything else prints and aborts."""
    return rc in ELEM_RWLOCK_OK


def element_array(mem, owner, count, gate_byte, elem_ctor):
    """Phase B (0x5f1076c..0x5f10838): build the 0xc40 element
    array. `elem_ctor` is called once per element with its
    address. Returns (begin, end, cap); raises LengthError
    when count exceeds the guard. A zero gate byte or a zero
    count leaves the triple null."""
    if gate_byte == 0 or count == 0:
        mem.write_qword(owner + ARRAY_BEGIN_OFF, 0)
        mem.write_qword(owner + ARRAY_END_OFF, 0)
        mem.write_qword(owner + ARRAY_CAP_OFF, 0)
        return (0, 0, 0)
    if count > ELEM_MAX_COUNT:
        raise LengthError(LENGTH_ERROR_TEXT)
    size = ELEM_SIZE * count
    begin = mem.alloc(size)
    end = begin + size
    mem.write_qword(owner + ARRAY_BEGIN_OFF, begin)
    mem.write_qword(owner + ARRAY_END_OFF, begin)
    mem.write_qword(owner + ARRAY_CAP_OFF, end)
    cursor = begin
    while cursor != end:
        elem_ctor(cursor)
        cursor += ELEM_SIZE
    mem.write_qword(owner + ARRAY_END_OFF, end)
    return (begin, end, end)


def tail_init(mem, owner, options, arg4):
    """Phase C (0x5f10838..0x5f1091d): initialise owner+0xc48..
    0xd08 (the array end is already at +0xc48)."""
    mem.write_qword(owner + 0xC58, arg4[0x40])
    mem.write_qword(owner + 0xC60, 0)
    mem.write_u32(owner + 0xC68, 0)
    mem.write_qword(owner + 0xC70, options[0x210])
    mem.write_qword(owner + 0xC78, options[0x300])
    mem.write_qword(owner + 0xC80, owner + 0xCB0)
    mem.write_qword(owner + 0xC88, 1)
    mem.write_qword(owner + 0xC90, 0)
    mem.write_qword(owner + 0xC98, 0)
    mem.write_u32(owner + 0xCA0, 0x3F800000)
    mem.write_qword(owner + 0xCA8, 0)
    mem.write_qword(owner + 0xCB0, 0)
    mem.write_bytes(owner + 0xCB8, TAIL_CONST_CB8)
    mem.write_bytes(owner + 0xCC8, TAIL_CONST_CC8)
    for off in (0xCD8, 0xCE8, 0xCF8):
        mem.write_qword(owner + off, 0)
    mem.write_qword(owner + 0xD08, 0)
    return owner


def small_install_gate(field20, field30, fieldc58):
    """The +0xc60 rebuild gate: small iff (+0x20 != 0) and
    (+0xc58 != 0 or +0x30 != 0)."""
    return field20 != 0 and (fieldc58 != 0 or field30 != 0)


def descriptor_size(value20):
    """0x61c26f0: the arena allocation size and the stored
    count for a given owner+0x20 input. Returns (n, size)
    with n = 4*ceil(value20/256) and size = 32*ceil(value20/
    256) + 31."""
    ceil = -(-value20 // 256) if value20 > 0 else 0
    n = 4 * ceil
    size = 32 * ceil + 31
    return n, size


def build_small_descriptor(mem, block, arena, value20, value28,
                           options220, allocator):
    """0x61c26f0(block, arena, owner+0x20, 6, owner+0x28,
    options+0x220): *(block+4) = 3, *(block+0) =
    4*ceil(value20/256), *(block+8) = the 32-aligned start of
    a zeroed arena allocation of 32*ceil(value20/256)+31
    bytes. `allocator` is called as (arena, size, value28,
    options220) and must return the raw pointer. Returns the
    (n, size, raw, aligned) tuple."""
    n, size = descriptor_size(value20)
    mem.write_u32(block + 0x04, 3)
    mem.write_u32(block + 0x00, n)
    raw = allocator(arena, size, value28, options220)
    for i in range(size):
        mem.write_byte(raw + i, 0)
    aligned = (raw + 31) & ~31
    mem.write_qword(block + 0x08, aligned)
    return (n, size, raw, aligned)


def once_predicate(mem, owner, slot15_returns=(0, 0)):
    """0x5f07300: the once predicate. `slot15_returns` are the
    two slot-15 call results (both 0 in the binary: slot 15 is
    `endbr64; xor %eax,%eax; ret`). Stores +0xcd0 and returns
    the boolean."""
    total = slot15_returns[0] + slot15_returns[1] + mem.read_qword(owner + 0xA00)
    mem.write_qword(owner + 0xCD0, total)
    h = mem.read_qword(owner + OWNER_ALIGNED_OFF)
    a = mem.read_qword(owner + 0xA80)
    scaled = _double_from_u64(h) * PRED_SCALE + _double_from_i64(a)
    h_plus_total = (h + total) & 0xFFFFFFFFFFFFFFFF
    if scaled > _double_from_u64(h_plus_total):
        return False
    if _double_from_u64(total) > scaled:
        return True
    base = mem.read_qword(owner + 0xE8)
    shift = mem.read_u32(owner + 0xF0) & 63  # shl uses cl & 63
    count = 1 << shift
    total_sum = mem.read_qword(owner + 0x9F8)
    for i in range(count):
        total_sum += mem.read_qword(base + i * 64 + 0x38)
    return total_sum < (h >> 2)


def once_helper(mem, owner, slot15_returns=(0, 0)):
    """0x5f07490: returns the latched flag value after the call.
    When the flag is already nonzero it returns at once; else
    it runs the predicate and latches 1 only on true."""
    if mem.read_u32(owner + ONCE_FLAG_OFF) != 0:
        return mem.read_u32(owner + ONCE_FLAG_OFF)
    if once_predicate(mem, owner, slot15_returns):
        mem.write_u32(owner + ONCE_FLAG_OFF, 1)
    return mem.read_u32(owner + ONCE_FLAG_OFF)


def install_table(mem, owner, table, log_k, entries):
    """The main install loop (0x5f1093e..0x5f10b30): allocate the
    0x48-byte big control, then for each of the N = 1 << log_k
    entries allocate a 0x20-byte small control, bump the big
    control's use and the small control's use to 2, install
    {&big+0x10, small} at the entry (releasing the old entry
    control), and release the small control's temporary second
    reference. `entries` maps entry index -> Control or None
    (the old entry controls). Returns (big, smalls, releases)
    where releases records each old-control release outcome."""
    big_addr = mem.alloc(BIG_CONTROL_SIZE)
    big = Control(mem, big_addr, BIG_CONTROL_VTABLE,
                  BIG_CONTROL_SIZE, CACHE_OBJECT_SIZE)
    smalls = []
    releases = []
    n = 1 << log_k
    for i in range(n):
        entry_addr = table + i * TABLE_ENTRY_SIZE
        small_addr = mem.alloc(SMALL_CONTROL_SIZE)
        small = Control(mem, small_addr, SMALL_CONTROL_VTABLE,
                        SMALL_CONTROL_SIZE, 0x10)
        mem.write_qword(small_addr + 0x10, big_addr + 0x10)
        mem.write_qword(small_addr + 0x18, big_addr)
        big.bump_use()
        mem.write_u32(small_addr + 0x08, 2)
        old = entries.get(i)
        mem.write_qword(entry_addr, big_addr + 0x10)
        mem.write_qword(entry_addr + 0x08, small_addr)
        if old is not None:
            releases.append(old.release())
        else:
            releases.append(None)
        small.release()  # temporary second reference: use 2 -> 1
        smalls.append(small)
    return big, smalls, releases


def owner_epilogue_release(big):
    """The epilogue tail jump to 0x5d350c0: release the big
    control once (the temporary reference held during the
    install). Returns the release outcome."""
    return big.release()


def caller_args(base, arg2, arg3):
    """The owner's non-rdi arguments as the two callers build
    them: (base+0x40, base+0x368, arg2, *(base+0x8e0), arg3,
    *(base)). `base` is a dict of the caller's object fields;
    rdi is the fresh 0xd20-byte owner and is the return value,
    not an argument here."""
    return (base[0x40], base[0x368], arg2, base[0x8E0], arg3, base[0x00])
