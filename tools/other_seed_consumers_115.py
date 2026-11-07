"""Python model of RE-001 remaining per-thread LCG-seed consumers (node #115).

Models the behaviour pinned by research/work-items/
RE-001-other-picker-seed-consumers-115/ from the digest-verified work
binary (SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

Open PR #3613 (RE-001-statistics-shard-record-115) established the
17-site census of the per-thread LCG seed (0x61c4080): 3 sites in the
StatisticsImpl record slots, and 14 elsewhere. Seven of those 14
were pinned by later packets (the tombstone factory 0x5f0a9c0 in the
merged RE-001-range-tombstone-cache-115 packet, the shard refresh
0x605e170 in the merged RE-001-shard-refresh-605e170-115 packet, the
hash-index insert 0x605f340 in the merged
RE-001-chain-histogram-snapshot-115 / RE-001-hashlinklist-insert-115
packets, the slot claim 0x61c1e10 in the merged
RE-001-zstd-decompress-cache-115 packet). This model covers the
remaining 10 sites in 9 host routines: what each host does with the
advanced seed value.

The seed word itself is a model input (its initial value is the
_Hash_bytes of pthread_self, pinned in #3613). Every derivation below
advances the word once with the same mersenne fold the binary uses
in all ten sites, then derives one bounded random value from it:

* oneshot builders 0x5f6b000 / 0x5f999d0: the 1-in-1024 sample flag
  (seed & 0x3ff) == 0x133, stored at LevelIterator record +0x90.
* flag wait 0x5fca940: the 1-in-256 skip flag (seed & 0xff) == 0.
* SkipListRep slot 0 (0x6063150): a geometric height draw by
  rejection sampling against this+0x14, capped at min(count, 32).
* randomised descent 0x6066b80: once per level, index = seed % n.
* SkipListRep slot 14 (0x6066f20): per iteration, index =
  seed % remaining_nodes; a hit needs index < remaining_count.
* ZSTD gate 0x60e5610: run the CCtx setup only when seed % N == 0.
* bitmap-node ctor 0x60f4a00: node+0x20 = seed % count, plus a
  log2-derived byte at node+0x10.
* sample-flag ctor 0x616f960: the 1-in-1024 flag at this+0x1e0.
"""

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

LCG_MULTIPLIER = 0x41A7
MERSENNE_MODULUS = 0x7FFFFFFF
SAMPLE_MAGIC_1024 = 0x133
SAMPLE_MASK_1024 = 0x3FF
SAMPLE_MASK_256 = 0xFF

# The Rust source-path pointer stored at LevelIterator record +0xb8
# and +0x100 (see records.json literals): the byte at the pointer is
# 0x00 and the path string begins one byte later, at 0x4376fe.
ONESHOT_PATH_POINTER = 0x4376FD
ONESHOT_PATH_STRING = ("/home/ubuntu/hl/code_Mainnet/z_vendor/"
                       "futures-channel/src/oneshot.rs")

# LevelIterator record (0x118 bytes, vtable 0x64cce30) layout fields
# pinned by the 0x5f6b000 / 0x5f999d0 builders.
LEVELITER_VTABLE = 0x64CCE30
LEVELITER_RECORD_SIZE = 0x118
LEVELITER_SAMPLE_FLAG_OFFSET = 0x90
LEVELITER_PREDICATE_OFFSET = 0x92
LEVELITER_STATS_RECORD_OFFSET = 0x88
LEVELITER_PATH_OFFSETS = (0xB8, 0x100)
# Fixed record fields (corrected after slopbot's limited review on
# PR #4156): +0x70 is movabs $0xffffffffffffff (0x00ffffffffffffff,
# 56-bit, NOT -1) in both builders; +0xc8 is u16 0x100 in both;
# +0x93 differs per builder -- the builder stores the 6th argument's
# low byte (r9b), the lookup stores u16 0x100 (low byte 0x00);
# +0x94 is byte 1 in the builder and the high byte of that u16 in
# the lookup.
LEVELITER_PLUS_0X70 = 0x00FFFFFFFFFFFFFF
LEVELITER_PLUS_0XC8 = 0x100

# The constant descriptor at 0x459a38 used by the bitmap-node ctor:
# low u32 4, high u32 32 (the divisor for the bitmap word count).
NODE_DESCRIPTOR = (4, 32)


# ---------------------------------------------------------------------------
# The shared advance: seed = seed * 0x41a7 mod 0x7fffffff (mersenne fold)
# ---------------------------------------------------------------------------

def mersenne_step(seed):
    """Advance the per-thread seed exactly as the binary does.

    Every host inlines the same sequence: t = seed * 0x41a7 (64-bit);
    low = t & 0x7fffffff; high = t >> 31; s = low + high (32-bit add);
    if the add sets the sign flag (s >= 2**31), s -= 0x7fffffff.
    The result is always in [0, 0x7fffffff]. Note the edge: when
    low + high == 0x7fffffff exactly, the sign flag is clear and the
    step keeps 0x7fffffff (the mathematical mod would give 0); that
    input is a single 31-bit value and never arises from the seed
    getter's range in practice, but the model follows the instructions.
    """
    t = (seed * LCG_MULTIPLIER) & ((1 << 64) - 1)
    low = t & MERSENNE_MODULUS
    high = t >> 31
    s = (low + high) & 0xFFFFFFFF
    if s & 0x80000000:
        s = (s - MERSENNE_MODULUS) & 0xFFFFFFFF
    return s


def seed_init(pthread_self_bytes):
    """The seed getter's first-use rule (0x61c4080, pinned in #3613).

    Kept here only as the input contract: the first use computes
    _Hash_bytes(&pthread_self, 8, 0xc70f6907) & 0x7fffffff, or 1 when
    that is 0. The derivations below take the current seed word as
    their input; this helper documents where it comes from.
    """
    return _hash_bytes(pthread_self_bytes, 0xC70F6907) & MERSENNE_MODULUS or 1


_MURMUR_M = 0xC6A4A7935BD1E995
_MURMUR_R = 47
_MASK64 = (1 << 64) - 1


def _hash_bytes(data, seed):
    """libstdc++ _Hash_bytes (MurmurHash64A); reused from #3613."""
    h = (seed ^ ((len(data) * _MURMUR_M) & _MASK64)) & _MASK64
    nblocks = len(data) // 8
    for i in range(nblocks):
        k = int.from_bytes(data[i * 8:(i + 1) * 8], "little")
        k = (k * _MURMUR_M) & _MASK64
        k ^= (k >> _MURMUR_R) & _MASK64
        k = (k * _MURMUR_M) & _MASK64
        h ^= k
        h = (h * _MURMUR_M) & _MASK64
    tail = data[nblocks * 8:]
    if tail:
        # _Hash_bytes folds the tail little-endian into the low bytes.
        h ^= int.from_bytes(tail, "little")
        h = (h * _MURMUR_M) & _MASK64
    h ^= (h >> _MURMUR_R) & _MASK64
    h = (h * _MURMUR_M) & _MASK64
    h ^= (h >> _MURMUR_R) & _MASK64
    return h


# ---------------------------------------------------------------------------
# 0x6063150: SkipListRep slot 0, geometric height draw
# ---------------------------------------------------------------------------

def height_draw(seed, bound, count):
    """Draw a skiplist height the way 0x6063150 does.

    Returns (height, new_seed, advances). Tries start at 1; each try
    advances the seed once and stops at the first seed < bound. The
    height is the try number, capped at min(count, 32): when
    tries + 1 == count the draw exhausts with height = count; when
    tries + 1 == 32 it caps at 32. When count <= 1 the seed is never
    touched and the height is 1. The byte offset of the height slot
    in the node is (height - 1) * 8.
    """
    if count <= 1:
        return (1, seed, 0)
    tries = 1
    cur = seed
    while True:
        cur = mersenne_step(cur)
        if cur < bound:
            return (tries, cur, tries)
        if tries + 1 == count:
            return (count, cur, tries)
        if tries + 1 == 32:
            return (32, cur, tries)
        tries += 1


def height_byte_offset(height):
    """Byte offset of the height slot: (height - 1) * 8."""
    return (height - 1) * 8


# ---------------------------------------------------------------------------
# 0x6066b80: randomised skiplist descent, one advance per level
# ---------------------------------------------------------------------------

def descent_pick(seed, n):
    """One level of the randomised descent: advance once, index = seed % n.

    Returns (new_seed, index). n is the number of 8-byte entries in
    the current level's array, computed by the host as
    (array_end - array_base) / 8.
    """
    cur = mersenne_step(seed)
    return (cur, cur % n)


# ---------------------------------------------------------------------------
# 1-in-1024 / 1-in-256 sample flags
# ---------------------------------------------------------------------------

def sample_flag_1024(seed):
    """(new_seed, flag) with flag = ((step(seed) & 0x3ff) == 0x133).

    Used by 0x5f6b000 (record+0x90, and the index-0 list-bump gate),
    0x5f999d0 (record+0x90) and 0x616f960 (this+0x1e0).
    """
    cur = mersenne_step(seed)
    return (cur, (cur & SAMPLE_MASK_1024) == SAMPLE_MAGIC_1024)


def sample_flag_256(seed):
    """(new_seed, skip) with skip = ((step(seed) & 0xff) == 0).

    Used by the flag wait 0x5fca940: skip selects the slow timed-wait
    adjustment path.
    """
    cur = mersenne_step(seed)
    return (cur, (cur & SAMPLE_MASK_256) == 0)


# ---------------------------------------------------------------------------
# 0x6066f20: SkipListRep slot 14, random-index sampler
# ---------------------------------------------------------------------------

def sampler_step(seed, remaining_nodes, remaining_count):
    """One sampler iteration: advance once, index = seed % remaining_nodes.

    Returns (new_seed, index, hit) where hit is index < remaining_count.
    On a hit the host hash-looks the sampled node up and decrements
    remaining_count; it loops while remaining_count != 0.
    """
    cur = mersenne_step(seed)
    index = cur % remaining_nodes
    return (cur, index, index < remaining_count)


# ---------------------------------------------------------------------------
# 0x60e5610: ZSTD CCtx-create gate
# ---------------------------------------------------------------------------

def zstd_gate(seed, divisor):
    """(new_seed, run) with run = (step(seed) % divisor) == 0.

    The heavy ZSTD CCtx setup runs only when the gate is true; the
    divisor is *(arg2+0x20). A divisor of 1 always runs.
    """
    cur = mersenne_step(seed)
    return (cur, cur % divisor == 0)


# ---------------------------------------------------------------------------
# 0x60f4a00: bitmap-node ctor
# ---------------------------------------------------------------------------

def log2_byte(count):
    """The node+0x10 byte: 0 when count < 2, else floor(log2(count >> 1)) + 1."""
    if count < 2:
        return 0
    return (count >> 1).bit_length()


def bitmap_start(seed, count):
    """(new_seed, start_index, log2_byte) for the bitmap node.

    start_index = step(seed) % count lands at node+0x20, where count
    is the rdx argument; the log2 byte lands at node+0x10 and is
    derived from the same count. The bitmap word count is a separate
    computation over *(this+0x30) -- see bitmap_word_count.
    """
    cur = mersenne_step(seed)
    return (cur, cur % count, log2_byte(count))


def bitmap_word_count(table_count):
    """Number of u32 bitmap words for the node.

    ((table_count - 1) >> log2_byte) // 32 + 1, where table_count is
    *(this+0x30) (not the rdx argument used for the seed modulus) and
    32 is the descriptor's high u32 at 0x459a38.
    """
    shift = log2_byte(table_count)
    return ((table_count - 1) >> shift) // NODE_DESCRIPTOR[1] + 1


# ---------------------------------------------------------------------------
# LevelIterator record (0x5f6b000 / 0x5f999d0 builders)
# ---------------------------------------------------------------------------

def level_record(shard_index, predicate, sample_flag, stats_record,
                 entry_ptr, arg2, arg3, cleanable_ptr, next_ptr):
    """Build the 0x118-byte LevelIterator record as a field map.

    Only the fields the seed hosts pin are modelled: the vtable, the
    per-shard statistics record pointer at +0x88, the sample flag at
    +0x90, the predicate result at +0x92, the entry pointer at +0x98,
    the shard index at +0xa0, and the oneshot path pointer at +0xb8
    and +0x100. The remaining fields are zero except +0x91 = 3,
    +0x70 = 0x00ffffffffffffff, +0xc8 = u16 0x100, +0x94 = 1 and
    +0x80 = &this+0x1118 (recorded symbolically here); +0x93 is
    per-builder, see level_record_flag_byte.
    """
    rec = {
        "vtable": LEVELITER_VTABLE,
        "size": LEVELITER_RECORD_SIZE,
        "cleanable": cleanable_ptr,
        "stats_record": stats_record,
        "sample_flag": sample_flag,
        "predicate": predicate,
        "entry_ptr": entry_ptr,
        "shard_index": shard_index,
        "path_pointer": ONESHOT_PATH_POINTER,
        "arg2": arg2,
        "arg3": arg3,
        "next_ptr": next_ptr,
    }
    return rec


def level_record_flag_byte(builder, sixth_arg_byte=None):
    """The LevelIterator record byte at +0x93, which differs per builder.

    The builder 0x5f6b000 stores the 6th argument's low byte (r9b,
    via r12b); the lookup 0x5f999d0 stores u16 0x100 at +0x93, so
    the byte is 0x00 and +0x94 is 0x01 as its high byte. `builder`
    is "builder" or "lookup".
    """
    if builder == "builder":
        if sixth_arg_byte is None:
            raise ValueError("builder needs the 6th argument byte")
        return sixth_arg_byte & 0xFF
    if builder == "lookup":
        return 0x00
    raise ValueError(builder)
