"""Python model of the node #115 StatisticsImpl write side.

Covers RE-001-stats-write-side-115: the six write-side vtable slots
of rocksdb::StatisticsImpl (primary vtable 0x64d2d88) plus the
helpers and lifecycle routines they depend on. Every number below
is pinned to the node #115 binary (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301);
the evidence packet is research/work-items/RE-001-stats-write-side-115/.

Layout (StatisticsImpl, 0x70 bytes, ctor 0x6071a00):
    +0x00  vtable pointer (0x64d2d88)
    +0x08  options vector {begin, end, capacity}
    +0x18  (zeroed by the ctor)
    +0x20  enable byte: 0 = record nothing, 1 = tickers only,
            >= 2 = tickers and histograms (ctor writes 3)
    +0x28  delegate Statistics* (shared_ptr raw pointer; +0x30 is
            the control block) moved in from the ctor's 2nd argument
    +0x38  mutex (pthread_mutex_t, init via 0x60d50c0)
    +0x60  shard-store pointer (built by 0x60716d0)
    +0x68  shard_bits (u8): shard count is 1 << shard_bits

Shard store: 1 << shard_bits shards of 0xce40 bytes each.
    shard + id*8            ticker counter id (u64)
    shard + 0x598 + id*0x3c8  HistogramImpl record id (0x3c8 bytes)
    shard + 0xce00..0xce40  0x40 tail, contents open (see README)

Valid ids: tickers 0..0xb1 (178), histograms 0..0x33 (52, slot
0xf8). Physical capacity is one slot wider on both sides
(179 ticker slots, 53 histogram records per shard).

Write side (all six slots are reached only through the vtable;
none has a direct call anywhere in the binary):
    slot 0xb0  record_tick      lock-free: gate, per-CPU shard pick
                                 (or LCG fallback), `lock add`, then
                                 tail-call the delegate's slot 0xb0
    slot 0xb8  set_ticker       locked: set_core, unlock, then walk
                                 the delegate chain the same way
    slot 0xc0  get_and_reset    locked: sum all shards with xchg-0,
                                 return the sum, then reset the
                                 delegate chain via slot 0xb8
    slot 0xd8  record_histogram lock-free: gate (> 1), per-CPU shard
                                 pick (or LCG fallback), call the
                                 record's slot 0x20, then tail-call
                                 the delegate's slot 0xd8 (only when
                                 id <= 0x33)
    slot 0xd0  record_histogram devirtualized twin of 0xd8: when
                                 this's own slot 0xd8 is the local
                                 0x606fef0 the body is inlined,
                                 otherwise it dispatches virtually
    slot 0xe0  reset            locked: zero all 178 tickers and
                                 re-init all 52 histograms on every
                                 shard; writes Status OK; no delegate
                                 walk, no enable-byte check

Helpers:
    0x60d5cd0  cpu_shard_pick: CPUID leaf 1 EBX[31:24] (the APIC id),
                                 or -1 when CPUID leaf 0 reports 0
    0x61c4080  thread_seed: address of this thread's Park-Miller
                                 seed, lazily seeded from
                                 _Hash_bytes(pthread_self, 8,
                                 0xc70f6907) & 0x7fffffff (or 1)
    0x6070ac0  set_core: shard 0 counter := value, all other shards'
                                 counters := 0 (xchg, no bound check)
    0x606b130  HistogramImpl slot 0x20 record: bucket++, min/max,
                                 count++, sum += value,
                                 sum_sq += value*value (u64 wrap)
    0x606afa0  bucket lower_bound over the 109 generated boundaries
    0x606b0c0  HistogramImpl slot 0x10 locked init (re-init a record)
    0x606b020  shared init: min := ceiling, max/count/sum/sum_sq := 0,
                                 buckets := 0
    0x606bf10  boundary generator: seeds [1, 2], cur *= 1.5, values
                                 above 109 truncated to 3 significant
                                 digits, until cur >= 2**64; the last
                                 boundary (the ceiling) is also stored
                                 at the holder's +0x18

The delegate chain is a singly linked list through +0x28. The
model walks it uniformly; the binary unrolls the first two levels
inline (with a devirtualization check on the delegate's slot) and
tail-calls the third, which is behaviorally identical when no
slot is overridden.
"""

MASK64 = (1 << 64) - 1
U64_CEILING = 13000000000000000000  # last histogram boundary
TICKER_COUNT = 178                 # valid ticker ids 0..0xb1
TICKER_CAPACITY = 179             # physical ticker slots per shard
HISTOGRAM_COUNT = 52              # valid histogram ids 0..0x33
HISTOGRAM_CAPACITY = 53           # physical histogram records per shard
SHARD_SIZE = 0xCE40
TICKER_AREA = 0x598
HIST_RECORD_SIZE = 0x3C8
PARK_MILLER_MOD = 0x7FFFFFFF       # 2**31 - 1
PARK_MILLER_MULT = 0x41A7          # 16807
HASH_SEED = 0xC70F6907
STATISTICS_NAME = "BasicStatistics"

STATISTICS_IMPL_VTABLE_SLOTS = {
    0x0: 0x6070EA0, 0x8: 0x6071040, 0x10: 0x609D760, 0x18: 0x609DC40,
    0x20: 0x5D32560, 0x28: 0x6095E70, 0x30: 0x6096790, 0x38: 0x5D2E090,
    0x40: 0x60956F0, 0x48: 0x609D0E0, 0x50: 0x60986B0, 0x58: 0x6095710,
    0x60: 0x609DE80, 0x68: 0x609D980, 0x70: 0x606FA20, 0x78: 0x5D32A30,
    0x80: 0x5D2E770, 0x88: 0x606FA30, 0x90: 0x5D2CA10, 0x98: 0x6070490,
    0xA0: 0x6070610, 0xA8: 0x6070700, 0xB0: 0x606FBA0, 0xB8: 0x6070DC0,
    0xC0: 0x6070C50, 0xC8: 0x5D48960, 0xD0: 0x606FFD0, 0xD8: 0x606FEF0,
    0xE0: 0x6070B30, 0xE8: 0x6070810, 0xF0: 0x6076030, 0xF8: 0x606FA40,
}

# Displacement-wide indirect-dispatch site counts from census.py
# (upper bounds on StatisticsImpl dispatches, not exact counts).
DISPATCH_SITES = {0xB0: 400, 0xB8: 36, 0xC0: 42,
                  0xD0: 14, 0xD8: 48, 0xE0: 31}

FOLLOWING_VTABLES = {
    0x64D2E98: ("N7rocksdb13ObjectLibrary12FactoryEntryINS_10StatisticsEEE",
                0x64D2D10),
    0x64D2EC8: ("St15_Sp_counted_ptrIPN7rocksdb14StatisticsImplELN9__gnu_cxx12_Lock_policyE2EE",
                0x64D2D48),
    0x64D2F00: ("St15_Sp_counted_ptrIPN7rocksdb10StatisticsELN9__gnu_cxx12_Lock_policyE2EE",
                0x64D2D60),
}


def histogram_boundaries():
    """The 109 boundaries, faithful to the generator 0x606bf10.

    Seeds [1, 2] from .rodata 0x453950; cur (a double) *= 1.5 each
    step until cur >= 2**64; each value is truncated toward zero
    to a u64 (with the >= 2**63 path subtracting 2**63 first and
    xoring the sign bit back in); values above 109 are truncated
    to 3 significant digits (divide by 10 while the pre-division
    value exceeds 1099, then scale back up).
    """
    out = [1, 2]
    cur = 2.0
    while True:
        cur = cur * 1.5
        if cur >= 2.0 ** 64:
            break
        if cur >= 2.0 ** 63:
            value = int(cur - 2.0 ** 63) ^ 0x8000000000000000
        else:
            value = int(cur)
        if value > 109:
            quot = value
            scale = 1
            while True:
                prev = quot
                quot //= 10
                scale *= 10
                if prev <= 1099:
                    break
            value = quot * scale
        out.append(value)
    return out


BOUNDARIES = histogram_boundaries()


def bucket_index(value):
    """Bucket index for a u64 value, faithful to 0x606afa0.

    At or above the ceiling goes to the last bucket; otherwise the
    first boundary >= value (lower_bound).
    """
    if value >= BOUNDARIES[-1]:
        return len(BOUNDARIES) - 1
    lo, hi = 0, len(BOUNDARIES)
    while lo < hi:
        mid = (lo + hi) // 2
        if BOUNDARIES[mid] >= value:
            hi = mid
        else:
            lo = mid + 1
    return lo


def _hash_bytes(data, seed):
    """libstdc++ _Hash_bytes (MurmurHash64A) over data with seed.

    The binary calls it as _Hash_bytes(pthread_self, 8,
    0xc70f6907) to seed the thread-local LCG state. The exact
    output is not byte-verified against a live run (the seed is
    thread-dependent); the algorithm is the documented libstdc++
    one and the model only relies on its determinism and range.
    """
    mask = MASK64
    m = 0xC6A4A7935BD1E995
    r = 47
    h = (seed ^ (len(data) * m)) & mask
    n = len(data)
    i = 0
    while n - i >= 8:
        k = int.from_bytes(data[i:i + 8], "little")
        k = (k * m) & mask
        k ^= k >> r
        k = (k * m) & mask
        h ^= k
        h = (h * m) & mask
        i += 8
    tail = n - i
    if tail:
        k = 0
        for j in range(tail):
            k ^= data[i + j] << (8 * j)
        k = (k * m) & mask
        k ^= k >> r
        k = (k * m) & mask
        h ^= k
    h ^= h >> r
    h = (h * m) & mask
    h ^= h >> r
    return h


class ThreadSeed:
    """One thread's Park-Miller state, per 0x61c4080.

    The state lives in thread-local storage; the first call seeds
    it from _Hash_bytes(pthread_self, 8, 0xc70f6907) & 0x7fffffff,
    or 1 when that is 0. Each fallback shard pick advances it by
    state = state * 16807 mod (2**31 - 1).
    """

    def __init__(self, state):
        self.state = state & PARK_MILLER_MOD

    @classmethod
    def from_thread_id(cls, thread_id_bytes):
        hashed = _hash_bytes(thread_id_bytes, HASH_SEED)
        state = hashed & PARK_MILLER_MOD
        if state == 0:
            state = 1
        return cls(state)

    def next_state(self):
        """One Park-Miller step, with the binary's exact reduction.

        x = state * 16807; r = (x & m) + (x >> 31); if r >= m:
        r -= m. For x < 2**62 this equals x % m.
        """
        x = self.state * PARK_MILLER_MULT
        r = (x & PARK_MILLER_MOD) + (x >> 31)
        if r >= PARK_MILLER_MOD:
            r -= PARK_MILLER_MOD
        self.state = r
        return r


def cpu_shard_pick(cpuid_max_leaf, ebx_leaf1):
    """Shard index from CPUID, faithful to 0x60d5cd0.

    Returns -1 when CPUID leaf 0 reports a max leaf of 0
    (CPUID unavailable); otherwise EBX[31:24] of leaf 1 (the
    APIC id, 0..255).
    """
    if cpuid_max_leaf == 0:
        return -1
    return (ebx_leaf1 >> 24) & 0xFF


class HistogramRecord:
    """One 0x3c8-byte HistogramImpl record inside a shard.

    Fields are the inner struct at the record start: min, max,
    count, sum, sum_sq, buckets[109], bucket_count at +0x390.
    """

    def __init__(self):
        self.bucket_count = len(BOUNDARIES)
        self.shared_init()

    def shared_init(self):
        """Shared init 0x606b020: min := ceiling, the rest := 0."""
        self.minimum = U64_CEILING
        self.maximum = 0
        self.count = 0
        self.total = 0
        self.total_sq = 0
        self.buckets = [0] * self.bucket_count

    def locked_init(self):
        """Slot 0x10 (0x606b0c0): lock the record mutex, shared init."""
        self.shared_init()

    def record(self, value):
        """Slot 0x20 (0x606b130): bucket++, min/max, count/sum."""
        value &= MASK64
        self.buckets[bucket_index(value)] += 1
        if value < self.minimum:
            self.minimum = value
        if value > self.maximum:
            self.maximum = value
        self.count += 1
        self.total = (self.total + value) & MASK64
        self.total_sq = (self.total_sq + value * value) & MASK64


class Shard:
    """One 0xce40-byte shard: 179 ticker slots, 53 histogram records."""

    def __init__(self):
        self.tickers = [0] * TICKER_CAPACITY
        self.histograms = [HistogramRecord()
                           for _ in range(HISTOGRAM_CAPACITY)]


class Status:
    """A Status out-param: code 0 is OK (0xe0 writes exactly this)."""

    def __init__(self, code=0):
        self.code = code

    def ok(self):
        return self.code == 0


class StatisticsImpl:
    """A StatisticsImpl object with its delegate chain."""

    def __init__(self, shard_bits=3, delegate=None, enabled=3):
        self.enabled = enabled       # +0x20 byte; ctor writes 3
        self.shard_bits = shard_bits  # +0x68 u8
        self.shards = [Shard() for _ in range(1 << shard_bits)]
        self.delegate = delegate     # +0x28 shared_ptr, None if null
        self.lock_depth = 0          # model lock accounting only
        self.lock_acquisitions = 0

    # -- accessors -------------------------------------------------
    def name(self):
        """Slot 0x70 (0x606fa20): "BasicStatistics"."""
        return STATISTICS_NAME

    def delegate_ptr(self):
        """Slot 0x88 (0x606fa30): the delegate pointer, or None."""
        return self.delegate

    @staticmethod
    def hist_id_valid(hist_id):
        """Slot 0xf8 (0x606fa40): hist_id <= 0x33."""
        return hist_id <= 0x33

    # -- shard selection -------------------------------------------
    def _pick_shard(self, cpu, seed):
        """Shared pick for 0xb0/0xd8/0xd0: CPU id, else LCG step."""
        if cpu is not None:
            picked = cpu_shard_pick(cpu[0], cpu[1])
        else:
            picked = -1
        if picked < 0:
            if seed is None:
                raise ValueError("fallback shard pick needs a ThreadSeed")
            picked = seed.next_state()
        return picked & ((1 << self.shard_bits) - 1)

    def _lock(self):
        self.lock_depth += 1
        self.lock_acquisitions += 1

    def _unlock(self):
        self.lock_depth -= 1

    # -- slot 0xb0: lock-free record tick ---------------------------
    def record_tick(self, ticker_id, value, cpu=None, seed=None):
        """Slot 0xb0 (0x606fba0): gate, pick, lock-add, forward."""
        if not self.enabled or ticker_id > 0xB1:
            return
        shard = self._pick_shard(cpu, seed)
        self.shards[shard].tickers[ticker_id] = (
            self.shards[shard].tickers[ticker_id] + (value & MASK64)
        ) & MASK64
        if self.delegate is not None:
            self.delegate.record_tick(ticker_id, value, cpu, seed)

    # -- unlocked set core 0x6070ac0 ---------------------------------
    def _set_core(self, ticker_id, value):
        """Shard 0 counter := value; every other shard's := 0."""
        value &= MASK64
        self.shards[0].tickers[ticker_id] = value
        for shard in self.shards[1:]:
            shard.tickers[ticker_id] = 0

    # -- slot 0xb8: locked set ticker -------------------------------
    def set_ticker(self, ticker_id, value):
        """Slot 0xb8 (0x6070dc0): lock, set_core, unlock, forward."""
        self._lock()
        try:
            self._set_core(ticker_id, value)
        finally:
            self._unlock()
        if self.delegate is not None and ticker_id <= 0xB1:
            self.delegate.set_ticker(ticker_id, value)

    # -- slot 0xc0: get-and-reset ticker ----------------------------
    def get_and_reset_ticker(self, ticker_id):
        """Slot 0xc0 (0x6070c50): locked sum + zero; reset the chain."""
        total = 0
        self._lock()
        try:
            for shard in self.shards:
                total = (total + shard.tickers[ticker_id]) & MASK64
                shard.tickers[ticker_id] = 0
        finally:
            self._unlock()
        if self.delegate is not None and ticker_id <= 0xB1:
            self.delegate.set_ticker(ticker_id, 0)
        return total

    # -- slot 0xd8 / 0xd0: lock-free record histogram ---------------
    def record_histogram(self, hist_id, value, cpu=None, seed=None):
        """Slot 0xd8 (0x606fef0); 0xd0 inlines this same body when
        the object's own slot 0xd8 is the local routine."""
        if self.enabled <= 1:
            return
        shard = self._pick_shard(cpu, seed)
        self.shards[shard].histograms[hist_id].record(value)
        if hist_id <= 0x33 and self.delegate is not None:
            self.delegate.record_histogram(hist_id, value, cpu, seed)

    # -- slot 0xe0: reset -------------------------------------------
    def reset(self):
        """Slot 0xe0 (0x6070b30): locked zero + re-init; Status OK."""
        out = Status(0)
        self._lock()
        try:
            for ticker_id in range(TICKER_COUNT):
                self._set_core(ticker_id, 0)
            for hist_id in range(HISTOGRAM_COUNT):
                for shard in self.shards:
                    shard.histograms[hist_id].locked_init()
        finally:
            self._unlock()
        return out
