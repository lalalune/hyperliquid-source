"""Python model of RE-001 StatisticsImpl shard record (node #115).

Models the behaviour pinned by research/work-items/
RE-001-statistics-shard-record-115/ from the digest-verified work
binary (SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):
StatisticsImpl records tickers and histograms into a per-CPU sharded
store. The shard is picked by a CPUID logical-processor count
(0x60d5cd0); when CPUID is unavailable the per-thread LCG seed
(0x61c4080) is advanced instead. The ticker slot 0xb0 (0x606fba0)
and the histogram slots 0xd0/0xd8 (0x606ffd0/0x606fef0) are the
StatisticsImpl vtable methods; the histogram record reaches the
per-shard HistogramImpl record through its vtable slot 0x20, the
record thunk 0x606b1c0.

The _Hash_bytes / ThreadSeed / mersenne_step helpers and the
Histogram record rules are reused from open PR #3575
(RE-001-chain-histogram-snapshot-115), whose model in turn follows
open PR #3371 for the 109 bucket boundaries; the record impl
(0x606b130) and the seed (0x61c4080) are re-shipped byte-identical
from #3575 in this packet.
"""

import math

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# Shard-store layout (established by the re-shipped ctor 0x6071a00
# and shard-store builder 0x60716d0 from open PR #3572):
# this+0x20 level byte, this+0x28 delegate, this+0x60 records base,
# this+0x68 bucket exponent. Each shard is 0xce40 bytes: a 0x598-byte
# header holding the ticker counters (8 bytes each), then 53 records
# of 0x3c8 bytes (HistogramImpl, vtable 0x64d2b80) at shard+0x598.
SHARD_SIZE = 0xCE40
HEADER_SIZE = 0x598
RECORD_SIZE = 0x3C8
RECORD_COUNT = 53
TICKER_MAX = 0xB1          # ticker ids 0..0xb1 inclusive are recorded
HISTOGRAM_FORWARD_MAX = 0x33  # only hist ids 0..0x33 are forwarded
MASK64 = (1 << 64) - 1

# ---------------------------------------------------------------------------
# 0x60d5cd0: CPUID logical-processor picker
# ---------------------------------------------------------------------------


def cpuid_logical_count(max_leaf, leaf1_ebx):
    """The picker's exact rule.

    cpuid leaf 0 gives the max leaf in eax; when it is 0 the picker
    returns -1. Otherwise cpuid leaf 1 is read and the count is
    EBX >> 24 (the maximum number of addressable logical-processor
    IDs). max_leaf / leaf1_ebx are the injected cpuid results.
    """
    if max_leaf == 0:
        return -1
    return (leaf1_ebx >> 24) & 0xFF


def pick_shard(source_value, exponent):
    """Shard index: source & ((1 << exponent) - 1)."""
    return source_value & ((1 << exponent) - 1)


# ---------------------------------------------------------------------------
# 0x61c4080: per-thread hash seed (libstdc++ _Hash_bytes over
# pthread_self); reused from open PR #3575.
# ---------------------------------------------------------------------------

_MURMUR_M = 0xC6A4A7935BD1E995
_MURMUR_R = 47
_MASK64 = (1 << 64) - 1


def _hash_bytes(data, seed):
    """libstdc++ _Hash_bytes (MurmurHash64A) over data with the given seed."""
    h = (seed ^ ((len(data) * _MURMUR_M) & _MASK64)) & _MASK64
    nblocks = len(data) // 8
    for i in range(nblocks):
        k = int.from_bytes(data[i * 8:(i + 1) * 8], "little")
        k = (k * _MURMUR_M) & _MASK64
        k ^= k >> _MURMUR_R
        k = (k * _MURMUR_M) & _MASK64
        h ^= k
        h = (h * _MURMUR_M) & _MASK64
    tail = data[nblocks * 8:]
    if tail:
        # _Hash_bytes folds the tail little-endian into the low bytes.
        h ^= int.from_bytes(tail, "little")
        h = (h * _MURMUR_M) & _MASK64
    h ^= h >> _MURMUR_R
    h = (h * _MURMUR_M) & _MASK64
    h ^= h >> _MURMUR_R
    return h


class ThreadSeed:
    """The per-thread cached seed at thread-0x20 (pointer at thread-0x10).

    First use computes _Hash_bytes(&pthread_self, 8, 0xc70f6907) &
    0x7fffffff (or 1 when that is 0) and caches it; later uses return
    the cached value. Callers advance the cached value in place.
    """

    SEED_CONSTANT = 0xC70F6907

    def __init__(self, tid_bytes):
        self._tid_bytes = bytes(tid_bytes)
        self._cached = None

    def pointer(self):
        """Return the cached seed value, computing it on first use."""
        if self._cached is None:
            v = _hash_bytes(self._tid_bytes, self.SEED_CONSTANT) & 0x7FFFFFFF
            self._cached = v if v != 0 else 1
        return self._cached

    def store(self, value):
        self._cached = value & 0xFFFFFFFF


def mersenne_step(seed):
    """One 0x41a7 multiply mod (2**31 - 1), exactly as the binary does it.

    v = seed * 0x41a7; folded = (v & 0x7fffffff) + (v >> 31); when the
    32-bit sum overflows into bit 31, subtract 0x7fffffff once (the
    cmovs after the add, whose flags come from the add because lea
    does not touch flags). The result is the true modulus except that
    a true 0 is represented as 0x7fffffff.
    """
    v = seed * 0x41A7
    folded = (v & 0x7FFFFFFF) + (v >> 31)
    folded &= 0xFFFFFFFF
    if folded & 0x80000000:
        folded = (folded - 0x7FFFFFFF) & 0xFFFFFFFF
    return folded


# ---------------------------------------------------------------------------
# HistogramImpl record (0x606b130 via the thunk 0x606b1c0); the 109
# generated bucket boundaries follow open PR #3371.
# ---------------------------------------------------------------------------


def generate_boundaries():
    """The 109 generated bucket boundaries (see #3371).

    Seed [1, 2]; cur starts at 3.0 and grows by 1.5; a pushed value
    above 109 is divided by 10 (integer) at least once, repeating
    while the pre-division value exceeds 1099, counting a factor of
    10 each time, then multiplied back.
    Stops when cur reaches 2**64.
    """
    out = [1, 2]
    cur = 3.0
    while cur < 2 ** 64:
        v = int(cur)
        if v > 109:
            f = 1
            while True:
                prev = v
                v //= 10
                f *= 10
                if prev <= 1099:
                    break
            v *= f
        out.append(v)
        cur *= 1.5
    return out


BOUNDARIES = generate_boundaries()


def bucket_index(value):
    """First index j with BOUNDARIES[j] >= value; values at or above
    the ceiling return count - 1 (std::lower_bound rule, #3371)."""
    lo, hi = 0, len(BOUNDARIES)
    while lo < hi:
        mid = (lo + hi) // 2
        if BOUNDARIES[mid] < value:
            lo = mid + 1
        else:
            hi = mid
    return min(lo, len(BOUNDARIES) - 1)


class Histogram:
    """The HistogramImpl inner record (0x606b130) as documented by #3371."""

    def __init__(self):
        self.buckets = [0] * len(BOUNDARIES)
        self.min = None
        self.max = None
        self.count = 0
        self.sum = 0
        self.sum_sq = 0

    def record(self, value):
        value &= (1 << 64) - 1
        self.buckets[bucket_index(value)] += 1
        self.min = value if self.min is None else min(self.min, value)
        self.max = value if self.max is None else max(self.max, value)
        self.count += 1
        self.sum = (self.sum + value) & ((1 << 64) - 1)
        self.sum_sq = (self.sum_sq + value * value) & ((1 << 64) - 1)

    def average(self):
        return self.sum / self.count if self.count else 0.0

    def stddev(self):
        if not self.count:
            return 0.0
        avg = self.average()
        var = self.sum_sq / self.count - avg * avg
        return math.sqrt(var) if var > 0 else 0.0

    def median(self):
        return self.percentile(50.0)

    def percentile(self, p):
        if not self.count:
            return 0.0
        # Linear interpolation inside the bucket holding the rank,
        # matching the renderer's percentile helper (0x606b260).
        rank = p / 100.0 * self.count
        seen = 0
        for i, c in enumerate(self.buckets):
            if c == 0:
                continue
            if seen + c >= rank:
                lo = 0 if i == 0 else BOUNDARIES[i - 1]
                hi = BOUNDARIES[i]
                frac = (rank - seen) / c if c else 0.0
                return lo + frac * (hi - lo)
            seen += c
        return float(BOUNDARIES[-1])


# ---------------------------------------------------------------------------
# StatisticsImpl shard store and record slots
# ---------------------------------------------------------------------------


class Shard:
    """One 0xce40-byte shard: 178 ticker counters, then 53 records."""

    def __init__(self):
        self.tickers = [0] * (TICKER_MAX + 1)
        self.records = [Histogram() for _ in range(RECORD_COUNT)]


class StatisticsImpl:
    """The StatisticsImpl object as the record slots see it.

    level is the +0x20 byte (the ctor writes 3); delegate is the
    +0x28 pointer (None when the ctor's argument was zeroed);
    exponent is the +0x68 bucket exponent and shards the records
    base at +0x60. slot_d8 holds the object's vtable slot 0xd8
    target: the canonical 0x606fef0 by default, or an override
    callable taking (stats, hist_id, value).
    """

    CANONICAL_D8 = 0x606FEF0

    def __init__(self, level=3, exponent=3, delegate=None):
        self.level = level & 0xFF
        self.delegate = delegate
        self.exponent = exponent
        self.shards = [Shard() for _ in range(1 << exponent)]
        self.slot_d8 = self.CANONICAL_D8

    def _shard_for(self, cpu_count, seed):
        """Shard pick shared by all three record slots.

        Returns (shard_index, used_seed). When the picker returns a
        negative count the caller's per-thread seed is advanced by
        one mersenne step and that value picks the shard.
        """
        if cpu_count >= 0:
            return pick_shard(cpu_count, self.exponent), None
        new_seed = mersenne_step(seed.pointer())
        seed.store(new_seed)
        return pick_shard(new_seed, self.exponent), new_seed

    def record_ticker(self, ticker_id, value, cpu_count, seed):
        """Slot 0xb0 (0x606fba0): record one ticker value.

        Returns True when the value was recorded. The level gate
        (level byte == 0) and the id gate (id > 0xb1) both return
        without recording and without forwarding. The delegate, when
        present, receives the same (id, value) through its slot 0xb0.
        """
        if ticker_id > TICKER_MAX:
            return False
        if self.level == 0:
            return False
        shard_index, _ = self._shard_for(cpu_count, seed)
        shard = self.shards[shard_index]
        shard.tickers[ticker_id] = (
            shard.tickers[ticker_id] + (value & MASK64)) & MASK64
        if self.delegate is not None:
            self.delegate.record_ticker(ticker_id, value, cpu_count, seed)
        return True

    def record_histogram(self, hist_id, value, cpu_count, seed):
        """Slot 0xd8 (0x606fef0): record one histogram sample.

        Returns True when the sample was recorded. The level gate
        (level <= 1) returns without recording and without
        forwarding. The sample lands in the picked shard's record
        hist_id through its slot 0x20 (the record thunk). The
        delegate, when present, receives the same (id, value)
        through its slot 0xd8 only when hist_id <= 0x33.
        """
        if self.level <= 1:
            return False
        shard_index, _ = self._shard_for(cpu_count, seed)
        shard = self.shards[shard_index]
        shard.records[hist_id].record(value)
        if hist_id <= HISTOGRAM_FORWARD_MAX and self.delegate is not None:
            self.delegate.record_histogram(hist_id, value, cpu_count, seed)
        return True

    def record_histogram_entry(self, hist_id, value, cpu_count, seed):
        """Slot 0xd0 (0x606ffd0): histogram entry with a canonical check.

        When this object's slot 0xd8 is not the canonical 0x606fef0,
        the call is tail-dispatched to that slot instead (the level
        gate is not consulted); otherwise the canonical body above
        runs. Returns whatever the dispatched call returns.
        """
        if self.slot_d8 != self.CANONICAL_D8:
            return self.slot_d8(self, hist_id, value, cpu_count, seed)
        return self.record_histogram(hist_id, value, cpu_count, seed)
