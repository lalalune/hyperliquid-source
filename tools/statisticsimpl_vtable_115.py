"""Python model of the node #115 StatisticsImpl primary vtable.

Covers RE-001-statisticsimpl-vtable-115: all 32 slots of the
rocksdb::StatisticsImpl primary vtable (stored pointer 0x64d2d88,
Itanium base 0x64d2d78, typeinfo N7rocksdb14StatisticsImplE at
0x64d2cf8, base N7rocksdb10StatisticsE at 0x64d2ce0), plus the
helpers and lifecycle routines the slots depend on. Every number
below is pinned to the node #115 binary (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301);
the evidence packet is
research/work-items/RE-001-statisticsimpl-vtable-115/.

Slot map (offset -> target, role):
    0x00  0x6070ea0  D1 destructor
    0x08  0x6071040  D0 deleting destructor (sized delete, 0x70)
    0x10  0x609d760  Customizable::GetOption (shared, 63 vtables)
    0x18  0x609dc40  Customizable::AreEquivalent (shared, 63)
    0x20  0x5d32560  returns empty std::string (shared, 66; name open)
    0x28  0x6095e70  base Configurable::PrepareOptions (shared, 50)
    0x30  0x6096790  Configurable::ValidateOptions (shared, 64)
    0x38  0x5d2e090  Customizable::GetOptionsPtr (shared, 62)
    0x40  0x60956f0  returns empty Status (shared, 68; name open)
    0x48  0x609d0e0  Configurable::ConfigureOptions (shared, 66)
    0x50  0x60986b0  Configurable::ParseOption (shared, 67)
    0x58  0x6095710  Configurable::OptionsAreEqual (shared, 65)
    0x60  0x609de80  base Customizable::SerializeOptions (shared, 50)
    0x68  0x609d980  Customizable::GetOptionName (shared, 63)
    0x70  0x606fa20  Name() -> "BasicStatistics"
    0x78  0x5d32a30  GetId (shared, 55; Name() as std::string)
    0x80  0x5d2e770  IsInstanceOf (shared, 44; Name or NickName)
    0x88  0x606fa30  delegate getter: *(this+0x28)
    0x90  0x5d2ca10  NickName() -> "" (shared, 45)
    0x98  0x6070490  locked ticker read (getTickerCount)
    0xa0  0x6070610  locked histogram percentiles (getHistogramData)
    0xa8  0x6070700  locked histogram text (getHistogramString)
    0xb0  0x606fba0  record tick (lock-free)
    0xb8  0x6070dc0  locked set ticker (setTickerCount)
    0xc0  0x6070c50  get-and-reset ticker (getAndResetTickerCount)
    0xc8  0x5d48960  level-3-only histogram forward (measureTime)
    0xd0  0x606ffd0  record histogram, devirtualized twin
    0xd8  0x606fef0  record histogram
    0xe0  0x6070b30  reset (Reset; Status OK)
    0xe8  0x6070810  StatisticsImpl::ToString
    0xf0  0x6076030  ticker-map fill (getTickerMap)
    0xf8  0x606fa40  histogram-id check (HistEnabledForType)

Layout (StatisticsImpl, 0x70 bytes, ctor 0x6071a00):
    +0x00  vtable pointer (0x64d2d88)
    +0x08  options vector {begin, end, capacity}
    +0x20  enable byte: 0 = record nothing, 1 = tickers only,
            >= 2 = tickers and histograms (ctor writes 3; the
            ctor is the single writer — no vtable slot writes it)
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

Level gates (the enable byte at +0x20):
    record_tick (0xb0):        enabled != 0 and id <= 0xb1
    record_histogram (0xd8):   enabled > 1 (no id bound locally)
    measure_time (0xc8):       enabled > 2, then slot 0xd8
    set_ticker / get-reset / reset: no gate at all

The delegate chain is a singly linked list through +0x28. The
model walks it uniformly; the binary unrolls the first two levels
inline (with a devirtualization check on the delegate's slot) and
tail-calls the third, which is behaviorally identical when no
slot is overridden.

Algorithms reused here (faithful to the sibling models):
    histogram boundaries / bucket index / _Hash_bytes /
    ThreadSeed / cpu_shard_pick: tools/stats_write_side_115.py
    percentile / average / stddev / percentile struct / text
    render: tools/histogram_stats_115.py (0x606b260, 0x606b500,
    0x606b540, 0x606b5d0, 0x606bce0, 0x606b6f0)
"""

import math

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
STATISTICS_NICKNAME = ""
SIZEOF_STATISTICS_IMPL = 0x70
VTABLE_STORED = 0x64D2D88
VTABLE_BASE = 0x64D2D78
TYPEINFO = 0x64D2CF8
TYPEINFO_NAME = "N7rocksdb14StatisticsImplE"
BASE_TYPEINFO = 0x64D2CE0
BASE_TYPEINFO_NAME = "N7rocksdb10StatisticsE"

SLOT_TARGETS = {
    0x00: 0x6070EA0, 0x08: 0x6071040, 0x10: 0x609D760, 0x18: 0x609DC40,
    0x20: 0x5D32560, 0x28: 0x6095E70, 0x30: 0x6096790, 0x38: 0x5D2E090,
    0x40: 0x60956F0, 0x48: 0x609D0E0, 0x50: 0x60986B0, 0x58: 0x6095710,
    0x60: 0x609DE80, 0x68: 0x609D980, 0x70: 0x606FA20, 0x78: 0x5D32A30,
    0x80: 0x5D2E770, 0x88: 0x606FA30, 0x90: 0x5D2CA10, 0x98: 0x6070490,
    0xA0: 0x6070610, 0xA8: 0x6070700, 0xB0: 0x606FBA0, 0xB8: 0x6070DC0,
    0xC0: 0x6070C50, 0xC8: 0x5D48960, 0xD0: 0x606FFD0, 0xD8: 0x606FEF0,
    0xE0: 0x6070B30, 0xE8: 0x6070810, 0xF0: 0x6076030, 0xF8: 0x606FA40,
}

SLOT_ROLES = {
    0x00: "D1 destructor",
    0x08: "D0 deleting destructor",
    0x10: "Customizable::GetOption",
    0x18: "Customizable::AreEquivalent",
    0x20: "returns empty std::string (C++ name open)",
    0x28: "base Configurable::PrepareOptions",
    0x30: "Configurable::ValidateOptions",
    0x38: "Customizable::GetOptionsPtr",
    0x40: "returns empty Status (C++ name open)",
    0x48: "Configurable::ConfigureOptions",
    0x50: "Configurable::ParseOption",
    0x58: "Configurable::OptionsAreEqual",
    0x60: "base Customizable::SerializeOptions",
    0x68: "Customizable::GetOptionName",
    0x70: "Name() -> \"BasicStatistics\"",
    0x78: "GetId",
    0x80: "IsInstanceOf",
    0x88: "delegate getter (returns *(this+0x28))",
    0x90: "NickName() -> \"\"",
    0x98: "locked ticker read (getTickerCount)",
    0xA0: "locked histogram percentiles (getHistogramData)",
    0xA8: "locked histogram text (getHistogramString)",
    0xB0: "record tick",
    0xB8: "locked set ticker (setTickerCount)",
    0xC0: "get-and-reset ticker (getAndResetTickerCount)",
    0xC8: "level-3-only histogram forward (measureTime, inference)",
    0xD0: "record histogram, devirtualized twin",
    0xD8: "record histogram",
    0xE0: "reset (Reset)",
    0xE8: "StatisticsImpl::ToString",
    0xF0: "ticker-map fill (getTickerMap)",
    0xF8: "histogram-id check (HistEnabledForType)",
}

# Displacement-wide indirect-dispatch site counts from census.py
# (upper bounds on StatisticsImpl dispatches, not exact counts).
DISPATCH_SITES = {
    0x00: 43, 0x08: 2039, 0x10: 1808, 0x18: 4639, 0x20: 5149,
    0x28: 335, 0x30: 244, 0x38: 297, 0x40: 144, 0x48: 120, 0x50: 188,
    0x58: 17, 0x60: 177, 0x68: 321, 0x70: 85, 0x78: 55, 0x80: 180,
    0x88: 50, 0x90: 50, 0x98: 241, 0xA0: 522, 0xA8: 54, 0xB0: 400,
    0xB8: 36, 0xC0: 42, 0xC8: 29, 0xD0: 14, 0xD8: 48, 0xE0: 31,
    0xE8: 55, 0xF0: 38, 0xF8: 37,
}

# Number of vtables installing each shared base slot (RELATIVE
# counts from the packet census; the StatisticsImpl vtable is one
# of them).
SHARED_SLOT_VTABLE_COUNTS = {
    0x609D760: 63, 0x609DC40: 63, 0x5D32560: 66, 0x6095E70: 50,
    0x6096790: 64, 0x5D2E090: 62, 0x60956F0: 68, 0x609D0E0: 66,
    0x60986B0: 67, 0x6095710: 65, 0x609DE80: 50, 0x609D980: 63,
    0x5D32A30: 55, 0x5D2E770: 44, 0x5D2CA10: 45,
}

PCT_DIVISOR = 100.0
P50_CONST = 50.0
P75_CONST = 75.0
P95_CONST = 95.0
P99_CONST = 99.0
P99_9_CONST = 99.9
P99_99_CONST = 99.99
COUNT_FORMAT = "Count: %lu, Average: %.4f, StdDev: %.2f\n"
MIN_MAX_FORMAT = "Min: %lu, Median: %.2f, Max: %lu\n"
PERCENTILES_FORMAT = ("Percentiles: P50: %.2f P75: %.2f P99: %.2f "
                      "P99.9: %.2f P99.99: %.2f\n")
DASHES = ("------------------------------------------------------"
          "------------------------------------------------------\n")
BUCKET_FORMAT = "%s%lu, %lu] %9lu %7.2f%% %7.2f%% %s\n"
TICKER_LINE_FORMAT = "%s COUNT : %lu\n"
HISTOGRAM_LINE_FORMAT = ("%s P50 : %f P95 : %f P99 : %f "
                         "P100 : %f COUNT : %lu SUM : %lu\n")
LENGTH_ERROR_MESSAGE = "basic_string::_M_replace_aux"


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
BUCKET_COUNT = len(BOUNDARIES)


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


def u64_to_f64(value):
    """A u64 as a double, as the percentile code converts it."""
    return float(value & MASK64)


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


class LengthError(Exception):
    """std::length_error from basic_string::_M_replace_aux."""


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

    def merge(self, other):
        """Slot 0x28 (0x606bdf0 -> 0x606b1d0): merge a shard record.

        Only when the other record's name equals this one's
        (both "HistogramImpl"); min/max by comparison, count/sum/
        sum-of-squares/buckets by wrapping u64 addition.
        """
        if other.minimum < self.minimum:
            self.minimum = other.minimum
        if other.maximum > self.maximum:
            self.maximum = other.maximum
        self.count = (self.count + other.count) & MASK64
        self.total = (self.total + other.total) & MASK64
        self.total_sq = (self.total_sq + other.total_sq) & MASK64
        for index in range(self.bucket_count):
            self.buckets[index] = (
                self.buckets[index] + other.buckets[index]) & MASK64

    def percentile(self, pct):
        """0x606b260 (vtable slot 0x60, via thunk 0x606b530).

        threshold = count * (pct / 100.0); walk buckets until the
        running total reaches the threshold, then interpolate
        linearly between the neighbouring boundaries and clamp
        the result to [min, max]. An empty bucket contributes its
        lower boundary; running past the last bucket returns max.
        """
        threshold = u64_to_f64(self.count) * (pct / PCT_DIVISOR)
        cumulative = 0
        previous = 0
        for index in range(BUCKET_COUNT):
            cumulative = (cumulative + self.buckets[index]) & MASK64
            if u64_to_f64(cumulative) >= threshold:
                lower = 0 if index == 0 else BOUNDARIES[index - 1]
                upper = BOUNDARIES[index]
                bucket_count = self.buckets[index]
                if bucket_count == 0:
                    value = float(lower)
                else:
                    frac = ((threshold - u64_to_f64(previous))
                            / u64_to_f64(bucket_count))
                    value = float(lower) + frac * float(upper - lower)
                return min(max(value, u64_to_f64(self.minimum)),
                           u64_to_f64(self.maximum))
            previous = cumulative
        return u64_to_f64(self.maximum)

    def median(self):
        """0x606b500 (vtable slot 0x58, via thunk 0x606b520)."""
        return self.percentile(P50_CONST)

    def average(self):
        """0x606b540 (vtable slot 0x68, via thunk 0x606b5c0)."""
        if self.count == 0:
            return 0.0
        return u64_to_f64(self.total) / u64_to_f64(self.count)

    def stddev(self):
        """0x606b5d0 (vtable slot 0x70, via thunk 0x606b6b0).

        sqrt(max(0, (count*sumSq - sum*sum) / count*count));
        count == 0 returns 0.0.
        """
        if self.count == 0:
            return 0.0
        count_f = u64_to_f64(self.count)
        variance = (count_f * u64_to_f64(self.total_sq)
                    - u64_to_f64(self.total) * u64_to_f64(self.total))
        variance /= count_f * count_f
        if variance < 0.0:
            variance = 0.0
        return math.sqrt(variance)

    def percentile_struct(self):
        """0x606bce0 (vtable slot 0x78, via thunk 0x606bdd0).

        The 9-field struct the StatisticsImpl::ToString path
        prints: P50, P95, P99, average, stddev, P100 (= max),
        count, sum, min.
        """
        return {
            "p50": self.median(),
            "p95": self.percentile(P95_CONST),
            "p99": self.percentile(P99_CONST),
            "average": self.average(),
            "stddev": self.stddev(),
            "p100": u64_to_f64(self.maximum),
            "count": self.count,
            "sum": self.total,
            "min": u64_to_f64(self.minimum),
        }

    def render(self):
        """0x606b6f0 (vtable slot 0x30, via entry 0x606bc90).

        The Count line, the Min/Median/Max line (literal 0/0 when
        empty), the Percentiles line, the dashes separator, then
        one row per non-empty bucket with a '#' bar of one '#'
        per 5 percent (rounded) and a trailing newline.
        """
        out = ""
        line = COUNT_FORMAT % (self.count, self.average(), self.stddev())
        self._check_append_room(len(out), len(line))
        out += line
        if self.count != 0:
            line = MIN_MAX_FORMAT % (self.minimum, self.median(),
                                     self.maximum)
        else:
            line = MIN_MAX_FORMAT % (0, self.median(), 0)
        self._check_append_room(len(out), len(line))
        out += line
        line = PERCENTILES_FORMAT % (
            self.percentile(P50_CONST), self.percentile(P75_CONST),
            self.percentile(P99_CONST), self.percentile(P99_9_CONST),
            self.percentile(P99_99_CONST))
        self._check_append_room(len(out), len(line))
        out += line
        self._check_append_room(len(out), len(DASHES))
        out += DASHES
        if self.count == 0:
            return out
        per_unit = PCT_DIVISOR / u64_to_f64(self.count)
        cumulative = 0
        for index in range(BUCKET_COUNT):
            bucket = self.buckets[index]
            if bucket == 0:
                continue
            cumulative = (cumulative + bucket) & MASK64
            lower = 0 if index == 0 else BOUNDARIES[index - 1]
            upper = BOUNDARIES[index]
            bucket_pct = u64_to_f64(bucket) * per_unit
            cum_pct = u64_to_f64(cumulative) * per_unit
            char = "[" if index == 0 else "("
            hashes = "#" * int(round(bucket_pct / 5.0))
            line = BUCKET_FORMAT % (char, lower, upper, bucket,
                                    bucket_pct, cum_pct, hashes)
            self._check_append_room(len(out), len(line))
            out += line
        return out

    def _check_append_room(self, out_len, chunk_len):
        """The renderer's __throw_length_error guard."""
        if 0x3FFFFFFFFFFFFFFF - out_len < chunk_len:
            raise LengthError(LENGTH_ERROR_MESSAGE)


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
    """A StatisticsImpl object with its delegate chain.

    The constructor mirrors the ctor 0x6071a00: the level byte is
    3 (kExceptDetailedTimers), the shard store is built with the
    given shard_bits, the delegate is moved in from the caller's
    options. The object is destroyed by destroy() (D1, slot 0x00)
    or delete() (D0, slot 0x08, sized delete of 0x70 bytes).
    """

    def __init__(self, shard_bits=3, delegate=None, enabled=3):
        self.enabled = enabled       # +0x20 byte; ctor writes 3
        self.shard_bits = shard_bits  # +0x68 u8
        self.shards = [Shard() for _ in range(1 << shard_bits)]
        self.delegate = delegate     # +0x28 shared_ptr, None if null
        self.lock_depth = 0          # model lock accounting only
        self.lock_acquisitions = 0
        self.destroyed = False

    # -- identity slots --------------------------------------------
    def name(self):
        """Slot 0x70 (0x606fa20): "BasicStatistics"."""
        return STATISTICS_NAME

    def nickname(self):
        """Slot 0x90 (0x5d2ca10): "" (empty string)."""
        return STATISTICS_NICKNAME

    def get_id(self):
        """Slot 0x78 (0x5d32a30): Name() as a std::string."""
        return self.name()

    def is_instance_of(self, candidate):
        """Slot 0x80 (0x5d2e770): Name() or NickName() by length
        then memcmp; else 0."""
        if len(candidate) != len(self.name()) and \
                len(candidate) != len(self.nickname()):
            return False
        return candidate == self.name() or candidate == self.nickname()

    def delegate_ptr(self):
        """Slot 0x88 (0x606fa30): the delegate pointer, or None."""
        return self.delegate

    @staticmethod
    def hist_id_valid(hist_id):
        """Slot 0xf8 (0x606fa40): hist_id <= 0x33."""
        return hist_id <= 0x33

    # -- level inlines (non-virtual; the ctor is the single writer)
    def set_stats_level(self, level):
        """setStatsLevel: write the enable byte at +0x20."""
        self.enabled = level & 0xFF

    def get_stats_level(self):
        """getStatsLevel: read the enable byte at +0x20."""
        return self.enabled

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

    def _check_alive(self):
        if self.destroyed:
            raise RuntimeError("use of a destroyed StatisticsImpl")

    # -- slot 0x98: locked ticker read ------------------------------
    def get_ticker_count(self, ticker_id):
        """Slot 0x98 (0x6070490): lock, sum all shards, unlock."""
        self._check_alive()
        self._lock()
        try:
            return sum(s.tickers[ticker_id] for s in self.shards)
        finally:
            self._unlock()

    # -- slot 0xa0: locked histogram percentiles --------------------
    def get_histogram_data(self, hist_id):
        """Slot 0xa0 (0x6070610): lock, build a merged temp
        histogram over all shards, fill the 9-field struct."""
        self._check_alive()
        self._lock()
        try:
            temp = HistogramRecord()
            for shard in self.shards:
                temp.merge(shard.histograms[hist_id])
            return temp.percentile_struct()
        finally:
            self._unlock()

    # -- slot 0xa8: locked histogram text ---------------------------
    def get_histogram_string(self, hist_id):
        """Slot 0xa8 (0x6070700): lock, build a merged temp
        histogram over all shards, render its text form."""
        self._check_alive()
        self._lock()
        try:
            temp = HistogramRecord()
            for shard in self.shards:
                temp.merge(shard.histograms[hist_id])
            return temp.render()
        finally:
            self._unlock()

    # -- slot 0xb0: lock-free record tick ---------------------------
    def record_tick(self, ticker_id, value, cpu=None, seed=None):
        """Slot 0xb0 (0x606fba0): gate, pick, lock-add, forward."""
        self._check_alive()
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
        self._check_alive()
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
        self._check_alive()
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

    # -- slot 0xc8: level-3-only histogram forward ------------------
    def measure_time(self, hist_id, value, cpu=None, seed=None):
        """Slot 0xc8 (0x5d48960): level > 2, else return silently;
        then tail-jump to this's slot 0xd8 with the same args."""
        self._check_alive()
        if self.enabled <= 2:
            return
        self.record_histogram(hist_id, value, cpu, seed)

    # -- slot 0xd8 / 0xd0: lock-free record histogram ---------------
    def record_histogram(self, hist_id, value, cpu=None, seed=None):
        """Slot 0xd8 (0x606fef0): gate (> 1), pick, record, forward
        to the delegate's slot 0xd8 when hist_id <= 0x33."""
        self._check_alive()
        if self.enabled <= 1:
            return
        shard = self._pick_shard(cpu, seed)
        self.shards[shard].histograms[hist_id].record(value)
        if hist_id <= 0x33 and self.delegate is not None:
            self.delegate.record_histogram(hist_id, value, cpu, seed)

    def record_histogram_devirt(self, hist_id, value, cpu=None,
                                seed=None):
        """Slot 0xd0 (0x606ffd0): when this's own slot 0xd8 is the
        local 0x606fef0 the body is inlined; otherwise dispatch
        virtually to the overriding slot 0xd8."""
        self._check_alive()
        if type(self).record_histogram is not \
                StatisticsImpl.record_histogram:
            self.record_histogram(hist_id, value, cpu, seed)
            return
        self.record_histogram(hist_id, value, cpu, seed)

    # -- slot 0xe0: reset -------------------------------------------
    def reset(self):
        """Slot 0xe0 (0x6070b30): locked zero + re-init; Status OK."""
        self._check_alive()
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

    # -- slot 0xe8: ToString ----------------------------------------
    def to_string(self, ticker_names, hist_names):
        """Slot 0xe8 (0x6070810): one COUNT line per ticker, one
        P50/P95/P99/P100 line per histogram, from the shard sums
        and the merged histogram structs. The caller passes the
        name tables (the ticker-name table at 0x432248 in the
        binary; the histogram names are the caller's)."""
        self._check_alive()
        out = ""
        self._lock()
        try:
            for ticker_id, name in enumerate(ticker_names):
                total = sum(s.tickers[ticker_id] for s in self.shards)
                out += TICKER_LINE_FORMAT % (name, total)
            for hist_id, name in enumerate(hist_names):
                data = self.get_histogram_data_unlocked(hist_id)
                out += HISTOGRAM_LINE_FORMAT % (
                    name, data["p50"], data["p95"], data["p99"],
                    data["p100"], data["count"], data["sum"])
        finally:
            self._unlock()
        return out

    def get_histogram_data_unlocked(self, hist_id):
        """The slot-0xa0 body without the lock (used by ToString,
        which already holds the mutex)."""
        temp = HistogramRecord()
        for shard in self.shards:
            temp.merge(shard.histograms[hist_id])
        return temp.percentile_struct()

    # -- slot 0xf0: ticker-map fill ---------------------------------
    def get_ticker_map(self, ticker_names):
        """Slot 0xf0 (0x6076030): lock, fill a name -> value map
        with one entry per ticker (shard-sum getter)."""
        self._check_alive()
        out = {}
        self._lock()
        try:
            for ticker_id, name in enumerate(ticker_names):
                out[name] = sum(s.tickers[ticker_id]
                                for s in self.shards)
        finally:
            self._unlock()
        return out

    # -- slots 0x00 / 0x08: destructors ----------------------------
    def destroy(self):
        """Slot 0x00 D1 (0x6070ea0): reinstall the vptr, destroy
        the histogram records, free the store, destroy the mutex,
        release the delegate shared_ptr, destroy the options
        vector. The model marks the object destroyed."""
        self._check_alive()
        self.shards = []
        self.delegate = None
        self.destroyed = True

    def delete(self):
        """Slot 0x08 D0 (0x6071040): D1, then sized delete of
        0x70 bytes (_ZdlPvm(this, 0x70))."""
        self.destroy()
        return SIZEOF_STATISTICS_IMPL
