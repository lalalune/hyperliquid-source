"""Python model of the node #115 StatisticsImpl locked read accessors.

Reconstructed from the node #115 binary (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301)
under RE-001; evidence packet
research/work-items/RE-001-locked-ticker-read-115/.

The three routines pinned here are the StatisticsImpl vtable
slots 0x98/0xa0/0xa8 (primary vtable 0x64d2d88, typeinfo
N7rocksdb14StatisticsImplE, base N7rocksdb10StatisticsE):
    0x6070490  slot 0x98  locked ticker count
    0x6070610  slot 0xa0  locked histogram percentiles
    0x6070700  slot 0xa8  locked histogram text (sret)
All three share one discipline: lock the mutex at this+0x38,
delegate to an unlocked helper (the ticker getter 0x6070430 or
the histogram builder 0x6070500), unlock, and on any exception
unlock (destroying the built temp first when one exists) and
resume unwinding. The two internal callers of the raw getter
(ToString 0x6070810 and the slot-0xf0 fill 0x6076030) call it
directly because they already hold the lock; the three slots
here are the public thread-safe path and are reached only
through the vtable (zero direct calls anywhere in the binary).

Object layout (StatisticsImpl, from #3362/#3378/#3386):
    this+0x20  u8 enabled flag (slot-0xb0 record gate)
    this+0x28  StatisticsOptions record pointer
    this+0x38  pthread mutex (the lock these accessors take)
    this+0x60  shard-store base pointer
    this+0x68  u8 shard_bits; shard count is 2**shard_bits
    shard s is 0xce40 bytes at base + s*0xce40
    shard+id*8         u64 ticker counter for ticker id
    shard+0x598+id*0x3c8  HistogramImpl record for histogram id
    (0x598 + 53*0x3c8 == 0xce00, leaving a 0x40 tail per shard
    whose contents are an open unknown)

The HistogramImpl snapshot semantics (boundaries, percentile
interpolation, text rendering) follow the RE-001-histogram-
stats-family-115 packet (#3371); the percentile struct is the
9-field record of 0x606bce0 (vtable slot 0x78) and the text is
the 0x606b6f0 renderer (vtable slot 0x30).

Unsigned 64-bit arithmetic wraps (the binary adds with plain
64-bit `add`); doubles use the binary's unsigned-conversion
fixup, which is round-to-nearest-even, identical to a direct
u64->double conversion.
"""

import math

MASK64 = (1 << 64) - 1
TWO63 = 1 << 63
TWO64 = 1 << 64

TARGET_SHA256 = ("a6e2897cd051213d004802deca416e8eca62b7a8278fa39f"
                 "249e98c3867b5301")

# StatisticsImpl primary vtable (0x64d2d88) and its three locked
# reads. The full 32-slot table is STATISTICS_IMPL_VTABLE below.
STATISTICS_IMPL_VTABLE = 0x64D2D88
STATISTICS_IMPL_TYPEINFO = 0x64D2CF8
STATISTICS_IMPL_TYPEINFO_NAME = "N7rocksdb14StatisticsImplE"
STATISTICS_TYPEINFO = 0x64D2CE0
STATISTICS_TYPEINFO_NAME = "N7rocksdb10StatisticsE"
LOCKED_TICKER_READ = 0x6070490       # slot 0x98
LOCKED_PERCENTILES = 0x6070610       # slot 0xa0
LOCKED_HISTOGRAM_TEXT = 0x6070700    # slot 0xa8
TICKER_GETTER = 0x6070430
HISTOGRAM_BUILDER = 0x6070500
MUTEX_LOCK = 0x60D5230
MUTEX_UNLOCK = 0x60D52F0
SIZED_DELETE = 0x5D8B3B0             # GOT slot 0x64ed2f0
TOSTRING = 0x6070810                 # slot 0xe8
TICKER_MAP_FILL = 0x6076030          # slot 0xf0

# Shard-store layout.
SHARD_SIZE = 0xCE40
SHARD_BITS_MAX = 8                   # observed; see README unknowns
HISTOGRAM_BASE = 0x598
HISTOGRAM_SIZE = 0x3C8
TICKER_MAX = 0xB1                    # slot-0xb0 record gate (cited)

# Double constants read from the binary (.rodata), as in #3371.
PCT_DIVISOR = 100.0        # 0x459498, percentile threshold divisor
P50_CONST = 50.0           # 0x459950
P75_CONST = 75.0           # 0x459c50
P95_CONST = 95.0           # 0x459640
P99_CONST = 99.0           # 0x459258
P99_9_CONST = 99.9         # 0x459ce8
P99_99_CONST = 99.99       # 0x459080
GROWTH_FACTOR = 1.5        # 0x4596c8, boundary generator multiplier
BOUNDARY_SEED0 = 1         # .rodata 0x453950, first qword
BOUNDARY_SEED1 = 2         # .rodata 0x453958, second qword
ROUND_KEEP_BELOW = 109     # 0x6d, values at or below keep exact
ROUND_LOOP_LIMIT = 1099    # 0x44b, divide-while-above limit
HASH_BAR_DIVISOR = 5.0     # 0x4593d0, one '#' per 5 percent
HASH_BAR_HALF = 0.5        # 0x459490, round-to-nearest for the bar

# Format strings read from the binary (.rodata), as in #3371.
COUNT_FORMAT = "Count: %lu Average: %.4f  StdDev: %.2f\n"          # 0x9663a0
MIN_MAX_FORMAT = "Min: %lu  Median: %.4f  Max: %lu\n"              # 0x964d10
PERCENTILES_FORMAT = ("Percentiles: P50: %.2f P75: %.2f P99: %.2f "
                      "P99.9: %.2f P99.99: %.2f\n")                 # 0x959298
DASHES = "------------------------------------------------------\n"  # 0x959b38
BUCKET_FORMAT = "%c %7lu, %7lu ] %8lu %7.3f%% %7.3f%% "           # 0x966d98
LENGTH_ERROR_MESSAGE = "basic_string::append"  # 0x4474d2

# Indirect virtual-dispatch sites through each slot's
# displacement, counted by the packet census over the whole
# binary. Displacement-wide, not type-attributed: any class with
# a slot at that displacement contributes, so these are upper
# bounds on StatisticsImpl dispatches, not exact caller counts.
DISPATCH_SITES = {0x98: 241, 0xA0: 522, 0xA8: 54}

# The StatisticsImpl primary vtable: slot offset -> routine.
# Re-derived from the RELATIVE records in relocations.txt.
STATISTICS_IMPL_VTABLE_SLOTS = {
    0x00: 0x6070EA0, 0x08: 0x6071040, 0x10: 0x609D760,
    0x18: 0x609DC40, 0x20: 0x5D32560, 0x28: 0x6095E70,
    0x30: 0x6096790, 0x38: 0x5D2E090, 0x40: 0x60956F0,
    0x48: 0x609D0E0, 0x50: 0x60986B0, 0x58: 0x6095710,
    0x60: 0x609DE80, 0x68: 0x609D980, 0x70: 0x606FA20,
    0x78: 0x5D32A30, 0x80: 0x5D2E770, 0x88: 0x606FA30,
    0x90: 0x5D2CA10, 0x98: 0x6070490, 0xA0: 0x6070610,
    0xA8: 0x6070700, 0xB0: 0x606FBA0, 0xB8: 0x6070DC0,
    0xC0: 0x6070C50, 0xC8: 0x5D48960, 0xD0: 0x606FFD0,
    0xD8: 0x606FEF0, 0xE0: 0x6070B30, 0xE8: 0x6070810,
    0xF0: 0x6076030, 0xF8: 0x606FA40,
}

# Vtables that follow the primary vtable in the group (their
# typeinfo slots sit at primary +0x108/+0x138/+0x170). They are
# not StatisticsImpl slots; only their identities are recorded.
FOLLOWING_VTABLES = {
    0x64D2E98: ("N7rocksdb13ObjectLibrary12FactoryEntryINS_10StatisticsEEE",
                0x64D2D10),
    0x64D2EC8: ("St15_Sp_counted_ptrIPN7rocksdb14StatisticsImplELN9__gnu_cxx12_Lock_policyE2EE",
                0x64D2D48),
    0x64D2F00: ("St15_Sp_counted_ptrIPN7rocksdb10StatisticsELN9__gnu_cxx12_Lock_policyE2EE",
                0x64D2D60),
}


class LengthError(Exception):
    """Raised where the binary throws __throw_length_error."""


class MutexError(Exception):
    """Model-level misuse: the binary would deadlock (double lock)
    or unlock an unheld mutex instead of raising."""


def u64_to_f64(value):
    """Unsigned u64 -> double exactly as the binary does it."""
    value &= MASK64
    if value < TWO63:
        return float(value)
    return float((value >> 1) | (value & 1)) * 2.0


def _truncate_boundary(value):
    """The 0x606bf10 rounding step for a just-pushed boundary."""
    if value <= ROUND_KEEP_BELOW:
        return value
    factor = 1
    current = value
    while True:
        previous = current
        factor *= 10
        current //= 10
        if previous <= ROUND_LOOP_LIMIT:
            break
    return factor * current


def generate_boundaries():
    """Reproduce the 0x606bf10 static boundary generator."""
    boundaries = [BOUNDARY_SEED0, BOUNDARY_SEED1]
    cur = float(BOUNDARY_SEED1) * GROWTH_FACTOR
    while True:
        if cur < float(TWO63):
            pushed = int(cur)  # cvttsd2si truncates toward zero
        else:
            pushed = (int(cur - float(TWO63)) ^ TWO63) & MASK64
        boundaries.append(_truncate_boundary(pushed))
        cur = cur * GROWTH_FACTOR
        if TWO64 < cur:
            break
    return boundaries


BOUNDARIES = generate_boundaries()
BUCKET_COUNT = len(BOUNDARIES)  # 109; 0x28 + 109*8 == 0x390
CEILING = BOUNDARIES[-1]        # statics +0x18; the initial min
FIRST_BOUNDARY = BOUNDARIES[0]  # statics +0x20


def bucket_index(value):
    """0x606afa0: first index j with BOUNDARIES[j] >= value."""
    value &= MASK64
    if value >= CEILING:
        return BUCKET_COUNT - 1
    lo, hi = 0, BUCKET_COUNT
    while lo < hi:
        mid = (lo + hi) // 2
        if BOUNDARIES[mid] < value:
            lo = mid + 1
        else:
            hi = mid
    return lo


class Histogram:
    """One HistogramImpl statistics struct (the `inner` object).

    Layout (from #3362/#3371): min/max/count/sum/sumSq at
    inner+0x00/+0x08/+0x10/+0x18/+0x20, buckets[0..108] at
    inner+0x28, bucket count at inner+0x390, mutex at obj+0x3a0.
    """

    def __init__(self):
        # 0x606b020: min = ceiling, max/count/sum/sumSq = 0,
        # buckets zeroed; bucket count set by 0x606b080.
        self.min = CEILING
        self.max = 0
        self.count = 0
        self.sum = 0
        self.sum_sq = 0
        self.buckets = [0] * BUCKET_COUNT
        self.destroyed = False

    def name(self):
        """0x606af40 (vtable slot 0x38)."""
        return "HistogramImpl"

    def is_empty(self):
        """0x606b110 (vtable slot 0x18, via thunk 0x606b120)."""
        return self.count == 0

    def add(self, value):
        """0x606b130 (vtable slot 0x20, via thunk 0x606b1c0)."""
        value &= MASK64
        index = bucket_index(value)
        self.buckets[index] = (self.buckets[index] + 1) & MASK64
        if value < self.min:
            self.min = value
        if value > self.max:
            self.max = value
        self.count = (self.count + 1) & MASK64
        self.sum = (self.sum + value) & MASK64
        self.sum_sq = (self.sum_sq + value * value) & MASK64

    def percentile(self, pct):
        """0x606b260 (vtable slot 0x60, via thunk 0x606b530)."""
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
                    frac = (threshold - u64_to_f64(previous)) / u64_to_f64(bucket_count)
                    value = float(lower) + frac * float(upper - lower)
                return min(max(value, u64_to_f64(self.min)),
                           u64_to_f64(self.max))
            previous = cumulative
        return u64_to_f64(self.max)

    def median(self):
        """0x606b500 (vtable slot 0x58, via thunk 0x606b520)."""
        return self.percentile(P50_CONST)

    def average(self):
        """0x606b540 (vtable slot 0x68, via thunk 0x606b5c0)."""
        if self.count == 0:
            return 0.0
        return u64_to_f64(self.sum) / u64_to_f64(self.count)

    def stddev(self):
        """0x606b5d0 (vtable slot 0x70, via thunk 0x606b6b0)."""
        if self.count == 0:
            return 0.0
        count_f = u64_to_f64(self.count)
        variance = (count_f * u64_to_f64(self.sum_sq)
                    - u64_to_f64(self.sum) * u64_to_f64(self.sum))
        variance /= count_f * count_f
        if variance < 0.0:
            variance = 0.0
        return math.sqrt(variance)

    def percentile_struct(self):
        """0x606bce0 (vtable slot 0x78, via thunk 0x606bdd0)."""
        return {
            "p50": self.median(),
            "p95": self.percentile(P95_CONST),
            "p99": self.percentile(P99_CONST),
            "average": self.average(),
            "stddev": self.stddev(),
            "p100": u64_to_f64(self.max),
            "count": self.count,
            "sum": self.sum,
            "min": u64_to_f64(self.min),
        }

    def merge(self, other):
        """0x606be40 + 0x606bdf0 + 0x606b1d0 (vtable slot 0x28)."""
        if other.name() != self.name():
            return False
        if other.min < self.min:
            self.min = other.min
        if other.max > self.max:
            self.max = other.max
        self.count = (self.count + other.count) & MASK64
        self.sum = (self.sum + other.sum) & MASK64
        self.sum_sq = (self.sum_sq + other.sum_sq) & MASK64
        for index in range(BUCKET_COUNT):
            self.buckets[index] = (
                self.buckets[index] + other.buckets[index]) & MASK64
        return True

    def _check_append_room(self, out_len, chunk_len):
        """The renderer's __throw_length_error guard."""
        if 0x3FFFFFFFFFFFFFFF - out_len < chunk_len:
            raise LengthError(LENGTH_ERROR_MESSAGE)

    def render(self):
        """0x606b6f0 (vtable slot 0x30, via entry 0x606bc90)."""
        out = ""
        line = COUNT_FORMAT % (self.count, self.average(), self.stddev())
        self._check_append_room(len(out), len(line))
        out += line
        if self.count != 0:
            line = MIN_MAX_FORMAT % (self.min, self.median(), self.max)
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
            line = BUCKET_FORMAT % (char, lower, upper, bucket,
                                    bucket_pct, cum_pct)
            self._check_append_room(len(out), len(line))
            out += line
            bar = int(bucket_pct / HASH_BAR_DIVISOR + HASH_BAR_HALF)
            out += "#" * bar
            out += "\n"
        return out


class Statistics:
    """A StatisticsImpl object: shard store plus the mutex.

    The shard store is a list of per-shard dicts (counters and
    histogram records), standing in for the binary's flat
    0xce40-byte shards at *(this+0x60). The lock discipline is
    modelled explicitly: _lock/_unlock track the held state and
    the accessors mirror the binary's landing pads (unlock, and
    destroy the temp when one was built, before resuming the
    exception).
    """

    def __init__(self, shard_bits=0):
        self.shard_bits = shard_bits
        self.shards = [
            {"counters": {}, "histograms": {}}
            for _ in range(1 << shard_bits)
        ]
        self._locked = False
        self.lock_events = []  # ("lock"/"unlock", routine) in order
        self.destroyed_temps = 0

    @property
    def shard_count(self):
        return 1 << self.shard_bits

    def set_ticker(self, shard, index, value):
        """Seed a shard counter (test/setup helper)."""
        self.shards[shard]["counters"][index & MASK64] = value & MASK64

    def set_histogram(self, shard, hist_id, histogram):
        """Seed a shard histogram record (test/setup helper)."""
        self.shards[shard]["histograms"][hist_id] = histogram

    def _lock(self, routine):
        if self._locked:
            raise MutexError("double lock (the binary would deadlock)")
        self._locked = True
        self.lock_events.append(("lock", routine))

    def _unlock(self, routine):
        if not self._locked:
            raise MutexError("unlock of an unheld mutex")
        self._locked = False
        self.lock_events.append(("unlock", routine))

    def ticker_getter(self, index):
        """0x6070430: sum over 2**shard_bits shards of the u64 at
        shard_base + shard*0xce40 + index*8 (index zero-extended
        from u32). Unlocked; the three locked reads and the two
        internal callers are the only users."""
        index &= 0xFFFFFFFF
        total = 0
        for shard in self.shards:
            total = (total + shard["counters"].get(index, 0)) & MASK64
        return total

    def locked_ticker_read(self, index):
        """0x6070490 (vtable slot 0x98): lock this+0x38, call the
        getter, unlock, return the sum. The landing pad at
        0x607047e unlocks and resumes on exception."""
        self._lock("locked_ticker_read")
        try:
            value = self.ticker_getter(index)
        except Exception:
            self._unlock("locked_ticker_read")
            raise
        self._unlock("locked_ticker_read")
        return value

    def build_histogram(self, hist_id):
        """0x6070500: allocate a fresh 0x3c8-byte HistogramImpl,
        initialise it, and merge each shard's record for hist_id
        (at shard + 0x598 + hist_id*0x3c8) via 0x606bdf0. The
        merge step has no throwing operation in the binary, so a
        build failure means no temp was published."""
        temp = Histogram()
        for shard in self.shards:
            record = shard["histograms"].get(hist_id)
            if record is not None:
                temp.merge(record)
        return temp

    def _destroy_temp(self, temp):
        """The sized-delete fast path (GOT 0x64ed2f0 holds the
        sized delete 0x5d8b3b0): the temp's deleting dtor is the
        standard one, so the binary frees it with _ZdlPvm 0x3c8
        instead of calling the dtor."""
        if temp.destroyed:
            raise MutexError("double destroy of a histogram temp")
        temp.destroyed = True
        self.destroyed_temps += 1

    def locked_percentiles(self, hist_id):
        """0x6070610 (vtable slot 0xa0): lock, build the temp,
        fill the caller's struct through the temp's vtable slot
        0x78 (percentile struct 0x606bce0), destroy the temp,
        unlock. Exceptions from the builder use the unlock-only
        pad (0x60705e7); exceptions after the build use the
        delete+unlock pad (0x60705d8)."""
        self._lock("locked_percentiles")
        temp = None
        try:
            temp = self.build_histogram(hist_id)
            out = temp.percentile_struct()
        except Exception:
            if temp is not None:
                self._destroy_temp(temp)
            self._unlock("locked_percentiles")
            raise
        self._destroy_temp(temp)
        self._unlock("locked_percentiles")
        return out

    def locked_histogram_text(self, hist_id):
        """0x6070700 (vtable slot 0xa8): lock the SECOND argument's
        mutex (the stats object arrives in rsi; rdi is the sret
        out-string, returned unchanged), build the temp, render
        into the out string through the temp's vtable slot 0x30
        (renderer 0x606b6f0), destroy the temp, unlock. Pads are
        the mirror of slot 0xa0 (0x60706ca delete+unlock,
        0x60706d9 unlock-only)."""
        self._lock("locked_histogram_text")
        temp = None
        try:
            temp = self.build_histogram(hist_id)
            out = temp.render()
        except Exception:
            if temp is not None:
                self._destroy_temp(temp)
            self._unlock("locked_histogram_text")
            raise
        self._destroy_temp(temp)
        self._unlock("locked_histogram_text")
        return out
