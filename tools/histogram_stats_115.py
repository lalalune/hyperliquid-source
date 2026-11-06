"""Python model of the node #115 HistogramImpl statistics family.

Reconstructed from the node #115 binary (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301)
under RE-001; evidence packet
research/work-items/RE-001-histogram-stats-family-115/.

Object layout (the HistogramImpl object, 0x3c8 bytes; the
statistics struct starts at +0x08, i.e. the `inner` pointer
the vtable thunks adjust `this` to):
    inner+0x00  min (u64, initialised to the last boundary)
    inner+0x08  max (u64, initialised to 0)
    inner+0x10  count (u64)
    inner+0x18  sum (u64)
    inner+0x20  sum of squares (u64)
    inner+0x28  buckets[0..108] (u64 each)
    inner+0x390 bucket count (u64, 109)
    obj+0x3a0   pthread mutex (40 bytes, to 0x3c8)

Routines modelled (addresses are node #115 .text):
    0x606bf10 boundary generator, 0x606c140 static init,
    0x606af70 vector dtor, 0x606afa0 bucket index,
    0x606b020 shared init, 0x606b080 bucket-count init,
    0x606b0c0 locked init, 0x606b110 empty check,
    0x606b130 record, 0x606b1d0 lock merge,
    0x606b260 percentile core, 0x606b500 P50,
    0x606b540 average, 0x606b5d0 stddev,
    0x606b6f0 full text renderer, 0x606bc90 ToString entry,
    0x606be40 merge entry, 0x606af40/50/60 name/min/max
    accessors, 0x606bce0 percentile struct (re-shipped).

Unsigned 64-bit arithmetic wraps (the binary adds with plain
64-bit `add`); doubles use the binary's unsigned-conversion
fixup (`shr $1` + `or` + `addsd` doubling), which is
round-to-nearest-even, identical to a direct u64->double
conversion.
"""

import math

MASK64 = (1 << 64) - 1
TWO63 = 1 << 63
TWO64 = 1 << 64

# Double constants read from the binary (.rodata).
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

# Format strings read from the binary (.rodata).
COUNT_FORMAT = "Count: %lu Average: %.4f  StdDev: %.2f\n"          # 0x9663a0
MIN_MAX_FORMAT = "Min: %lu  Median: %.4f  Max: %lu\n"              # 0x964d10
PERCENTILES_FORMAT = ("Percentiles: P50: %.2f P75: %.2f P99: %.2f "
                      "P99.9: %.2f P99.99: %.2f\n")                 # 0x959298
DASHES = "------------------------------------------------------\n"  # 0x959b38
BUCKET_FORMAT = "%c %7lu, %7lu ] %8lu %7.3f%% %7.3f%% "           # 0x966d98
LENGTH_ERROR_MESSAGE = "basic_string::append"  # 0x4474d2


class LengthError(Exception):
    """Raised where the binary throws __throw_length_error."""


def u64_to_f64(value):
    """Unsigned u64 -> double exactly as the binary does it.

    Values below 2**63 convert directly; values at or above use
    the (x >> 1 | x & 1) conversion doubled (0x606b3c0-style
    fixup), which is round-to-nearest-even.
    """
    value &= MASK64
    if value < TWO63:
        return float(value)
    return float((value >> 1) | (value & 1)) * 2.0


def _truncate_boundary(value):
    """The 0x606bf10 rounding step for a just-pushed boundary.

    Values at or below 109 keep exact. Larger values are divided
    by 10 (counting a factor of 10 each time) while the
    pre-division value exceeds 1099, then multiplied back by the
    accumulated factor -- i.e. truncated to the top 2-3 digits.
    """
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
    """Reproduce the 0x606bf10 static boundary generator.

    Seeds [1, 2] from .rodata 0x453950; then repeatedly pushes
    (u64)cur with cur starting at 2 * 1.5, rounding each pushed
    value with _truncate_boundary, and multiplying cur by 1.5
    until cur * 1.5 reaches 2**64. Returns the boundary list;
    its length is the bucket count (109) and its last entry is
    the ceiling stored at the statics +0x18 (the initial min).
    """
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
    """0x606afa0: first index j with BOUNDARIES[j] >= value.

    Values at or above the ceiling go to the last bucket
    (count - 1); the binary search is std::lower_bound.
    """
    value &= MASK64
    if value >= CEILING:
        return BUCKET_COUNT - 1
    lo, hi = 0, BUCKET_COUNT
    while lo < hi:
        mid = (lo + hi) // 2
        if BOUNDARIES[mid] >= value:
            hi = mid
        else:
            lo = mid + 1
    return lo


class Histogram:
    """One HistogramImpl statistics struct (the `inner` object)."""

    def __init__(self):
        # 0x606b020: min = ceiling, max/count/sum/sumSq = 0,
        # buckets zeroed; bucket count set by 0x606b080.
        self.min = CEILING
        self.max = 0
        self.count = 0
        self.sum = 0
        self.sum_sq = 0
        self.buckets = [0] * BUCKET_COUNT

    def name(self):
        """0x606af40 (vtable slot 0x38)."""
        return "HistogramImpl"

    def is_empty(self):
        """0x606b110 (vtable slot 0x18, via thunk 0x606b120)."""
        return self.count == 0

    def min_value(self):
        """0x606af50 (vtable slot 0x40)."""
        return self.min

    def max_value(self):
        """0x606af60 (vtable slot 0x48)."""
        return self.max

    def add(self, value):
        """0x606b130 (vtable slot 0x20, via thunk 0x606b1c0).

        Bucket from 0x606afa0; min/max by comparison; count,
        sum and sum-of-squares by wrapping u64 addition.
        """
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
        """0x606b5d0 (vtable slot 0x70, via thunk 0x606b6b0).

        sqrt(max(0, (count*sumSq - sum*sum) / count*count));
        count == 0 returns 0.0.
        """
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
            "p100": u64_to_f64(self.max),
            "count": self.count,
            "sum": self.sum,
            "min": u64_to_f64(self.min),
        }

    def merge(self, other):
        """0x606be40 + 0x606bdf0 + 0x606b1d0 (vtable slot 0x28).

        Merges only when the other histogram's name equals this
        one's (the slot-0x28 entry compares names, defaulting to
        "HistogramImpl"); min/max by comparison, count/sum/
        sum-of-squares/buckets by wrapping u64 addition. The
        binary does the updates under the histogram mutex with
        lock cmpxchg / lock add; the model performs the same
        updates plainly.
        """
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
        """0x606b6f0 (vtable slot 0x30, via entry 0x606bc90).

        Builds the full text form into a fresh string: the Count
        line, the Min/Median/Max line (literal 0/0 when empty),
        the Percentiles line, the dashes separator, then one row
        per non-empty bucket with a '#' bar of one '#' per 5
        percent (rounded) and a trailing newline.
        """
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
