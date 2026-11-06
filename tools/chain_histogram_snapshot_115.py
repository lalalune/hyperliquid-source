"""Python model of RE-001 chain-histogram snapshot (node #115).

Models the behaviour pinned by research/work-items/
RE-001-chain-histogram-snapshot-115/ from the digest-verified work
binary (SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):
HashLinkListRep slot 0x90 (0x605feb0) rebuilds its entry index, measures
the per-bucket chain-length distribution into a stack HistogramImpl, renders
it and logs it. The model implements only the semantics established in the
packet; virtual dispatches (the slot-0x20 size source, the slot-0x18 node
allocator, the slot-0x08 comparator, the logger's slots) are injected as
callables, and the HistogramImpl record/render rules follow open PR #3371.
"""

import math

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# ---------------------------------------------------------------------------
# 0x605cfa0: block-size normalizer
# ---------------------------------------------------------------------------


def normalize_block_size(n):
    """Clamp to [0x1000, 0x80000000) then round up to a multiple of 16.

    n <= 0x1000 -> 0x1000; n >= 0x80000000 -> 0x1000; otherwise the
    smallest multiple of 16 >= n.
    """
    n &= (1 << 64) - 1
    if n <= 0x1000:
        return 0x1000
    if n >= 0x80000000:
        return 0x1000
    if n & 0xF:
        return (n & ~0xF) + 0x10
    return n


# ---------------------------------------------------------------------------
# 0x61c4080: per-thread hash seed (libstdc++ _Hash_bytes over pthread_self)
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
    the cached value. The insert advances the cached value in place.
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
    """One 0x41a7 multiply mod (2**31 - 1), exactly as 0x605f340 does it.

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


def advance_seed(seed, step, count):
    """The insert's rehash seed advance (0x605f340, 0x605f4bc..0x605f529).

    Returns (new_seed, new_size). When count <= 1 the loop is skipped
    and the size stays 1. Otherwise the seed is multiplied until it
    reaches step (size = iterations + 1) or the iteration count hits
    count (size = iterations + 2).
    """
    if count <= 1:
        return seed, 1
    r12 = 1
    while True:
        seed = mersenne_step(seed)
        ecx = r12 + 1
        if seed >= step:
            return seed, ecx
        if ecx == count:
            return seed, r12 + 2
        r12 = ecx


# ---------------------------------------------------------------------------
# HistogramImpl record/render rules (pinned by open PR #3371)
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
    """The HistogramImpl inner record (0x606b130) plus the ToString
    renderer (0x606b6f0) as documented by #3371."""

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

    def render(self):
        """The renderer's exact line shapes (see #3371)."""
        lines = []
        lines.append("Count: %d Average: %.4f  StdDev: %.2f\n"
                     % (self.count, self.average(), self.stddev()))
        if self.count:
            lines.append("Min: %d  Median: %.4f  Max: %d\n"
                         % (self.min, self.median(), self.max))
        else:
            lines.append("Min: %d  Median: %.4f  Max: %d\n"
                         % (0, 0.0, 0))
        lines.append("Percentiles: P50: %.2f P75: %.2f P99: %.2f "
                     "P99.9: %.2f P99.99: %.2f\n"
                     % (self.percentile(50.0), self.percentile(75.0),
                        self.percentile(99.0), self.percentile(99.9),
                        self.percentile(99.99)))
        lines.append("-" * 54 + "\n")
        cum = 0
        for i, c in enumerate(self.buckets):
            if c == 0:
                continue
            pct = 100.0 * c / self.count
            cum += c
            cum_pct = 100.0 * cum / self.count
            lo = 0 if i == 0 else BOUNDARIES[i - 1]
            lines.append("%c %7d, %7d ] %8d %7.3f%% %7.3f%% %s\n"
                         % ("[" if i == 0 else "(", lo, BOUNDARIES[i], c,
                            pct, cum_pct, "#" * round(pct / 5)))
        return "".join(lines)


# ---------------------------------------------------------------------------
# 0x605dd90: rocksdb::Arena (observable state only)
# ---------------------------------------------------------------------------


class Arena:
    """The Arena built by 0x605dd90 (vtable 0x64d1fb8).

    block_size is the normalized hint; each of the two tables holds a
    64-byte slot block and a 512-byte data block; the tail struct
    carries the 0x800 constants and the rounded arg4.
    """

    SIZE = 0x8F0

    def __init__(self, size_hint, arg3=0, arg4=0):
        self.normalized_size = normalize_block_size(size_hint)
        self.slot_blocks = 2  # two 64-byte blocks (8 slots each)
        self.data_blocks = 2  # two 512-byte blocks
        self.tail = {
            "size_ptr": "out+0x810",
            "base_ptr": "out+0x10",
            "const_a": 0x800,
            "rounded_arg4": (arg4 if arg4 == 0 or arg4 >= self.normalized_size
                             else ((self.normalized_size - 1) // arg4 + 1) * arg4),
            "const_b": 0x800,
            "arg3": arg3,
        }
        self.counter_add_calls = []
        if arg3 != 0:
            # counter_add 0x605e830(arg3, 0x800)
            self.counter_add_calls.append((arg3, 0x800))


# ---------------------------------------------------------------------------
# 0x605f290 / 0x605f340: the 0x38-byte index
# ---------------------------------------------------------------------------


class Index38:
    """The index built by 0x605f290 and grown by 0x605f340.

    count/divisor/step mirror the struct fields; array A holds
    count+1 zeroed head slots, array B holds count tail pointers all
    starting at A; insert appends keys to per-bucket chains ordered by
    the injected comparator, advancing the shared thread seed and
    growing the arrays exactly as the binary's arithmetic dictates.
    """

    SIZE = 0x38

    def __init__(self, count, divisor, key_obj, allocator, thread_seed):
        self.count = count
        self.divisor = divisor
        self.step = 0x80000000 // divisor
        self.key_obj = key_obj
        self.allocator = allocator
        self.thread_seed = thread_seed
        self.array_a = [None] * (count + 1)  # heads, zeroed
        self.array_b = [self.array_a] * count  # tails, all start at A
        self.capacity = 1  # +0x20
        self.size_marker = 1  # +0x30
        self.chains = {}  # bucket -> ordered list of keys

    def _bucket_for(self, key):
        return (key * 0x41A7) % 0x7FFFFFFF % max(self.count, 1)

    def insert(self, key, comparator):
        """Insert one key; returns the bucket it landed in."""
        bucket = self._bucket_for(key)
        chain = self.chains.setdefault(bucket, [])
        # Ordered insert by the comparator (negative => key sorts first).
        pos = 0
        while pos < len(chain) and comparator(chain[pos], key) < 0:
            pos += 1
        chain.insert(pos, key)
        if len(chain) > self.capacity:
            # Rehash: advance the thread seed, grow the arrays.
            seed = self.thread_seed.pointer()
            seed, new_size = advance_seed(seed, self.step, self.count)
            self.thread_seed.store(seed)
            if self.capacity < new_size:
                self.capacity = new_size
                self.size_marker = new_size
        return bucket


# ---------------------------------------------------------------------------
# 0x5fcef60: level-gated log dispatch
# ---------------------------------------------------------------------------


class LogGate:
    """The log gate: slot 0x40 returns the level; <= 1 emits through
    slot 0x28 with level 1, > 1 drops the message."""

    def __init__(self, level_fn, emit_fn):
        self.level_fn = level_fn
        self.emit_fn = emit_fn
        self.emitted = []

    def log(self, fmt, *args):
        if self.level_fn() > 1:
            return False
        rendered = fmt % args if args else fmt
        self.emit_fn(1, rendered)
        self.emitted.append(rendered)
        return True


# ---------------------------------------------------------------------------
# 0x605feb0: the host — rebuild, measure, report
# ---------------------------------------------------------------------------

LOG_FORMAT = "hashLinkedList Entry distribution among buckets: %s"


class HashLinkListRep:
    """The rep object (this) behind the host: bucket array, key object,
    logger, report flag."""

    def __init__(self, buckets, key_obj, logger, report_flag, size_source):
        self.buckets = buckets  # list of chain heads (or None)
        self.key_obj = key_obj
        self.logger = logger
        self.report_flag = report_flag
        self.size_source = size_source  # slot-0x20 size getter


def rebuild_and_report(rep, allocator, thread_seed, comparator):
    """The host 0x605feb0 end to end.

    Builds an Arena from the rep's size source, builds a 12-bucket /
    divisor-4 index, walks every bucket's chains inserting each entry
    (counting per bucket), records each per-bucket count into a stack
    histogram when the report flag is set, renders and logs the
    histogram, and returns (iterator, histogram, rendered_text).
    The iterator is modelled as the (index, arena) pair the binary
    installs under the FullListIterator vtable.
    """
    arena = Arena(rep.size_source(), 0, 0)
    index = Index38(0xC, 0x4, rep.key_obj, allocator, thread_seed)
    hist = Histogram()
    for head in rep.buckets:
        count = 0
        node = head
        while node is not None:
            index.insert(node.key, comparator)
            count += 1
            node = node.next
        if rep.report_flag:
            hist.record(count)
    rendered = ""
    if rep.report_flag and rep.logger is not None:
        rendered = hist.render()
        gate = LogGate(rep.logger.level, rep.logger.emit)
        gate.log(LOG_FORMAT, rendered)
    iterator = {"index": index, "arena": arena,
                "vtable": 0x64D2090}  # FullListIterator
    return iterator, hist, rendered


class ChainNode:
    def __init__(self, key, nxt=None):
        self.key = key
        self.next = nxt


class FakeLogger:
    def __init__(self, level):
        self._level = level
        self.emitted = []

    def level(self):
        return self._level

    def emit(self, level, text):
        self.emitted.append((level, text))
