"""Node #115 plain-table index builder model (RE-001).

Models the per-key record host 0x6198900 and the dump host 0x6198d40
of rocksdb/table/plain/plain_table_index.cc, together with their
callees: the chunked entry store (0x6198790), the run-length
HistogramImpl (0x606b130 via the thunk 0x606b1c0), the varint encoder
(0x61bd410), the serializer (0x6198370), the bucket-count computer
(0x6198230), the chain gather (0x6198290), rocksdb::Hash (0x61c34a0)
and the hex encoder (0x61c7e30).

Grounding: research/work-items/RE-001-plain-table-index-115/
(evidence packet: raw objdump excerpts, records.json, verify.py).
The hash is implemented from the binary disassembly; its
authoritative pin is dd12m54's open PR #3525
(RE-001-hash-entry-61c34a0-115) and is only referenced here.
The HistogramImpl family is re-shipped from open PR #3371 and the
hex encoder from open PR #3585 (originally #3561).

The owner struct is modelled with the fields the hosts actually
touch; the allocator behind (*owner)->vtable[0x18] is a
harness-supplied callback, and the +0x758 flag is an input (the
binary never sets it to 1 inside the pinned windows).
"""

import math

HASH_SEED = 397
HASH_MIX = 0xC6A4A793
MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
EMPTY_BUCKET = 0x7FFFFFFF
MULTI_FLAG = 0x80000000
SOURCE_FILE = "table/plain/plain_table_index.cc"


def _u64(value):
    return value & MASK64


def _u32(value):
    return value & MASK32


def _sign_extend_byte(byte):
    return byte - 256 if byte >= 0x80 else byte


def rocksdb_hash(data, seed=HASH_SEED):
    """rocksdb::Hash(data, len, seed) at 0x61c34a0.

    h = (len * 0xc6a4a793) ^ seed; per 4-byte word w:
    h += w; h = (h * m) ^ ((h * m) >> 16). Tail of 1-3 bytes:
    h += sign_extend(data[k]) << (8 * k) for the remaining bytes,
    low byte first, then h = (h * m) ^ ((h * m) >> 24). A length
    that is a multiple of 4 returns h with no final mix, so
    Hash(b"", 397) == 397.
    """
    h = _u32(len(data) * HASH_MIX) ^ seed
    pos = 0
    while pos + 4 <= len(data):
        word = int.from_bytes(data[pos:pos + 4], "little")
        h = _u32(h + word)
        mixed = _u32(h * HASH_MIX)
        h = mixed ^ (mixed >> 16)
        pos += 4
    tail = len(data) - pos
    if tail:
        for k in range(tail):
            h = _u32(h + (_sign_extend_byte(data[pos + k]) << (8 * k)))
        mixed = _u32(h * HASH_MIX)
        h = mixed ^ (mixed >> 24)
    return h


def hex_encode(data, flag):
    """Hex encoder 0x61c7e30: flag 0 raw-copies the slice; any other
    flag renders each byte as two UPPERCASE hex characters."""
    if flag == 0:
        return bytes(data)
    return "".join("%02X" % b for b in data).encode("ascii")


def varint_len(value):
    """Unsigned LEB128 length: 1 byte to 0x7f, 2 to 0x3fff, 3 to
    0x1fffff, 4 to 0xfffffff, else 5."""
    if value <= 0x7F:
        return 1
    if value <= 0x3FFF:
        return 2
    if value <= 0x1FFFFF:
        return 3
    if value <= 0xFFFFFFF:
        return 4
    return 5


def varint_encode(value):
    """Unsigned LEB128 encoding, as written by 0x61bd410."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def bucket_index(value, boundaries):
    """Bucket index 0x606afa0: std::lower_bound over the boundaries —
    the first index j with boundaries[j] >= value; value >= last
    boundary returns count - 1."""
    if value >= boundaries[-1]:
        return len(boundaries) - 1
    lo, hi = 0, len(boundaries)
    while lo < hi:
        mid = (lo + hi) // 2
        if boundaries[mid] < value:
            lo = mid + 1
        else:
            hi = mid
    return lo


def load_boundaries(path):
    """Read the 109 histogram boundaries from boundaries.tsv."""
    rows = []
    with open(path) as handle:
        header = handle.readline()
        assert header.strip() == "index\tboundary"
        for line in handle:
            index, value = line.split("\t")
            rows.append((int(index), int(value)))
    assert [index for index, _ in rows] == list(range(len(rows)))
    return [value for _, value in rows]


class Histogram:
    """HistogramImpl data subobject (0x606b130 and friends).

    min starts at the last boundary, max at 0, count/sum/sumsq at 0.
    """

    def __init__(self, boundaries):
        self.boundaries = list(boundaries)
        self.min = self.boundaries[-1]
        self.max = 0
        self.count = 0
        self.sum = 0
        self.sum_of_squares = 0
        self.buckets = [0] * len(self.boundaries)

    def record(self, value):
        bucket = bucket_index(value, self.boundaries)
        self.buckets[bucket] += 1
        if value < self.min:
            self.min = value
        if value > self.max:
            self.max = value
        self.count += 1
        self.sum = _u64(self.sum + value)
        self.sum_of_squares = _u64(self.sum_of_squares + value * value)

    def average(self):
        if self.count == 0:
            return 0.0
        return self.sum / self.count

    def stddev(self):
        if self.count == 0:
            return 0.0
        count = float(self.count)
        variance = (count * self.sum_of_squares - self.sum * self.sum) / (count * count)
        if variance < 0.0:
            return 0.0
        return math.sqrt(variance)

    def percentile(self, pct):
        """Percentile 0x606b260, clamped to [min, max]; an empty
        bucket returns its lower boundary; past the last bucket
        returns (double)max; an empty histogram returns 0.0."""
        threshold = self.count * (pct / 100.0)
        if len(self.buckets) == 0:
            return float(self.max)
        running = 0
        for index, bucket_count in enumerate(self.buckets):
            running += bucket_count
            # The binary walks while running <= threshold (signed path:
            # jae jumps only when running > threshold), so a threshold
            # landing exactly on a bucket boundary continues to the
            # next non-empty bucket and skips any empty bucket's range.
            if running > threshold:
                if index == 0:
                    lower = 0
                else:
                    lower = self.boundaries[index - 1]
                upper = self.boundaries[index]
                if bucket_count == 0:
                    value = float(lower)
                else:
                    value = lower + ((threshold - (running - bucket_count)) / bucket_count) * (upper - lower)
                return min(max(value, float(self.min)), float(self.max))
        return float(self.max)

    def median(self):
        return self.percentile(50.0)

    def to_string(self):
        """Renderer 0x606b6f0: the exact ToString text form."""
        lines = []
        lines.append("Count: %d Average: %.4f  StdDev: %.2f\n"
                     % (self.count, self.average(), self.stddev()))
        if self.count == 0:
            lines.append("Min: %d  Median: %.4f  Max: %d\n"
                         % (0, self.median(), 0))
        else:
            lines.append("Min: %d  Median: %.4f  Max: %d\n"
                         % (self.min, self.median(), self.max))
        lines.append("Percentiles: P50: %.2f P75: %.2f P99: %.2f "
                     "P99.9: %.2f P99.99: %.2f\n"
                     % (self.percentile(50.0), self.percentile(75.0),
                        self.percentile(99.0), self.percentile(99.9),
                        self.percentile(99.99)))
        lines.append("-" * 54 + "\n")
        if self.count:
            per_unit = 100.0 / self.count
            running = 0
            for index, bucket_count in enumerate(self.buckets):
                if bucket_count == 0:
                    continue
                running += bucket_count
                if index == 0:
                    lower, bracket = 0, "["
                else:
                    lower, bracket = self.boundaries[index - 1], "("
                upper = self.boundaries[index]
                pct = bucket_count * per_unit
                cum_pct = running * per_unit
                lines.append("%c %7d, %7d ] %8d %7.3f%% %7.3f%% "
                             % (bracket, lower, upper, bucket_count, pct, cum_pct))
                lines.append("#" * int(pct / 5.0 + 0.5) + "\n")
        return "".join(lines)


class Entry:
    """One 16-byte chunked-store entry: {u32 hash, u32 arg4, u64 next}."""

    __slots__ = ("hash", "arg4", "next")

    def __init__(self, hash_value, arg4):
        self.hash = hash_value
        self.arg4 = arg4
        self.next = None


class ChunkedStore:
    """The +0x728 chunked entry store (0x6198790 / 0x61985f0).

    entries_per_chunk is the chunk capacity; chunks grow by
    appending a fresh chunk when the current one fills.
    """

    def __init__(self, entries_per_chunk):
        self.entries_per_chunk = entries_per_chunk
        self.chunks = [[]]
        self.used_in_last = 0

    def append(self, hash_value, arg4):
        if self.used_in_last != self.entries_per_chunk:
            self.chunks[-1].append(Entry(hash_value, arg4))
            self.used_in_last += 1
        else:
            self.chunks.append([Entry(hash_value, arg4)])
            self.used_in_last = 1

    def entries(self):
        out = []
        for chunk in self.chunks:
            out.extend(chunk)
        return out

    def total(self):
        return sum(len(chunk) for chunk in self.chunks)


class PlainTableIndex:
    """The plain-table index builder owner (record host 0x6198900
    and dump host 0x6198d40).

    allocate(total) must return a writable bytearray of at least
    total bytes (the allocator behind (*owner)->vtable[0x18]).
    log_records collects (level, text) pairs the hosts log through
    0x5fceda0; nothing is printed.
    """

    def __init__(self, boundaries, entries_per_chunk=4, sample_interval=0,
                 bucket_gate=0, ratio=0.0, allocate=None):
        self.boundaries = list(boundaries)
        self.histogram = Histogram(boundaries)
        self.store = ChunkedStore(entries_per_chunk)
        self.last_key = b""
        self.stored_hash = 0
        self.total_keys = 0
        self.run_length = 0
        self.flag_758 = False
        self.flag_759 = False
        self.sample_interval = sample_interval
        self.bucket_gate = bucket_gate
        self.ratio = ratio
        self.bucket_count = 0
        self.suffix_size = 0
        self.allocate = allocate or (lambda total: bytearray(total))
        self.log_records = []

    def _log(self, level, text):
        self.log_records.append((level, text))

    def _counter_path(self):
        self.run_length += 1
        if self.sample_interval != 0 and self.run_length % self.sample_interval == 0:
            self.flag_759 = True
        self.flag_758 = False

    def _main_body(self, key, arg4):
        self.run_length = 0
        self.last_key = hex_encode(key, 0)
        self.stored_hash = rocksdb_hash(key, HASH_SEED)
        self.flag_759 = True
        self.store.append(self.stored_hash, arg4)
        self.flag_759 = False
        self._counter_path()

    def record_key(self, key, arg4):
        """Record host 0x6198900: track runs of identical keys,
        record the finished run length into the histogram on a key
        change, and append one (hash, arg4) entry per new (or
        re-sampled) key."""
        if self.flag_758:
            self.total_keys += 1
            self._main_body(key, arg4)
            return
        if hex_encode(key, 0) != self.last_key:
            self.total_keys += 1
            self.histogram.record(self.run_length)
            self._main_body(key, arg4)
        else:
            if self.flag_759:
                self.store.append(self.stored_hash, arg4)
                self.flag_759 = False
            self._counter_path()

    def compute_bucket_count(self):
        """Bucket-count computer 0x6198230."""
        if self.bucket_gate == 0 or self.ratio <= 0.0:
            return 1
        return int(self.total_keys * (1.0 / self.ratio)) + 1

    def dump(self):
        """Dump host 0x6198d40: gather the chains, record the final
        run, render and log the histogram, serialize the index.
        Returns (buffer, size)."""
        self.bucket_count = self.compute_bucket_count()
        count = self.bucket_count
        heads = [None] * count
        counts = [0] * count
        for entry in self.store.entries():
            bucket = entry.hash % count
            entry.next = heads[bucket]
            heads[bucket] = entry
            counts[bucket] += 1
        self.suffix_size = sum(c * 4 + varint_len(c) for c in counts if c > 1)
        self.histogram.record(self.run_length)
        text = self.histogram.to_string()
        self._log(1, "[%s:101] Number of Keys per prefix Histogram: %s"
                  % (SOURCE_FILE, text))
        buffer = self.serialize(heads, counts)
        return buffer

    def serialize(self, heads, counts):
        """Serializer 0x6198370: [varint bucket_count][varint
        key_count][bucket_count x u32 slots][suffix area]."""
        count = self.bucket_count
        total = (varint_len(count) + varint_len(self.total_keys)
                 + self.suffix_size + count * 4)
        self._log(0, "[%s:156] Reserving %u bytes for plain table's sub_index"
                  % (SOURCE_FILE, self.suffix_size))
        buf = self.allocate(total)
        pos = 0
        for value in (count, self.total_keys):
            encoded = varint_encode(value)
            buf[pos:pos + len(encoded)] = encoded
            pos += len(encoded)
        slot_base = pos
        suffix_base = slot_base + count * 4
        suffix_off = 0
        for index in range(count):
            if counts[index] == 0:
                slot = EMPTY_BUCKET
            elif counts[index] == 1:
                slot = heads[index].arg4
            else:
                slot = suffix_off | MULTI_FLAG
                write_at = suffix_base + suffix_off
                encoded = varint_encode(counts[index])
                buf[write_at:write_at + len(encoded)] = encoded
                write_at += len(encoded)
                chain = []
                node = heads[index]
                while node is not None:
                    chain.append(node)
                    node = node.next
                for position, node in enumerate(chain):
                    slot_pos = write_at + (len(chain) - 1 - position) * 4
                    buf[slot_pos:slot_pos + 4] = node.arg4.to_bytes(4, "little")
                suffix_off += varint_len(counts[index]) + counts[index] * 4
            buf[slot_base + index * 4: slot_base + index * 4 + 4] = \
                slot.to_bytes(4, "little")
        self._log(0, "[%s:202] hash table size: %u, suffix_map length %u"
                  % (SOURCE_FILE, count, self.suffix_size))
        return bytes(buf[:total])
