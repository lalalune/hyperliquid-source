"""Python model of node #115 HashLinkListRep slot-0x08 insert.

Pinned from the digest-verified work binary (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
provenance/artifacts.json path artifacts/node/115/hl-node):
host 0x605f700 (vtable slot 0x08 of HashLinkListRep 0x64d2168),
its factory ctor 0x605eb40 (HashLinkListRepFactory slot 0x98),
the varint32 decoder 0x61bd4f0, the canonical
InternalKeySliceTransform slot-0x98 0x5e9af30, the 64-bit hash
0x61c38a0, the hex encoder 0x61c7e30, and the re-shipped index
builder 0x605f290 / index insert 0x605f340 / log gate 0x5fcef60
(open PR #3575).

A record is {next (+0x00), varint32 key-length + key bytes (+0x08)}.
The host inserts one record into the bucket selected by the
transformed key's hash, keeping each bucket's chain ordered by the
key object's slot-0x10 comparator, converting a bucket to a
sub-index when its chain count reaches the +0x20 threshold, and
logging (hex-encoded key) when the count reaches the +0x40
threshold.

Assumptions (recorded explicitly, see the work-item README):
- The key object's slot-0x08 (record/record) and slot-0x10
  (record/slice) comparators are caller-supplied; the reference
  instance here compares decoded key bytes bytewise.
- The transform chain's terminal (non-canonical) transform is
  chain-supplied; the model takes it as a callable. The reference
  terminal transform is the identity on the pair it receives.
- The 0x38-byte sub-index's rehash/growth internals (pinned in
  #3575) are abstracted as an ordered record list preserving its
  observable contract: ordered insertion by the comparator.
- Hash inputs longer than 128 bytes use helpers 0x61c2890 /
  0x61c3230 outside the hashed FDE; the model raises for them
  (boundary, documented in records.json).
- std::string storage/SSO is not modeled; only string contents.
"""

MASK = (1 << 64) - 1
M32 = (1 << 32) - 1

# Hash constants, transcribed from 0x61c38a0.
_GOLDEN = 0x9E3779B185EBCA87
_FIN_MUL = 0x165667B19E3779F9
_K1 = 0xBE4BA423396CFEB8
_K2 = 0x1CAD21F72C81017C
_K3 = 0xDB979083E96DD4DE
_K4 = 0x1F67B3B7A4A44072
_EMPTY_HASH = 0x5342C3010FE1DD04


def _mum(a, b):
    """128-bit multiply; returns (lo, hi) of a*b."""
    p = (a & MASK) * (b & MASK)
    return p & MASK, (p >> 64) & MASK


def _fin(x):
    """Shared hash finalizer: y = x ^ (x >> 37); z = y * _FIN_MUL;
    return z ^ (z >> 32)."""
    y = (x ^ (x >> 37)) & MASK
    z = (y * _FIN_MUL) & MASK
    return (z ^ (z >> 32)) & MASK


def _read64(data, off):
    return int.from_bytes(data[off:off + 8], "little")


def _read32(data, off):
    return int.from_bytes(data[off:off + 4], "little")


def hash64(data):
    """Transcription of 0x61c38a0 for len(data) <= 128.

    Returns the 64-bit hash. Raises ValueError for len > 128
    (helpers 0x61c2890 / 0x61c3230, outside the modeled FDE).
    """
    n = len(data)
    if n > 128:
        raise ValueError("hash64: len %d > 128 uses helpers outside 0x61c38a0" % n)
    if n == 0:
        return _EMPTY_HASH
    if n <= 3:
        v = (data[0] | (n << 24) | (data[n // 2] << 8)
             | (data[n - 1] << 16)) ^ 0x396CFEB8
        v = (v * _GOLDEN) & MASK
        return _fin(v)
    if n <= 8:
        pre = (((_read32(data, n - 4) << 32) | _read32(data, 0)) ^ _K1) & MASK
        t = pre ^ (pre >> 51)
        t = (t * 0x9E3779B1) & MASK
        t = (t + n) & MASK
        u = t ^ (t >> 47)
        y = (u * 0xC2B2AE3D27D4EB4F) & MASK
        return _fin(y)
    if n <= 16:
        a = _read64(data, 0) ^ _K1
        b = _read64(data, n - 8) ^ _K2
        lo, hi = _mum((a + n) & MASK, b)
        return _fin((a + n + b + (lo ^ hi)) & MASK)
    seed = (n * _GOLDEN) & MASK
    if n <= 32:
        lo1, hi1 = _mum(_read64(data, 8) ^ _K2, _read64(data, 0) ^ _K1)
        lo2, hi2 = _mum(_read64(data, n - 8) ^ _K4,
                        _read64(data, n - 16) ^ _K3)
        return _fin(((hi1 ^ lo1) + (hi2 ^ lo2) + seed) & MASK)
    # 33..128: lane-pair contributions accumulate into the seed,
    # then the 17..32 tail finishes.
    if n > 96:
        lo1, hi1 = _mum(_read64(data, 0x30) ^ 0x3F349CE33F76FAA8,
                        _read64(data, 0x38) ^ 0x1D4F0BC7C7BBDCF9)
        lo2, hi2 = _mum(_read64(data, n - 0x40) ^ 0x3159B4CD4BE0518A,
                        _read64(data, n - 0x38) ^ 0x647378D9C97E9FC8)
        seed = (seed + (lo1 ^ hi1) + (lo2 ^ hi2)) & MASK
    if n > 64:
        lo1, hi1 = _mum(_read64(data, 0x20) ^ 0xCB00C391BB52283C,
                        _read64(data, 0x28) ^ 0xA32E531B8B65D088)
        lo2, hi2 = _mum(_read64(data, n - 0x30) ^ 0x4EF90DA297486471,
                        _read64(data, n - 0x28) ^ 0xD8ACDEA946EF1938)
        seed = (seed + (lo1 ^ hi1) + (lo2 ^ hi2)) & MASK
    if n > 32:
        lo1, hi1 = _mum(_read64(data, 0x10) ^ 0x78E5C0CC4EE679CB,
                        _read64(data, 0x18) ^ 0x2172FFCC7DD05A82)
        lo2, hi2 = _mum(_read64(data, n - 0x20) ^ 0x8E2443F7744608B8,
                        _read64(data, n - 0x18) ^ 0x4C263A81E69035E0)
        seed = (seed + (lo1 ^ hi1) + (lo2 ^ hi2)) & MASK
    lo1, hi1 = _mum(_read64(data, 8) ^ _K2, _read64(data, 0) ^ _K1)
    lo2, hi2 = _mum(_read64(data, n - 8) ^ _K4,
                    _read64(data, n - 16) ^ _K3)
    return _fin(((hi1 ^ lo1) + (hi2 ^ lo2) + seed) & MASK)


def encode_varint32(value):
    """LEB128 varint32 encoding (the inverse of 0x61bd4f0)."""
    out = bytearray()
    v = value & M32
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def decode_varint32(buf, start=0, limit=None):
    """Transcription of 0x61bd4f0.

    Decodes a varint32 starting at buf[start], bounded by limit
    (default: end of buf). Returns (value, end_index). On failure
    (start >= limit, or the shift passes 28) returns (0, start)
    matching the binary: the callee returns 0 as the end pointer and
    leaves the out slot untouched (the host pre-zeroes it).
    """
    if limit is None:
        limit = len(buf)
    if start >= limit:
        return 0, start
    pos = start
    shift = 0
    value = 0
    while True:
        b = buf[pos]
        pos += 1
        if b & 0x80:
            value |= (b & 0x7F) << shift
            shift += 7
            if shift > 28:
                return 0, start
            if pos >= limit:
                return 0, start
        else:
            value |= (b & 0x7F) << shift
            return value, pos


def hex_encode(data, uppercase=True):
    """Transcription of 0x61c7e30 (content only; SSO not modeled).

    uppercase=True (flag 1): each byte becomes two UPPERCASE hex
    digits. uppercase=False (flag 0): the raw bytes are copied.
    """
    if uppercase:
        return data.hex().upper().encode("ascii")
    return bytes(data)


class ChainExhausted(Exception):
    """The transform chain ran out of nodes without a terminal
    transform (the binary would dereference past the chain)."""


def run_transform_chain(nodes, key):
    """Walk the *(this+0x28) transform chain over one key.

    nodes: list of callables-or-None in chain order; None marks the
    canonical transform 0x5e9af30, any other entry is a terminal
    transform called as fn(pair) -> (bytes, length). key: the
    decoded key bytes. Returns (bytes, length) from the first
    non-canonical transform. Each canonical hop pre-strips 8 from
    the length, so the transform at chain index k receives
    (key, len(key) - 8*(k+1)), exactly as the host's unrolled loop
    builds its stack pairs (rsp+0x30..0x108) and 0x5e9af30 builds
    its own.
    """
    length = len(key)
    for k, node in enumerate(nodes):
        if node is None:
            continue
        return node((key, length - 8 * (k + 1)))
    raise ChainExhausted(
        "chain of %d canonical nodes has no terminal transform" % len(nodes))


def identity_transform(pair):
    """Reference terminal transform: returns the pair unchanged."""
    return pair


def compare_records(a_key, b_key):
    """Reference key-object comparator: bytewise on decoded keys.

    Models slot 0x08 (record/record) and slot 0x10 (record/slice)
    of the caller-supplied key object. Returns negative / zero /
    positive like the binary's comparator.
    """
    if a_key < b_key:
        return -1
    if a_key > b_key:
        return 1
    return 0


class Record(object):
    """One key record: varint32 key-length + key bytes (+0x08).

    next: the following record in a bucket chain (or self for a
    sub-index node, matching the binary's *(node) == node marker).
    """

    def __init__(self, key):
        self.key = bytes(key)
        self.next = None

    @property
    def encoded(self):
        return encode_varint32(len(self.key)) + self.key

    def __repr__(self):
        return "Record(%r)" % (self.key,)


class CountNode(object):
    """A bucket's 0x10-byte head: next = first key record,
    count = keys in the chain (incremented per insert)."""

    def __init__(self, first, count=1):
        self.next = first
        self.count = count


class IndexNode(object):
    """A converted bucket: 0x48-byte block; next is itself
    (the binary's *(node) == node marker), count tracks entries,
    index holds the key records in comparator order."""

    def __init__(self, count):
        self.next = self
        self.count = count
        self.index = []

    def insert(self, record):
        """Insert one record into the sub-index, ordered by the
        comparator (the observable contract of 0x605f340)."""
        keys = [r.key for r in self.index]
        pos = 0
        while pos < len(keys) and compare_records(keys[pos], record.key) < 0:
            pos += 1
        self.index.insert(pos, record)


class HashLinkListRep(object):
    """Model of the HashLinkListRep object built by 0x605eb40.

    bucket_count: *(this+0x10); convert_threshold: *(this+0x20)
    (clamped to >= 3 by the ctor); log_threshold: *(this+0x40)
    (<= 0 disables the log); transform_nodes: the *(this+0x28)
    chain (None per canonical hop, a callable for a terminal
    transform); terminal: a callable appended as the chain's final
    node when given (the reference terminal is identity_transform).
    log_sink: called as fn(bucket_index, count, hex_key) when the
    log path fires; records the binary's log-gate call.
    """

    def __init__(self, bucket_count, convert_threshold=3, log_threshold=0,
                 transform_nodes=(), terminal=None, log_sink=None):
        self.bucket_count = bucket_count
        self.convert_threshold = max(convert_threshold, 3)
        self.log_threshold = log_threshold
        self.transform_nodes = list(transform_nodes)
        if terminal is not None:
            # The chain ends in its terminal transform; appending it
            # puts it at the last chain position, which fixes the
            # level arithmetic for the pair it receives.
            self.transform_nodes.append(terminal)
        self.log_sink = log_sink
        self.buckets = [None] * bucket_count

    def _bucket_index(self, key):
        """Hash the transformed key, bucket = (count * hash) >> 64."""
        transformed, tlen = run_transform_chain(self.transform_nodes, key)
        h = hash64(transformed[:tlen])
        return ((self.bucket_count * h) >> 64) & MASK, transformed[:tlen]

    def insert(self, record):
        """Transcription of the host 0x605f700 for one record.

        Returns a tuple describing the path taken:
        ('empty-bucket', bucket), ('linked', bucket),
        ('sub-index-insert', bucket), ('converted', bucket),
        ('logged', bucket) is folded into the path that follows it.
        The record's .next is set exactly as the binary sets
        *(arg2): the following chain node, or None for a fresh head.
        """
        key = record.key
        bucket, _tkey = self._bucket_index(key)
        head = self.buckets[bucket]
        if head is None:
            record.next = None
            self.buckets[bucket] = record
            return ("empty-bucket", bucket)
        if isinstance(head, Record) and head.next is None:
            # Second insert into a bare-head bucket: wrap it in a
            # 0x10-byte count node (count 1), then fall through.
            head = CountNode(head, 1)
            self.buckets[bucket] = head
        if isinstance(head, IndexNode):
            head.count += 1
            head.insert(record)
            return ("sub-index-insert", bucket)
        # Plain chain head: a CountNode. Threshold checks run on the
        # pre-insert count, then the count increments.
        if self.log_threshold > 0 and head.count == self.log_threshold:
            if self.log_sink is not None:
                self.log_sink(bucket, head.count,
                              hex_encode(key, uppercase=True))
        if head.count == self.convert_threshold:
            index = IndexNode(head.count + 1)
            node = head.next
            while node is not None:
                index.insert(node)
                node = node.next
            index.insert(record)
            self.buckets[bucket] = index
            return ("converted", bucket)
        head.count += 1
        # Ordered splice: walk from head.next comparing each node's
        # key against the DECODED key via slot 0x10; splice the
        # record before the first node that compares >= 0, or at
        # the end when the chain runs out.
        prev = None
        cur = head.next
        while cur is not None:
            if compare_records(cur.key, key) >= 0:
                break
            prev = cur
            cur = cur.next
        record.next = cur
        if prev is not None:
            prev.next = record
        else:
            head.next = record
        return ("linked", bucket)
