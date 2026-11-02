"""Model of node #94 0x515a960: the hashtable range constructor.

The window (FDE 0x515a960..0x515ae14, 2740 bytes, no padding to the
next FDE 0x515ae14) builds a hash table from an input range of
0x68-byte records. Each record carries a string key at +0x00 (pointer)
and +0x08 (length) and a 0x48-byte payload at +0x20..+0x68. The
constructor inserts each record's key once (unique keys: a record
whose key already exists in the table is skipped) and returns void;
the table is the result.

This model pins the window's own control flow. The library callees
it dispatches to are injected callables, not re-implemented here:
_M_next_bkt (the initial bucket-count choice), _Hash_bytes (the
key hash, seed 0xc70f6907), _M_need_rehash (the rehash decision),
and the rehash auxiliary 0x515a820 itself (modelled in full by its
own packet, PR #1751; here only its call contract is pinned: table,
new count, and the saved next-resize slot, followed by a bucket
recompute against the new count). The payload bytes are copied
verbatim; their field meanings are not claimed.

Table layout, as the window uses it: buckets pointer at +0x00,
bucket count at +0x08, before-begin next pointer at +0x10, element
count at +0x18, rehash policy at +0x20 (max load factor float at
+0x20, next-resize count at +0x28), single-bucket slot at +0x30.
A node carries its chain next pointer at +0x00, its key string at
+0x08 (pointer), +0x10 (length), +0x18 (inline buffer or capacity),
its payload at +0x28..+0x70, and its cached hash at +0x70. Bucket
array entries point at the node *before* the bucket's first node
(the before-begin sentinel for a bucket whose first node is the
chain head); an entry is empty exactly when it was never written
(the array is zeroed on allocation).
"""

# Hash seed passed to _Hash_bytes at 0x515ab26.
HASH_SEED = 0xC70F6907
# Linear-scan limit: the window scans the chain directly while the
# element count is at most this value, and takes the hash path above
# it (0x515aa37).
LINEAR_LIMIT = 20
# Node allocation size (0x515aba8) and input record stride.
NODE_SIZE = 0x78
RECORD_STRIDE = 0x68
# Key string threshold: at most 15 bytes stay inline, longer keys go
# through _M_create (0x515abde).
SSO_LIMIT = 15
# Allocation overflow guards (0x515a9ea, 0x515ad4d).
ALLOC_LIMIT = 1 << 60
ARRAY_LENGTH_LIMIT = 1 << 61


class BadAlloc(Exception):
    """Raised for requested counts in [2**60, 2**61)."""


class BadArrayNewLength(Exception):
    """Raised for requested counts >= 2**61."""


class ChainExhausted(Exception):
    """Raised when a bucket walk meets an inconsistent chain."""


class _Sentinel:
    """A table's before-begin node: its next pointer is the chain
    head. One instance per table, mirroring the window's use of the
    address of that table's own +0x10 field as the sentinel."""

    def __init__(self):
        self.next = None

    def __repr__(self):
        return "BEFORE_BEGIN"


class Node:
    """One hash-table node: key string, payload, cached hash."""

    def __init__(self, key, payload, cached_hash):
        self.key = bytes(key)
        self.payload = bytes(payload)
        self.cached_hash = cached_hash
        self.next = None

    @property
    def key_len(self):
        return len(self.key)

    @property
    def storage(self):
        """'sso' for keys of at most 15 bytes, else 'heap'."""
        return "sso" if len(self.key) <= SSO_LIMIT else "heap"


class Element:
    """One 0x68-byte input record: a key and a 0x48-byte payload."""

    def __init__(self, key, payload):
        if len(payload) != 0x48:
            raise ValueError("payload must be exactly 0x48 bytes")
        self.key = bytes(key)
        self.payload = bytes(payload)


class Table:
    """The table the window builds.

    ``buckets`` maps a bucket index to its before-node (the sentinel
    or a node); an absent index is an empty (zeroed) entry.
    """

    def __init__(self):
        self.buckets = {}
        self.bucket_count = 1
        self.element_count = 0
        self.next_resize = 0
        self.max_load_factor = 1.0
        # The head IS the sentinel's next pointer (the table+0x10
        # field), so inserting after the sentinel updates the head
        # automatically; keeping them as two attributes diverged.
        self.sentinel = _Sentinel()

    @property
    def head(self):
        return self.sentinel.next

    @head.setter
    def head(self, node):
        self.sentinel.next = node

    def set_head(self, node):
        self.head = node

    def bucket_entry(self, index):
        return self.buckets.get(index)

    def chain_keys(self):
        keys = []
        node = self.head
        while node is not None:
            keys.append(node.key)
            node = node.next
        return keys


def _key_equal(node, key):
    """The window's key comparison: length, then memcmp (skipped
    for empty keys, whose length match alone decides)."""
    if node.key_len != len(key):
        return False
    if len(key) == 0:
        return True
    return node.key == bytes(key)


def _linear_scan(table, key):
    """The direct chain scan (0x515aa30..0x515aac8).

    Returns True when the key is already present. The empty-key arm
    walks while a node's length is nonzero; the nonempty arm
    compares length then memcmp. Reaching the chain end means "not
    found" and the caller takes the hash path.
    """
    node = table.head
    if node is None:
        return False
    if len(key) == 0:
        while node is not None and node.key_len != 0:
            node = node.next
        return node is not None
    while node is not None:
        if node.key_len == len(key) and node.key == bytes(key):
            return True
        node = node.next
    return False


def _bucket_walk(table, key, cached_hash, bucket):
    """The bucket-segment walk (0x515ab51..0x515aba8).

    Returns True when the key is already present (duplicate: the
    caller skips the record), False when the record must be
    inserted. The walk stops at the chain end or at the first node
    whose bucket differs from the target bucket (the bucket's
    segment ended). The duplicate arm checks the before-node's next
    pointer: it is the matched node itself on every consistent
    walk, so the arm's insert branch cannot fire from a consistent
    table; it is implemented literally anyway.
    """
    pred = table.bucket_entry(bucket)
    if pred is None:
        return False
    node = pred.next
    if node is None:
        raise ChainExhausted("bucket before-node has no next node")
    while True:
        if node.cached_hash == cached_hash and _key_equal(node, key):
            # Duplicate arm (0x515ab07): insert only when the
            # before-node's next pointer is null.
            if pred.next is None:
                return False
            return True
        nxt = node.next
        if nxt is None:
            return False
        if nxt.cached_hash % table.bucket_count != bucket:
            return False
        pred = node
        node = nxt


def _insert(table, element, cached_hash, bucket, need_rehash, rehash_fn):
    """Allocate and link one node (0x515aba8..0x515ac95).

    The need-rehash call takes (bucket count, element count, 1) and
    returns (need, new count); on need, the rehash auxiliary is
    called with (table, new count, saved next-resize slot) and the
    bucket is recomputed against the new count before linking.
    """
    node = Node(element.key, element.payload, cached_hash)
    need, new_count = need_rehash(table.bucket_count,
                                  table.element_count, 1)
    if need:
        if rehash_fn is None:
            raise ValueError("rehash needed but no rehash_fn given")
        saved_next_resize = table.next_resize
        rehash_fn(table, new_count, saved_next_resize)
        bucket = cached_hash % table.bucket_count
    entry = table.bucket_entry(bucket)
    if entry is None:
        # Empty bucket (0x515ad10): prepend to the chain head; when
        # an old head exists, its bucket entry is repointed at the
        # new node; the new bucket's entry becomes the sentinel.
        old_head = table.head
        table.set_head(node)
        node.next = old_head
        if old_head is not None:
            old_bucket = old_head.cached_hash % table.bucket_count
            table.buckets[old_bucket] = node
        table.buckets[bucket] = table.sentinel
    else:
        # Nonempty bucket (0x515ac62): insert after the before-node.
        first = entry.next
        node.next = first
        entry.next = node
    table.element_count += 1
    return node


def range_ctor(elements, hint, next_bkt, hash_bytes, need_rehash,
               rehash_fn=None):
    """Build a table from ``elements`` in range order.

    ``next_bkt`` maps the hint to the initial bucket count,
    ``hash_bytes`` maps (key, seed) to a hash, ``need_rehash`` maps
    (bucket count, element count, 1) to (need, new count), and
    ``rehash_fn`` maps (table, new count, saved next-resize) to
    None, updating the table's bucket count and entries.
    """
    table = Table()
    next_count = next_bkt(hint)
    if table.bucket_count >= next_count:
        # Skip: the single-bucket slot already covers the request.
        pass
    elif next_count == 1:
        # Single-bucket arm (0x515ad3f): the +0x30 slot, zeroed.
        # Unreachable from this init (count starts at 1, so the
        # skip arm above takes counts of 1), but present in the
        # bytes; kept here to mirror the window exactly.
        table.buckets = {}
        table.bucket_count = 1
    else:
        if next_count >= ALLOC_LIMIT:
            if next_count >= ARRAY_LENGTH_LIMIT:
                raise BadArrayNewLength(next_count)
            raise BadAlloc(next_count)
        table.buckets = {}
        table.bucket_count = next_count
    count = 0  # the window's rbp: the element count at loop head
    entry_point = "linear"
    for element in elements:
        key = element.key
        if entry_point == "linear" and count <= LINEAR_LIMIT:
            if _linear_scan(table, key):
                entry_point = "linear"
                continue
            # Chain end or empty chain: fall through to hash path.
        # Hash path (0x515ab26).
        cached_hash = hash_bytes(key, HASH_SEED)
        bucket = cached_hash % table.bucket_count
        if count > LINEAR_LIMIT:
            if _bucket_walk(table, key, cached_hash, bucket):
                # Duplicate in the bucket walk: the next record
                # goes straight to the hash path (0x515ab11).
                entry_point = "hash"
                continue
        _insert(table, element, cached_hash, bucket,
                need_rehash, rehash_fn)
        count = table.element_count
        entry_point = "linear"
    return table
