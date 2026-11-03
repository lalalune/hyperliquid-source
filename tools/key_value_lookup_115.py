"""Python model of node #115's key-to-value lookup pair:
the key lookup routine at 0x5d8cf70 and the second-stage value
lookup at 0x5d8ce90, which the key lookup tail-jumps into on a
match (site 0x5d8cfea).

RE-001 work item: research/work-items/RE-001-key-value-lookup-115/.

Key lookup, stated literally. It takes a map object in rdi and a
key in rsi, where the key is a (pointer, length) pair: the key
bytes live at [key+0x00] and the length is the qword at
[key+0x08]. The map's qword at +0x18 decides the path: when it
is greater than 20 (unsigned) the hash path runs, otherwise the
small path runs.

Small path: the node chain starts at the qword at map+0x10.
Each node carries its successor at +0x00, its key bytes at
+0x08 and its key length at +0x10. Nodes are scanned in chain
order; a node matches when its length equals the key length and
either the length is zero (no memcmp is issued for an empty
key) or memcmp over exactly that many bytes reports equal. On
a match the dword at the node +0x28 is the id handed to the
value lookup; on exhaustion (a null head or a null successor)
the lookup returns 0 at once.

Hash path: the key bytes and length are passed to the _Hash_bytes
library call with seed 0xc70f6907 (a PLT call, not node logic;
the model takes its result as an input). The bucket count is
the qword at map+0x08 and the bucket array is the qword at
map+0x00; the bucket index is hash % bucket_count. A zero slot
means a miss. Otherwise the slot points at a header whose +0x00
field is the first node; each node carries its successor at
+0x00, its key bytes at +0x08, its key length at +0x10, its id
at +0x28 (dword) and its stored hash at +0x30. A node matches
when its stored hash equals the computed hash, its length
equals the key length, and either the length is zero or memcmp
over exactly that many bytes reports equal. Advancing past a
node stops with a miss when the successor is null or when the
successor's stored hash % bucket_count differs from the bucket
index (the bucket's nodes form one contiguous chain segment).
On a match the node's +0x28 dword is handed to the value
lookup.

Value lookup, stated literally. It takes the same map object in
rdi (the tail jump passes rdi unchanged) and the id in esi
(the dword is zero-extended). The qword at map+0x50 decides
the path.

Small path (flag zero): the value chain starts at the qword at
map+0x48. Each value node carries its successor at +0x00, its
id dword at +0x08 and its value pointer at +0x10. The first
node whose id equals the sought id yields its +0x10 value; a
null head or chain exhaustion returns 0. A matched node whose
+0x10 value is itself 0 therefore returns 0, exactly like a
miss.

Bucketed path (flag nonzero): the bucket count is the qword at
map+0x40 and the bucket array is the qword at map+0x38; the
bucket index is id % bucket_count. A zero slot means a miss.
Otherwise the slot points at a header whose +0x00 field is the
first value node, and nodes are scanned the same way as the
key hash path: advancing past a node stops with a miss when
the successor is null or when the successor's id %
bucket_count differs from the bucket index. On a match the
value is the matched node's +0x10 field, reached through its
predecessor's +0x00 field (for the first node, through the
header); if that predecessor field were null the binary would
return 0, which the model mirrors only for a null header slot
(the first node itself is dereferenced unchecked, see below).

Representation: maps, nodes and value nodes are dicts. A map
has keys "count" (+0x18), "small_head" (+0x10), "bucket_count"
(+0x08), "buckets" (+0x00, a list of headers or None),
"value_flag" (+0x50), "value_head" (+0x48),
"value_bucket_count" (+0x40) and "value_buckets" (+0x38, a list
of headers or None). A key node has "next", "key" (bytes),
"id" (dword int) and "hash" (stored hash int); a bucket header
has only "next". A value node has "next", "id" and "value"
(int, 0 for a null pointer). A missing map field raises
ValueError; the binary would simply read whatever bytes lie at
that address, so a missing field is a modelling gap, not a
binary behavior. Two inputs the binary dereferences without a
null check also raise in the model instead of faulting: a
bucket header whose +0x00 field is null, and a bucket count of
zero (a division by zero). The _Hash_bytes result and memcmp
are library behavior, not reconstructed here: the model takes
the hash as an argument and compares key bytes directly.

NOT claimed: what the map, its nodes, the keys or the ids
denote; the _Hash_bytes algorithm itself; any caller semantics
beyond the census (the nine key-lookup call sites and the
eight value-lookup call sites are recorded by address in the
packet's callers.tsv only); or the wrapper at 0x5d8cf30, which
calls the value lookup and stores its result but is not
modelled here.
"""

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1
SMALL_LIMIT = 20
HASH_SEED = 0xC70F6907


def _require(mapping, field):
    if field not in mapping:
        raise ValueError("missing field %r" % field)
    return mapping[field]


def _bucket_index(hash_value, bucket_count):
    if bucket_count == 0:
        raise ValueError("bucket count is zero (binary would fault)")
    return hash_value % bucket_count


def _advance_hash_node(node, bucket_index, bucket_count):
    """Return the next key node, or None on a binary miss stop.

    The binary stops with a miss when the successor is null or
    when the successor's stored hash % bucket_count differs from
    the bucket index.
    """
    nxt = node["next"]
    if nxt is None:
        return None
    if _bucket_index(nxt["hash"], bucket_count) != bucket_index:
        return None
    return nxt


def lookup_id(map_obj, key, hash_value):
    """Run the 0x5d8cf70 key lookup; return the id dword or None.

    Returns None exactly where the binary returns 0 without
    reaching the value lookup (a miss). On a match returns the
    matched node's +0x28 dword.
    """
    count = _require(map_obj, "count")
    if count > SMALL_LIMIT:
        bucket_count = _require(map_obj, "bucket_count")
        buckets = _require(map_obj, "buckets")
        bucket_index = _bucket_index(hash_value, bucket_count)
        if bucket_index >= len(buckets):
            raise ValueError("bucket index out of range")
        header = buckets[bucket_index]
        if header is None:
            return None
        node = header["next"]
        if node is None:
            raise ValueError("bucket header with a null first node")
        while True:
            if node["hash"] == hash_value and len(node["key"]) == len(key):
                if len(key) == 0 or node["key"] == key:
                    return node["id"] & MASK32
            node = _advance_hash_node(node, bucket_index, bucket_count)
            if node is None:
                return None
    head = _require(map_obj, "small_head")
    node = head
    while node is not None:
        if len(node["key"]) == len(key):
            if len(key) == 0 or node["key"] == key:
                return node["id"] & MASK32
        node = node["next"]
    return None


def value_lookup(map_obj, wanted_id):
    """Run the 0x5d8ce90 value lookup; return the value or 0."""
    wanted_id &= MASK32
    flag = _require(map_obj, "value_flag")
    if flag == 0:
        node = _require(map_obj, "value_head")
        while node is not None:
            if node["id"] & MASK32 == wanted_id:
                return node["value"]
            node = node["next"]
        return 0
    bucket_count = _require(map_obj, "value_bucket_count")
    buckets = _require(map_obj, "value_buckets")
    bucket_index = _bucket_index(wanted_id, bucket_count)
    if bucket_index >= len(buckets):
        raise ValueError("bucket index out of range")
    header = buckets[bucket_index]
    if header is None:
        return 0
    prev = header
    node = header["next"]
    if node is None:
        raise ValueError("bucket header with a null first node")
    while True:
        if node["id"] & MASK32 == wanted_id:
            # The binary reaches the value through the
            # predecessor's +0x00 field; that field is this
            # node by construction, so its +0x10 is the value.
            if prev["next"] is None:
                return 0
            return node["value"]
        nxt = node["next"]
        if nxt is None:
            return 0
        if _bucket_index(nxt["id"], bucket_count) != bucket_index:
            return 0
        prev, node = node, nxt


def lookup(map_obj, key, hash_value):
    """Run the whole pair end to end: key -> id -> value, or 0."""
    found = lookup_id(map_obj, key, hash_value)
    if found is None:
        return 0
    return value_lookup(map_obj, found)
