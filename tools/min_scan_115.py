"""Model of node #115 unmatched-node minimum scan 0x5f134b0, its
value callee 0x5f0a1d0 and its null-query caller 0x5d8bd30.

The window walks the intrusive list hanging off its argument
object (sentinel at object + 0x08, node next at + 0x00, node
key-record pointer at + 0x10). For each node it asks whether the
node's key record is matched by the query record (second argument):
with a null query every node is unmatched; in linear mode the
query's chain (head at query + 0x10, entry next at + 0x00, entry
key at + 0x08) must contain the node's key record; in hash mode
(query + 0x18 nonzero) the node's key is divided by the bucket
count at query + 0x08 and the bucket chain must contain it, with
every later chain entry's key required to hash to the same bucket.
For every unmatched node the window calls 0x5f0a1d0, which returns
the qword at key-record + 0xc38, and keeps the minimum over the
nonzero results (a zero result is skipped, so the result is 0 when
no unmatched node yields a nonzero value). Matched nodes contribute
nothing. An empty outer list returns 0.

Key records in the model carry an integer key_id standing in for
the pointer value the window divides in hash mode; linear matching
uses object identity, as the window compares pointers.
"""

MASK = (1 << 64) - 1


class KeyRecord:
    """One outer-list node's key record (the pointer at node + 0x10).

    value_c38 is the qword the value callee reads at + 0xc38;
    key_id stands in for the record's address in hash-mode division.
    """

    def __init__(self, value_c38, key_id=0):
        self.value_c38 = value_c38
        self.key_id = key_id


class ChainEntry:
    """A query chain entry: key record pointer, then next at + 0x00."""

    def __init__(self, key, nxt=None):
        self.key = key
        self.nxt = nxt


class HashBucket:
    """One hash-bucket array slot: None means the slot itself is
    null (no match); a bucket whose head is None would fault in the
    window when it reads the head's key field."""

    def __init__(self, head=None):
        self.head = head


class LinearQuery:
    def __init__(self, head=None):
        self.head = head


class HashQuery:
    def __init__(self, divisor, buckets):
        self.divisor = divisor
        self.buckets = buckets


def value_of(key_record):
    """The 0x5f0a1d0 value callee: the qword at key-record + 0xc38."""
    return key_record.value_c38


def match_linear(node, query):
    """Linear mode (query + 0x18 == 0): True iff some chain entry's
    + 0x08 field equals the node's key record."""
    entry = query.head
    while entry is not None:
        if entry.key is node:
            return True
        entry = entry.nxt
    return False


def match_hash(node, query):
    """Hash mode (query + 0x18 != 0), following the window literally.

    The bucket index is the node's key divided by the bucket count
    (unsigned div; a zero divisor faults, modelled as raising).
    A null bucket slot means no match. The first entry's key is
    compared directly; every later entry's key must hash to the
    same bucket or the search ends as no match. On a hit the window
    tests the link that led to the entry ((%r9)); that link is the
    matching entry itself by construction, so a hit always counts
    here, and the zero arm is recorded as an open unknown.
    """
    if query.divisor == 0:
        raise ValueError(
            "hash mode with bucket count 0 faults on div (no guard)")
    bucket = node.key_id % query.divisor
    if bucket >= len(query.buckets):
        raise ValueError("bucket index outside the modelled array")
    slot = query.buckets[bucket]
    if slot is None:
        return False
    cur = slot.head
    if cur is None:
        raise ValueError(
            "bucket wrapper with null head would fault reading its key")
    if cur.key is node:
        return slot.head is not None
    while True:
        nxt = cur.nxt
        if nxt is None:
            return False
        if nxt.key.key_id % query.divisor != bucket:
            return False
        prev = cur
        cur = nxt
        if cur.key is node:
            return prev.nxt is not None


def scan(nodes, query):
    """The 0x5f134b0 scan: minimum nonzero 0xc38 value over the
    unmatched nodes, or 0 when there is none (including an empty
    outer list and a null query counting every node)."""
    best = 0
    for node in nodes:
        if query is None:
            matched = False
        elif isinstance(query, LinearQuery):
            matched = match_linear(node, query)
        elif isinstance(query, HashQuery):
            matched = match_hash(node, query)
        else:
            raise ValueError("unknown query shape")
        if matched:
            continue
        result = value_of(node)
        if result != 0 and (best == 0 or result < best):
            best = result
    return best


def caller_min(flag_nonzero, field948, scan_nodes, record8e8_value):
    """The 0x5d8bd30 caller, modelled whole from its own window.

    When the byte at object + 0x978 is zero it returns the field at
    object + 0x948 at once. Otherwise it scans the list at
    object + 0x8f0 with a null query, takes the scan result when it
    is nonzero and below field948, and then takes the smaller of
    that candidate and the + 0xc38 value of the record at
    object + 0x8e8, with a zero value leaving the candidate in
    place instead of forcing zero.
    """
    if not flag_nonzero:
        return field948
    s = scan(scan_nodes, None)
    candidate = s if (s != 0 and s < field948) else field948
    v = record8e8_value
    if v != 0 and v < candidate:
        return v
    return candidate
