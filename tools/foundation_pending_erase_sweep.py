"""Model of node #94 0x5160560: pending-key erase sweep.

Stdlib only. The model pins the behavior recorded in
research/work-items/RE-001-pending-erase-sweep-94/: a pending
vector of (key, floor) elements is swept in order; each element's
key is looked up in a hash table, erased only when the found
node's value is >= the floor, and the vector is compacted by
shifting the tail left. The sweep returns 0 when the vector is
fully swept, or the first element key it could not erase.

Field types are deliberately neutral: keys, floors, and values
are compared as unsigned integers, matching the binary's
unsigned comparisons, and no semantic type is claimed.

The bucket-predecessor / before-begin sentinel fixups mirror
the binary's removal exactly, including the sole-node-of-bucket
arm (old bucket cleared, sentinel advanced when the old bucket
entry was the sentinel).
"""

SENTINEL = "SENTINEL"
"""Stands for the address of the outer +0x50 before-begin node,
which bucket entries use as a predecessor value when the
bucket's first node is the chain head."""


class InconsistentTable(Exception):
    """A table shape the binary does not guard: a bucket
    predecessor with no next node, or a removal target that is
    not reachable from its bucket predecessor. The binary would
    fault on such a table; the model refuses it instead."""


class HashNode:
    """One 24-byte hash node: next (+0x00), key (+0x08),
    value (+0x10). ``next`` is another HashNode or None."""

    def __init__(self, key, value, next_node=None):
        self.key = key
        self.value = value
        self.next = next_node

    def __repr__(self):
        return "HashNode(key=%r, value=%r)" % (self.key, self.value)


class SweepTable:
    """The hash table at outer +0x40..+0x58.

    ``buckets`` entries are None (empty bucket), a HashNode
    (the predecessor of the bucket's first node), or SENTINEL
    (the bucket's first node is the chain head). ``count`` is
    the +0x58 element count; when it is 0 the lookup is a
    linear chain walk instead of a bucket lookup.
    """

    def __init__(self, buckets, before_begin_next, count):
        self.buckets = list(buckets)
        self.before_begin_next = before_begin_next
        self.count = count

    @property
    def bucket_count(self):
        return len(self.buckets)


def _next_of(table, pred):
    if pred is SENTINEL:
        return table.before_begin_next
    return pred.next


def _set_next(table, pred, node):
    if pred is SENTINEL:
        table.before_begin_next = node
    else:
        pred.next = node


def _lookup_chain(table, key):
    """Count-zero path: linear walk from before_begin_next."""
    cur = table.before_begin_next
    while cur is not None:
        if cur.key == key:
            return cur
        cur = cur.next
    return None


def _lookup_bucket(table, key):
    """Count-nonzero path: bucket walk with the binary's order
    (first node: key only; later nodes: bucket check, then key).
    Returns the found node, or None when the window bails."""
    bucket_count = table.bucket_count
    if bucket_count == 0:
        raise InconsistentTable("bucket lookup with zero bucket count")
    index = key % bucket_count
    pred = table.buckets[index]
    if pred is None:
        return None
    cur = _next_of(table, pred)
    if cur is None:
        raise InconsistentTable("bucket predecessor with no next node")
    if cur.key == key:
        return cur
    while True:
        cur = cur.next
        if cur is None:
            return None
        if cur.key % bucket_count != index:
            return None
        if cur.key == key:
            return cur


def _remove(table, target, key):
    """Unlink ``target`` with the binary's fixups. Caller has
    already applied the floor guard."""
    bucket_count = table.bucket_count
    if bucket_count == 0:
        raise InconsistentTable("removal with zero bucket count")
    index = key % bucket_count
    pred = table.buckets[index]
    if pred is None:
        raise InconsistentTable("removal from an empty bucket")
    cur = pred
    while True:
        nxt_of_cur = _next_of(table, cur)
        if nxt_of_cur is target:
            break
        if nxt_of_cur is None:
            raise InconsistentTable("target not reachable from bucket")
        cur = nxt_of_cur
    nxt = target.next
    first = cur is pred
    if first:
        if nxt is None:
            if cur is SENTINEL:
                table.before_begin_next = None
            table.buckets[index] = None
        elif nxt.key % bucket_count != index:
            table.buckets[nxt.key % bucket_count] = cur
            if table.buckets[index] is SENTINEL:
                table.before_begin_next = nxt
            table.buckets[index] = None
        _set_next(table, cur, nxt)
    else:
        if nxt is not None and nxt.key % bucket_count != index:
            table.buckets[nxt.key % bucket_count] = cur
        _set_next(table, cur, nxt)
    table.count -= 1


def sweep(pending, table):
    """Sweep ``pending`` (a list of (key, floor) pairs, mutated
    in place by compaction) against ``table``.

    Returns 0 when every element was erased, or the first key
    that could not be erased (not found, or found node's value
    below the floor). Elements erased before a bail stay erased.
    """
    i = 0
    while i < len(pending):
        key, floor = pending[i]
        if table.count == 0:
            found = _lookup_chain(table, key)
        else:
            found = _lookup_bucket(table, key)
        if found is None or found.value < floor:
            return key
        _remove(table, found, key)
        del pending[i]
    return 0


def caller_min(getter_result, sweep_result, second_result):
    """The twin wrappers' combination (census only): the minimum
    of the getter result, the sweep result when nonzero, and
    the second call's result when nonzero. Zeros count as
    absent, not as minima."""
    candidates = [getter_result]
    if sweep_result != 0:
        candidates.append(sweep_result)
    if second_result != 0:
        candidates.append(second_result)
    return min(candidates)
