"""Model for node #94 0x515a820 (RE-001-rehash-aux-94).

The window rehashes a hash table into a new bucket array: it
allocates (or reuses the table's single-bucket slot for a
requested count of 1), migrates every node of the old chain into
the new array by its cached hash modulo the new count, frees the
old array unless it was the single-bucket slot, and commits the
new count and base. On allocation failure it restores the
table's next-resize field from the caller's saved copy and
rethrows.

The expectations are transcribed from the window's disassembly
(see research/work-items/RE-001-rehash-aux-94/): the table and
node layouts, the single-bucket and overflow arms, the
empty/nonempty bucket insertion rules, the previous-bucket
fixup, the old-array free rule, and the catch-arm restore. The
model pins the algorithm, not an execution of the target binary
(no execution is available here).
"""

# The sentinel object stands for the address of the table+0x10
# field (the before-begin slot). A bucket entry holding it means
# the bucket's before-node is that field, whose contents are the
# table head pointer.


class Sentinel:
    def __repr__(self):
        return "SENTINEL"


SENTINEL = Sentinel()


class BadArrayNewLength(Exception):
    """Requested count >= 2**61: the byte size itself overflowed."""


class BadAlloc(Exception):
    """Requested count in [2**60, 2**61): too large to allocate."""


class AllocationFailed(Exception):
    """Operator new threw; the table's next-resize was restored."""


class Node:
    """One hash-table node: chain next pointer and cached hash."""

    def __init__(self, node_id, cached_hash, nxt=None):
        self.id = node_id
        self.cached_hash = cached_hash
        self.next = nxt

    def __repr__(self):
        return "Node(%r)" % (self.id,)


class Table:
    """A hash table as the window sees it.

    buckets: a list of bucket entries (None, SENTINEL, or a Node).
    bucket_count: the table+0x08 count.
    head: the table+0x10 before-begin next pointer (a Node or None).
    element_count: table+0x18, untouched by the window.
    next_resize: table+0x28, restored on allocation failure.
    single_bucket: the table+0x30 one-slot array (a 1-list).
    buckets_is_single: True when buckets is the single slot.
    freed: records old arrays the window freed (True = heap array
    freed, False = single slot kept).
    """

    def __init__(self, buckets, bucket_count, head, element_count=0,
                 next_resize=0, buckets_is_single=False):
        self.buckets = buckets
        self.bucket_count = bucket_count
        self.head = head
        self.element_count = element_count
        self.next_resize = next_resize
        self.single_bucket = [None]
        self.buckets_is_single = buckets_is_single
        self.freed = []

    def chain(self):
        """Node ids in global chain order from the head."""
        out = []
        node = self.head
        while node is not None:
            out.append(node.id)
            node = node.next
        return out

    def bucket_entries(self):
        """Bucket entries rendered as None, 'S', or a node id."""
        out = []
        for entry in self.buckets:
            if entry is None:
                out.append(None)
            elif entry is SENTINEL:
                out.append("S")
            else:
                out.append(entry.id)
        return out


def _before_next(table, before):
    """The next pointer a before-node points at."""
    if before is SENTINEL:
        return table.head
    return before.next


def _set_before_next(table, before, node):
    """Point a before-node at the given node."""
    if before is SENTINEL:
        table.head = node
    else:
        before.next = node


def rehash_aux(table, new_count, saved_next_resize, alloc_fail=False):
    """Run the 0x515a820 rehash on the table, in place.

    new_count is the requested bucket count; saved_next_resize
    is the value the caller's saved slot holds (the window reads
    it only on allocation failure). alloc_fail simulates operator
    new throwing. Returns a summary dict.
    """
    if new_count == 0:
        # The window has no guard for this; its migration divides
        # by the new count. The model refuses instead of modelling
        # a fault.
        raise ValueError("new bucket count 0 would divide by zero")
    if new_count == 1:
        # Single-bucket arm: no allocation, no overflow check.
        new_buckets = table.single_bucket
        new_buckets[0] = None
        is_single = True
    else:
        if new_count >= (1 << 60):
            if new_count >= (1 << 61):
                raise BadArrayNewLength(
                    "bucket count %d overflows the byte size"
                    % new_count)
            raise BadAlloc("bucket count %d too large to allocate"
                           % new_count)
        if alloc_fail:
            # Catch arm: restore next-resize, then rethrow; the
            # table's buckets, count and head are untouched.
            table.next_resize = saved_next_resize
            raise AllocationFailed("operator new failed")
        new_buckets = [None] * new_count
        is_single = False

    old_buckets = table.buckets
    old_count = table.bucket_count
    old_is_single = table.buckets_is_single

    # Migration: walk the old chain in its existing order.
    node = table.head
    table.head = None
    prev_bucket = 0
    while node is not None:
        nxt = node.next
        bucket = node.cached_hash % new_count
        before = new_buckets[bucket]
        if before is not None:
            node.next = _before_next(table, before)
            _set_before_next(table, before, node)
        else:
            node.next = table.head
            table.head = node
            new_buckets[bucket] = SENTINEL
        if node.next is None:
            new_buckets[prev_bucket] = node
        prev_bucket = bucket
        node = nxt

    # Epilogue: free the old array unless it was the single slot,
    # then commit the new count and base.
    table.freed.append(not old_is_single)
    table.buckets = new_buckets
    table.bucket_count = new_count
    table.buckets_is_single = is_single
    return {
        "new_count": new_count,
        "old_count": old_count,
        "old_array_freed": not old_is_single,
        "chain": table.chain(),
        "buckets": table.bucket_entries(),
    }
