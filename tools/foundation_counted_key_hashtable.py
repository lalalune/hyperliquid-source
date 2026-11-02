"""Python model of node #94 0x5160dd0: mutex-guarded counted-key
increment-or-insert over the hashtable at outer+0x40, with its
find-or-insert callee 0x5160c10 and that callee's rehash callee
0x5160ad0 (see research/work-items/RE-001-counted-key-hashtable-94/).

The outer struct is the same pending-key table shape as PR #1798's
erase sweep: a hashtable at +0x40 (buckets +0x00, bucket count
+0x08, before-begin next +0x10, element count +0x18, policy +0x20,
next-resize +0x28, single-bucket slot +0x30) guarded by the mutex
at +0x78. The window itself never touches the outer +0x00..+0x38
range, so that range is not modeled here.

Node layout (24 bytes): next +0x00, key +0x08, value +0x10. The
key is compared by 64-bit equality and the bucket is the key
modulo the bucket count (unsigned division); there is no separate
hash call, so the hash is the key itself for this instantiation.
Bucket entries hold the node before the first node of the bucket,
the sentinel address (table+0x10) when the first node is the table
head, or nothing when the bucket was never written.

The libstdc++ prime rehash policy behind the PLT
_M_need_rehash call is NOT pinned here: the model takes it as a
caller-supplied ``need_rehash(bucket_count, element_count, n)``
callable returning ``(need, new_count)``, and the tests supply
deterministic policies. What is pinned is the call contract:
arguments (policy, bucket count, element count, 1), the saved
next-resize snapshot taken before the call, the rehash call with
(table, new count, saved pointer), and the bucket recomputation
afterwards.
"""

MASK64 = (1 << 64) - 1

# Sentinel marker for a bucket entry holding the table+0x10 address.
SENTINEL = "sentinel"


class InconsistentTable(ValueError):
    """Raised where the binary would divide by zero or walk a
    table whose fields contradict each other (for example a zero
    bucket count, which the binary divides by)."""


class BadAlloc(MemoryError):
    """Operator new failure (binary: __throw_bad_alloc)."""


class BadArrayNewLength(MemoryError):
    """Oversized array request (binary: __throw_bad_array_new_length)."""


class LockError(RuntimeError):
    """Nonzero mutex lock result (binary: __throw_system_error)."""


class Node:
    """One 24-byte hashtable node: next, key, value."""

    def __init__(self, key, value=0, next_node=None):
        if not 0 <= key <= MASK64:
            raise ValueError("key must be an unsigned 64-bit value")
        self.key = key
        self.value = value & MASK64
        self.next = next_node

    def __repr__(self):
        return "Node(key=%r, value=%r)" % (self.key, self.value)


class HashTable:
    """The hashtable at outer+0x40.

    ``buckets[i]`` is None (never written), SENTINEL (the first
    node of the bucket is the table head), or the node before the
    first node of bucket i. ``head`` is table+0x10, ``count`` is
    table+0x08, ``element_count`` is table+0x18, ``next_resize``
    is table+0x28. ``single_slot`` tracks whether the bucket array
    is the +0x30 single-bucket slot (no operator delete[] on free)
    or a heap array. ``freed_old`` records the last old-array free
    for tests; ``freed_nodes`` records nodes freed on the insert
    exception path.
    """

    def __init__(self):
        self.count = 1
        self.buckets = [None]
        self.single_slot = True
        self.head = None
        self.element_count = 0
        self.next_resize = 0
        self.freed_old = False
        self.freed_nodes = []

    # -- before-node helpers (the sentinel's next is the head) --

    def _next_of(self, before):
        if before is SENTINEL:
            return self.head
        return before.next

    def _set_next_of(self, before, node):
        if before is SENTINEL:
            self.head = node
        else:
            before.next = node

    # -- rehash auxiliary 0x5160ad0 --

    def rehash_aux(self, new_count, saved_next_resize,
                   force_alloc_failure=False):
        """Migrate every node to a new bucket array of new_count.

        ``saved_next_resize`` is the snapshot of table+0x28 taken
        before the _M_need_rehash call. On any allocation failure
        the binary's catch pad restores table+0x28 from that
        snapshot and rethrows; ``force_alloc_failure`` exercises
        that pad in tests.
        """
        if new_count == 1:
            # Single-bucket arm: reuse the +0x30 slot, zeroed,
            # overflow checks skipped.
            new_buckets = [None]
            new_single = True
        else:
            # Overflow arms, checked before allocation.
            if new_count >> 60:
                self.next_resize = saved_next_resize
                if new_count >> 61:
                    raise BadArrayNewLength(
                        "bucket count %d overflows the array size"
                        % new_count)
                raise BadAlloc(
                    "bucket count %d in the bad_alloc window" % new_count)
            if force_alloc_failure:
                # Operator new threw: catch pad restores +0x28.
                self.next_resize = saved_next_resize
                raise BadAlloc("simulated operator new failure")
            new_buckets = [None] * new_count
            new_single = False

        old_head = self.head
        new_head = None
        prev_bucket = 0
        node = old_head
        self.head = None
        while node is not None:
            nxt = node.next
            bucket = node.key % new_count
            slot = new_buckets[bucket]
            if slot is not None:
                # Nonempty bucket: insert after the before-node.
                node.next = new_head if slot is SENTINEL else slot.next
                if slot is SENTINEL:
                    new_head = node
                else:
                    slot.next = node
            else:
                # Empty bucket: prepend to the head, entry is the
                # sentinel; when the displaced head is non-null,
                # the previous bucket's entry is repointed at this
                # node, then the previous index follows.
                old_new_head = new_head
                node.next = old_new_head
                new_head = node
                new_buckets[bucket] = SENTINEL
                if old_new_head is not None:
                    new_buckets[prev_bucket] = node
                prev_bucket = bucket
            node = nxt

        # Old array freed unless it was the single-bucket slot.
        self.freed_old = not self.single_slot
        self.buckets = new_buckets
        self.count = new_count
        self.single_slot = new_single
        self.head = new_head
        # Element count and policy are untouched by the aux.

    # -- find-or-insert 0x5160c10 --

    def _bucket_walk(self, key):
        """The lookup walk. Returns the node on a match, else None.

        The binary walks the bucket segment comparing keys, and
        stops at the chain end or at the first node whose bucket
        differs. The found arm re-loads the before-node's next and
        falls to the miss path on null; that arm cannot fire from
        a consistent walk (the node was just dereferenced) and is
        recorded here as a defensive branch only.
        """
        if self.count == 0:
            raise InconsistentTable("bucket count is zero (div by zero)")
        bucket = key % self.count
        entry = self.buckets[bucket]
        if entry is None:
            return None
        node = self._next_of(entry)
        if node is None:
            # Defensive arm from the binary's found path; a
            # consistent table never reaches it with entry set.
            return None
        prev = entry
        while node is not None:
            if node.key == key:
                return node
            nxt = node.next
            if nxt is None:
                return None
            if nxt.key % self.count != bucket:
                return None
            prev = node
            node = nxt
        return None

    def find_or_insert(self, key, need_rehash, rehash_aux=None):
        """Return the value-slot node for key, inserting a fresh
        (key, 0) node on a miss. ``need_rehash`` is the policy
        callable; ``rehash_aux`` defaults to this table's aux.
        On a rehash failure the fresh node is freed (the binary's
        exception pad calls operator delete on it) and the error
        propagates.
        """
        if self.count == 0:
            raise InconsistentTable("bucket count is zero (div by zero)")
        found = self._bucket_walk(key)
        if found is not None:
            return found
        node = Node(key, 0)
        saved_next_resize = self.next_resize
        need, new_count = need_rehash(self.count, self.element_count, 1)
        if need:
            aux = rehash_aux if rehash_aux is not None else self.rehash_aux
            try:
                aux(new_count, saved_next_resize)
            except (BadAlloc, BadArrayNewLength):
                self.freed_nodes.append(node)
                raise
        # Bucket recomputed after any rehash.
        bucket = key % self.count
        entry = self.buckets[bucket]
        if entry is not None:
            # Insert after the before-node; entry unchanged.
            node.next = self._next_of(entry)
            self._set_next_of(entry, node)
        else:
            # Head path: the new node becomes the head, the old
            # head's bucket entry (when there is an old head) is
            # repointed at it, then this bucket's entry is the
            # sentinel.
            old_head = self.head
            node.next = old_head
            self.head = node
            if old_head is not None:
                self.buckets[old_head.key % self.count] = node
            self.buckets[bucket] = SENTINEL
        self.element_count += 1
        return node


class FakeMutex:
    """Stand-in for the pthread mutex at outer+0x78."""

    def __init__(self, lock_result=0):
        self.lock_result = lock_result
        self.lock_calls = 0
        self.unlock_calls = 0

    def lock(self):
        self.lock_calls += 1
        return self.lock_result

    def unlock(self):
        self.unlock_calls += 1
        return 0


class CountedKeyTable:
    """The outer struct: hashtable at +0x40, mutex at +0x78."""

    def __init__(self, mutex=None):
        self.table = HashTable()
        self.mutex = mutex if mutex is not None else FakeMutex()


def increment_or_insert(outer, key, need_rehash, rehash_aux=None):
    """Window 0x5160dd0: increment key's count, or insert it
    with count 1. Returns ("found", node) or ("inserted", node).
    The mutex is unlocked on every path, including the exception
    path (the binary's 0x5160dc0 cleanup stub); a lock failure
    throws before anything is touched.
    """
    table = outer.table
    if outer.mutex.lock() != 0:
        raise LockError("mutex lock failed (system_error)")
    try:
        if table.element_count == 0:
            # Linear chain walk from the before-begin next.
            node = table.head
            while node is not None:
                if node.key == key:
                    node.value = (node.value + 1) & MASK64
                    return ("found", node)
                node = node.next
        else:
            if table.count == 0:
                raise InconsistentTable(
                    "bucket count is zero (div by zero)")
            bucket = key % table.count
            entry = table.buckets[bucket]
            if entry is not None:
                node = table._next_of(entry)
                prev = entry
                while node is not None:
                    if node.key == key:
                        node.value = (node.value + 1) & MASK64
                        return ("found", node)
                    nxt = node.next
                    if nxt is None:
                        break
                    if nxt.key % table.count != bucket:
                        break
                    prev = node
                    node = nxt
        node = table.find_or_insert(key, need_rehash, rehash_aux)
        node.value = 1
        return ("inserted", node)
    finally:
        outer.mutex.unlock()
