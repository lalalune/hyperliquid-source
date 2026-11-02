"""Model of the node #115 hash-table rehash at 0x5f0e520 (RE-001).

Window 0x5f0e520..0x5f0e65d (317 bytes), extracted from the
digest-verified work binary work/hl-node-115.bin. Packet:
research/work-items/RE-001-hash-rehash-115/.

Layout (this-relative, as observed in-window):
  +0x00  bucket-array pointer (old array on entry, new array on exit)
  +0x08  bucket count (old on entry, new count on exit)
  +0x10  list-head field (old head on entry, detached to 0, rebuilt)
  +0x28  field restored by the exception landing pad only (see below)
  +0x30  embedded single-bucket slot (the new array when count == 1)

Nodes form one global singly linked list via their +0x00 next field
and carry their hash code in +0x20. Bucket slots do NOT hold first
nodes: each slot holds the node PRECEDING the bucket's first node
(the "before" node). For a bucket whose first node is the list head,
the slot holds the address of the head field itself (+0x10) — the
HEAD sentinel below.

Literal in-window behavior, in order:
  1. count == 1: the embedded slot (+0x30) is cleared to 0 and used
     as the one-slot new array; no heap allocation happens.
  2. count >= 2**60: count in [2**60, 2**61) raises BadAlloc, count
     >= 2**61 raises BadArrayNewLength (the byte size count*8 would
     overflow). Otherwise a count*8-byte array is allocated and
     zeroed (operator new + memset).
  3. The old list is detached (head field zeroed) and every node is
     reinserted: bucket = hash % new_count (a 64-bit div; count 0
     with a non-empty list faults there, modelled as
     ZeroDivisionError). For an occupied bucket the node is spliced
     directly after the slot's before-node. For an empty bucket the
     node becomes the new list head, the slot takes the HEAD
     sentinel, and — only when the node has a successor — the slot
     of the most recently started bucket (initially bucket 0) is
     rewritten to this node; that bucket index is then updated to
     the current bucket. The occupied path does NOT update it.
  4. The old array is released with sized delete[] (old_count * 8
     bytes) unless the old array pointer equals the embedded slot
     address (+0x30); then the new count and array are installed.

Exception path (landing pad 0x5f0e630, covering the region from the
operator-new call through the install, per the decoded LSDA at
0x414a94): any exception there runs __cxa_begin_catch, copies *r12
into this+0x28, and rethrows. r12 is the new array once allocation
succeeded, and the original third argument when allocation itself
throws — that argument is dead on the normal path (overwritten by
the new-array pointer right after a successful allocation), so its
meaning is recorded as unknown in the packet and is NOT modelled
here; the model propagates allocation failures as exceptions.
"""

HEAD = object()


class BadAlloc(Exception):
    """__throw_bad_allocv: count in [2**60, 2**61)."""


class BadArrayNewLength(Exception):
    """__throw_bad_array_new_lengthv: count >= 2**61."""


class Node:
    """One table node: hash code (+0x20) and next pointer (+0x00)."""

    def __init__(self, hash_code, nxt=None):
        self.hash_code = hash_code
        self.next = nxt

    def __repr__(self):
        return "Node(%r)" % (self.hash_code,)


class Table:
    """The table object. `buckets` slots hold HEAD, a Node, or None.

    `embedded` is True when `buckets` is the embedded single slot
    (installed by a previous count-1 rehash), which decides whether
    the old array is freed. `field_0x28` is untouched by the normal
    path; only the landing pad writes it.
    """

    def __init__(self, buckets, bucket_count, head,
                 embedded=False, field_0x28=None):
        self.buckets = buckets
        self.bucket_count = bucket_count
        self.head = head
        self.embedded = embedded
        self.field_0x28 = field_0x28


def rehash(table, new_count):
    """Rehash `table` to `new_count` buckets, following 0x5f0e520."""
    if new_count == 1:
        new_buckets = [None]
        embedded_new = True
    elif new_count >= (1 << 60):
        if new_count >= (1 << 61):
            raise BadArrayNewLength(new_count)
        raise BadAlloc(new_count)
    else:
        new_buckets = [None] * new_count
        embedded_new = False

    # Detach the old list (this+0x10 = 0) and walk it in order.
    nodes = []
    cur = table.head
    while cur is not None:
        nodes.append(cur)
        cur = cur.next
    table.head = None

    prev_started = 0
    for node in nodes:
        if new_count == 0:
            raise ZeroDivisionError("hash %% 0: div faults in-window")
        bkt = node.hash_code % new_count
        before = new_buckets[bkt]
        if before is not None:
            if before is HEAD:
                node.next = table.head
                table.head = node
            else:
                node.next = before.next
                before.next = node
        else:
            node.next = table.head
            table.head = node
            new_buckets[bkt] = HEAD
            if node.next is not None:
                new_buckets[prev_started] = node
            prev_started = bkt

    freed = not table.embedded
    table.buckets = new_buckets
    table.bucket_count = new_count
    table.embedded = embedded_new
    return {"freed_old_array": freed, "bucket_count": new_count,
            "embedded": embedded_new}
