"""Python model of node #115 hash-table find-or-insert (0x5f0e660).

RE-001 work item. The model follows the window's observed behavior,
not a C++ spelling: the exact standard-library name of the container
is inference, the mechanics below are the window's.

Observed layout
---------------
Container (``this``):
  +0x00  bucket array (slots hold a before-node, or the address of
         the +0x10 head field for a bucket whose first node is the
         list head, or null for a never-touched bucket)
  +0x08  bucket count
  +0x10  list-head field (the before-begin node)
  +0x18  element count (incremented only on insert, never on a hit)
  +0x20  rehash-policy object (passed to _M_need_rehash)
  +0x28  field whose value is copied to a stack slot before
         _M_need_rehash and whose address is passed to the rehash
         callee (0x5f0e520, mapped by the neighbouring RE-001 packet);
         the callee's landing pad writes the saved value back to
         this+0x28, so the argument reads as a restore pointer.

Node:
  +0x00  next node (or null)
  +0x08  key pointer (the key bytes in this model)
  +0x10  key length
  +0x18  mapped-value slot; the function returns its address
  +0x20  hash code (compared as a full 64-bit word against the
         zero-extended 32-bit hash from the hash call)

Behavior (one function, end to end)
-----------------------------------
1. Hash the key: the window calls 0x61c34a0 with (key pointer,
   key length, 0x18d). The hash body is cited by contract here (as
   in the neighbouring packets); the model takes the resulting
   32-bit hash as an input, so the table mechanics are testable
   without re-proving the hash.
2. Bucket = hash % bucket_count (a 64-bit division with no zero
   guard in-window; a zero bucket count faults, mirrored here by
   Python's ZeroDivisionError).
3. Walk the bucket's run: from the slot's before-node, each
   candidate must match the full hash code, then the key length,
   then the key bytes (memcmp). Advancing moves to the next node;
   the walk ends (insert path) when the next node is null or
   belongs to a different bucket.
4. Hit: return the node's mapped-value slot (the node object here).
5. Miss: allocate a 0x28-byte node, copy the 16-byte key record,
   zero the mapped-value slot, ask _M_need_rehash(bucket_count,
   element_count, 1); when it reports a new count, call the rehash
   callee with (new_count, saved this+0x28) and recompute the
   bucket under the new count. Then splice the node in:
   - empty slot: the node becomes the list head; the old head's
     bucket slot (when the old head exists) is rewritten to the
     new node first, then this bucket's slot is set to the head
     field address (so a same-bucket old head ends up pointing at
     the head field, not at the new node);
   - occupied slot: the slot value is re-read at insert time and
     the node is spliced directly after that before-node (or after
     the head field when the slot holds the head address) -- even
     when the walk ended at a foreign-bucket node or at null, the
     splice position comes from the slot, not from the walk.
   The element count increments and the new node's mapped-value
   slot address is returned.
6. Cleanup: a throw from _M_need_rehash or the rehash callee runs
   the landing pad at 0x5f0e84e, which deletes the new node with
   the sized operator delete[] (0x28 bytes) and resumes unwinding.
   Throws from the hash/memcmp region have no landing pad in the
   LSDA, and operator new throwing needs no cleanup (nothing is
   stored yet). The model does not raise through step 6; the pad
   is recorded in the packet, not simulated.

The rehash helper below is a reference aid implementing the
placement rules recorded by the neighbouring rehash packet; the
claim of this packet is the call site, the argument passing and
the bucket recomputation, not the helper's slot bytes. Tests use
it only to prove that find/insert still works across a rebuild.
"""

HEAD = object()  # marker for "the slot holds the head-field address"


class Node(object):
    """One hash-table node (offsets +0x00/+0x08/+0x10/+0x18/+0x20)."""

    def __init__(self, key, hash_code):
        self.key = key            # bytes; +0x08 pointer, +0x10 length
        self.hash_code = hash_code  # +0x20
        self.value = 0            # +0x18 mapped-value slot
        self.next = None          # +0x00

    def __repr__(self):
        return "Node(%r, hash=%r)" % (self.key, self.hash_code)


class Table(object):
    """Container fields +0x00/+0x08/+0x10/+0x18 (+0x28 saved field)."""

    def __init__(self, bucket_count, field_0x28=None):
        self.buckets = [None] * bucket_count  # +0x00, +0x08 = len
        self.head = None                      # +0x10
        self.size = 0                         # +0x18
        self.field_0x28 = field_0x28          # +0x28 (opaque)

    def nodes_in_order(self):
        out = []
        cur = self.head
        while cur is not None:
            out.append(cur)
            cur = cur.next
        return out


def _deref(marker, head):
    """What a slot's before-node points at: the bucket's first node."""
    if marker is HEAD:
        return head
    return marker.next


def _set_next(marker, table, node):
    """Store ``node`` as the successor of a slot's before-node."""
    if marker is HEAD:
        table.head = node
    else:
        marker.next = node


def _reference_rehash(table, new_count):
    """Rebuild the bucket array following the rehash packet's rules.

    Detach the list, then place each node in old-list order:
    bucket = hash % new_count; an occupied slot splices the node
    directly after its before-node; an empty slot makes the node
    the new head, stores the head-field address in the slot, and
    (only when the node has a successor in the new list) rewrites
    the most-recently-started bucket's slot to the node. The
    single-bucket case (new_count == 1) falls out of the same
    rules with a one-slot array.
    """
    old_nodes = table.nodes_in_order()
    table.head = None
    table.buckets = [None] * new_count
    prev_started = 0
    for node in old_nodes:
        bucket = node.hash_code % new_count  # div fault on 0, as in-window
        slot = table.buckets[bucket]
        if slot is not None:
            node.next = _deref(slot, table.head)
            _set_next(slot, table, node)
        else:
            node.next = table.head
            table.head = node
            table.buckets[bucket] = HEAD
            if node.next is not None:
                table.buckets[prev_started] = node
            prev_started = bucket


def find_or_insert(table, key, hash_code, need_rehash, rehash=None):
    """Find ``key`` or insert it; return ``(node, was_inserted)``.

    ``need_rehash(bucket_count, element_count, 1)`` must return
    ``(needed, new_count)`` like _M_need_rehash. ``rehash`` defaults
    to :func:`_reference_rehash` and is called as
    ``rehash(table, new_count, saved_field_0x28)``.
    """
    if rehash is None:
        def rehash(t, nc, _saved):
            _reference_rehash(t, nc)
    count = len(table.buckets)
    bucket = hash_code % count  # no zero guard in-window
    marker = table.buckets[bucket]
    if marker is not None:
        cur = _deref(marker, table.head)
        while True:
            if cur is None:
                break
            if cur.hash_code != hash_code:
                pass  # advance below
            elif len(cur.key) != len(key) or cur.key != key:
                pass  # advance below (length check, then memcmp)
            else:
                return cur, False
            nxt = cur.next
            if nxt is None:
                break
            if nxt.hash_code % count != bucket:
                break  # the bucket's run has ended
            cur = nxt
    # Miss: allocate the node, copy the key record, zero the value.
    # NOTE: the splice below re-reads the slot value (as the window
    # does at 0x5f0e7af); it does NOT splice after the last walked
    # node. A run that ends at a foreign-bucket node still inserts
    # directly after the bucket's before-node.
    node = Node(key, hash_code)
    saved = table.field_0x28  # copied to a stack slot before the call
    needed, new_count = need_rehash(len(table.buckets), table.size, 1)
    if needed:
        rehash(table, new_count, saved)
        bucket = hash_code % len(table.buckets)  # recomputed, as in-window
        marker = table.buckets[bucket]
    if marker is None:
        old_head = table.head
        table.head = node
        node.next = old_head
        if old_head is not None:
            # Old head's bucket slot first, then this slot: a
            # same-bucket old head ends up pointing at the head
            # field, not at the new node.
            table.buckets[old_head.hash_code % len(table.buckets)] = node
        table.buckets[bucket] = HEAD
    else:
        node.next = _deref(marker, table.head)
        _set_next(marker, table, node)
    table.size += 1
    return node, True
