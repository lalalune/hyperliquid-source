"""Python model of node #115 routine 0x5d52e60 (RE-001 drain-and-flush).

The routine takes a holder pointer in rdi. It drains two pending lists,
then repeatedly removes the head record of a hash-linked record set,
emitting one callback per record, until the record count reaches zero,
and finishes with a tail counter decrement, a subobject call and a
tail jump. Callee implementations are call-shape only here: the list
element destructors (0x5f04800, 0x5d8d820), the range builders
(0x5d4a6a0), the guard pair (0x606ca40, 0x60d52f0), the tail subobject
call (0x60d57c0) and the per-record callback (0x5e4b7c0) enter the
model as operations, not as computed results.

Holder fields (offsets pinned, kinds not pinned):
  +0x700  subobject passed to the guard pair
  +0xa10  object passed to the tail subobject call
  +0x1318 record-table base, +0x1320 table modulus, +0x1328 record head,
          +0x1330 record count (qword), +0x1444 tail counter (dword)
  +0x1398/+0x13a0/+0x13a8/+0x13b0/+0x13b8  list A cursor/pair/base/chain/end
  +0x13e8/+0x13f0/+0x13f8/+0x1400/+0x1408  list B cursor/pair/base/chain/end

Record fields: +0x00 next pointer, +0x08 bucket key, +0x10 string A
(ptr/size/capacity at +0x10/+0x18/+0x20), +0x30 string B (at
+0x30/+0x38/+0x40), +0x50 dword callback argument, +0x58 qword callback
argument, +0x60 dword callback argument; records are freed with size
0x68. A string is in short form when its data pointer equals its own
base + 0x10, in which case disposal frees nothing; otherwise disposal
is a sized delete of (pointer, capacity + 1).

Lists are modelled as a sequence of chunks; each chunk is a list of
elements (None for a null slot). Popping the last element of a chunk
frees that chunk's 0x200 buffer (a chunk_reset operation) and popping
continues from the next chunk. The chunk-chain fields themselves are
recorded literally in the packet; their linking invariant is an
assumption, not a pinned claim.

The record-table walk treats the head-field address as a possible
predecessor (HEAD): a bucket slot may hold HEAD, meaning the head
record is that bucket's first element, and storing a successor into
HEAD advances the head. flush returns (ops, state) where state holds
the final head, record count, tail counter and table.
"""

HEAD = "HEAD"

GUARD_OPEN = 0x606CA40
GUARD_CLOSE = 0x60D52F0
DESTROY_A = 0x5F04800
DESTROY_B = 0x5D8D820
BUILD = 0x5D4A6A0
EMIT = 0x5E4B7C0
TAIL_CALL = 0x60D57C0
RECORD_SIZE = 0x68
CHUNK_SIZE = 0x200


def _dispose_string(label, string):
    """Disposal operation for a (text, heap_capacity_or_None) string."""
    _text, heap_cap = string
    if heap_cap is None:
        return ("dispose_string", label, "short")
    return ("dispose_string", label, "sized", heap_cap + 1)


def drain(chunks, label, destroy_size, entry_guard=True):
    """Drain one pending list; return the operation list.

    chunks is a list of chunks (each a list of elements, None = null
    slot). List A starts with a guard open; list B does not (its first
    pop follows list A's trailing open directly). Every pop is
    followed by a guard close and then the destroy or the null skip,
    and a guard open follows every element; the trailing open reads
    the cursor that sees the end. Popping the last slot of a chunk
    frees that chunk's 0x200 buffer before the guard close.
    """
    ops = []
    if entry_guard:
        ops.append(("guard_open", GUARD_OPEN))
    for chunk in chunks:
        if not chunk:
            continue
        for position, element in enumerate(chunk):
            if position == len(chunk) - 1:
                ops.append(("chunk_reset", CHUNK_SIZE))
            ops.append(("guard_close", GUARD_CLOSE))
            if element is None:
                ops.append(("skip_null", label))
            else:
                ops.append(("destroy", label, destroy_size, element))
            ops.append(("guard_open", GUARD_OPEN))
    return ops


def unlink(table, head, record_id, records, modulus):
    """Remove record_id from its bucket chain; return (head, ops).

    table maps bucket index to a node id or HEAD. records maps node id
    to a dict with keys "next" and "key". The walk follows next links
    from the bucket slot until a node whose next equals the record;
    that node (or HEAD) is the predecessor. Stores are emitted in the
    binary's order: cross-bucket predecessor store, head store, bucket
    clear, predecessor link.
    """
    ops = []
    record = records[record_id]
    index = record["key"] % modulus
    bucket_head = table.get(index)

    def nxt(node):
        return head if node == HEAD else records[node]["next"]

    cur = bucket_head
    while True:
        following = nxt(cur)
        if following == record_id:
            pred = cur
            break
        if following is None:
            raise ValueError("record not present in its bucket chain")
        cur = following
    succ = record["next"]
    if pred == bucket_head:
        if succ is None:
            if pred == HEAD:
                head = succ
                ops.append(("store", ("head",), succ))
            table[index] = None
            ops.append(("store", ("bucket", index), None))
        else:
            succ_index = records[succ]["key"] % modulus
            if succ_index != index:
                table[succ_index] = pred
                ops.append(("store", ("bucket", succ_index), pred))
                if bucket_head == HEAD:
                    head = succ
                    ops.append(("store", ("head",), succ))
                table[index] = None
                ops.append(("store", ("bucket", index), None))
        if pred == HEAD:
            head = succ
        else:
            records[pred]["next"] = succ
        ops.append(("store", ("next", pred), succ))
    else:
        if succ is not None:
            succ_index = records[succ]["key"] % modulus
            if succ_index != index:
                table[succ_index] = pred
                ops.append(("store", ("bucket", succ_index), pred))
        if pred == HEAD:
            head = succ
        else:
            records[pred]["next"] = succ
        ops.append(("store", ("next", pred), succ))
    return head, ops


def flush(chunks_a, chunks_b, records, table, modulus, head, count,
          tail_counter, build=None):
    """Run the whole 0x5d52e60 behaviour; return (ops, state).

    records maps node id to a dict with keys "next", "key", "str_a",
    "str_b" (each a (text, heap_capacity_or_None) pair), "f50", "f58",
    "f60". table maps bucket index to a node id or HEAD. build, when
    given, maps a record string's text to an output (text,
    heap_capacity_or_None) pair; by default outputs stay in short form.
    """
    if build is None:
        def build(text):
            return (text, None)
    records = {k: dict(v) for k, v in records.items()}
    table = dict(table)
    ops = []
    ops.extend(drain(chunks_a, "A", 0x58, entry_guard=True))
    ops.extend(drain(chunks_b, "B", 0x290, entry_guard=False))
    while count > 0:
        if head is None:
            raise ValueError("record count nonzero but head is null")
        record = records[head]
        out_a = build(record["str_a"][0])
        ops.append(("build", "A", record["str_a"][0]))
        out_b = build(record["str_b"][0])
        ops.append(("build", "B", record["str_b"][0]))
        removed = head
        head, link_ops = unlink(table, head, removed, records, modulus)
        ops.extend(link_ops)
        ops.append(_dispose_string("B", record["str_b"]))
        ops.append(_dispose_string("A", record["str_a"]))
        ops.append(("free", RECORD_SIZE, removed))
        count -= 1
        ops.append(("count", count))
        ops.append(("guard_close", GUARD_CLOSE))
        ops.append(("emit", EMIT, record["f60"], out_a[0], out_b[0],
                    record["f50"], record["f58"]))
        ops.append(("guard_open", GUARD_OPEN))
        ops.append(_dispose_string("outB", out_b))
        ops.append(_dispose_string("outA", out_a))
    tail_counter -= 1
    ops.append(("tail_count", tail_counter))
    ops.append(("tail_call", TAIL_CALL))
    ops.append(("tail_jump", GUARD_CLOSE))
    state = {"head": head, "count": count, "tail_counter": tail_counter,
             "table": table}
    return ops, state
