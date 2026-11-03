"""Model of node #115 routine 0x5d52cf0: threshold flag clear.

Pinned from the digest-verified node #115 binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The routine takes two arguments: an owner pointer in rdi and a
threshold in rsi. End to end, in order:

1. Acquire: call 0x60d5390 with owner +0x9c8. That callee is a
   no-op stub (endbr64; ret, FDE 0x60d5390..0x60d5395): the call
   returns at once and changes nothing observable.
2. Scan: walk the owner's entry sequence, which is chunked in
   0x200-byte blocks of 0x20-byte entries. The walk state is
   read from the owner: cursor at +0xb30, current chunk end at
   +0xb40, end cursor at +0xb50, and the current chunk's map
   slot at +0xb48 (the next chunk is taken from the following
   slot, +8 at a time). For each entry, in order:
   - if the cursor equals the end cursor, stop;
   - if the entry's first qword (its key) is unsigned-less
     than the threshold, stop at once -- later entries, in this
     and later chunks, are untouched;
   - otherwise write 0 to the byte at entry +0x10 and advance
     the cursor by 0x20;
   - when the cursor reaches the current chunk end, take the
     next chunk base from the next map slot, set the chunk end
     to base + 0x200, and stop if that base equals the end
     cursor, else continue with the new chunk's first entry.
   The field at +0xb38 (between cursor and chunk end) is never
   read, and no entry byte other than +0x10 is written.
3. Broadcast: tail-jump to 0x60d57c0 with owner +0xb70. That
   callee's first action is pthread_cond_broadcast on its
   argument, so the +0xb70 member is broadcast on; the callee's
   internal error path (fprintf + abort on an unexpected
   broadcast result) is callee-internal and not modelled.

NOT modelled: what the owner, the entries, the keys, or the
+0x10 flag byte denote, or the order the entries are stored
in beyond the stop rule above. The deque-shaped reading of the
fields (cursor / chunk end / end cursor / map slot) is an
inference from the walk shape, recorded as such; the model
implements the literal transition rules. A null owner raises,
matching the binary's unconditional reads; a cursor or map
slot the model cannot resolve raises instead of reading past
the sequence unchecked, as the binary would.
"""

ENTRY_SIZE = 0x20
CHUNK_SIZE = 0x200
FLAG_OFFSET = 0x10
CURSOR_OFFSET = 0xB30
CHUNK_END_OFFSET = 0xB40
END_OFFSET = 0xB50
NODE_SLOT_OFFSET = 0xB48
LOCK_OFFSET = 0x9C8
COND_OFFSET = 0xB70
ACQUIRE_CALLEE = 0x60D5390
BROADCAST_CALLEE = 0x60D57C0
MASK64 = 0xFFFFFFFFFFFFFFFF


class Entry:
    """One 0x20-byte entry: a key qword and a flag byte at +0x10."""

    def __init__(self, key, flag=1):
        self.key = key & MASK64
        self.flag = flag


class Chunk:
    """One 0x200-byte chunk: 16 entries, addressed by base."""

    def __init__(self, base, entries):
        self.base = base
        self.entries = entries

    def entry_at(self, address):
        index = (address - self.base) // ENTRY_SIZE
        if address < self.base or (address - self.base) % ENTRY_SIZE:
            raise ValueError("cursor %#x is not an entry start" % address)
        if index >= len(self.entries):
            raise ValueError("cursor %#x past chunk end" % address)
        return self.entries[index]


def flag_clear(owner, threshold, events):
    """Run the pinned behaviour.

    owner: dict with "cursor" (int), "chunk_end" (int),
    "end" (int), "slots" (list of chunk bases, the map slots in
    order, with the current chunk's slot first), and "chunks"
    (dict base -> Chunk). threshold: int, compared unsigned.
    events: list the model appends observable steps to, in order.

    Returns "returned" on every normal path; the event list and
    the cleared flags are what distinguish the paths.
    """
    if owner is None:
        raise ValueError("null owner pointer")
    threshold &= MASK64
    events.append("acquire stub called (0x60d5390, owner +0x9c8, no-op)")
    cursor = owner["cursor"]
    chunk_end = owner["chunk_end"]
    end = owner["end"]
    slots = owner["slots"]
    chunks = owner["chunks"]
    if not slots:
        raise ValueError("empty map slot list")
    slot_index = 0
    while True:
        if cursor == end:
            break
        chunk = chunks.get(slots[slot_index])
        if chunk is None:
            raise ValueError("no chunk for slot %#x" % slots[slot_index])
        entry = chunk.entry_at(cursor)
        if entry.key < threshold:
            events.append("stop: key %#x below threshold %#x"
                          % (entry.key, threshold))
            break
        entry.flag = 0
        events.append("cleared flag at %#x (key %#x)"
                      % (cursor, entry.key))
        cursor += ENTRY_SIZE
        if cursor != chunk_end:
            continue
        slot_index += 1
        if slot_index >= len(slots):
            raise ValueError("map slot list exhausted at chunk end")
        cursor = slots[slot_index]
        chunk_end = cursor + CHUNK_SIZE
        if cursor == end:
            break
    events.append("broadcast called (0x60d57c0, owner +0xb70)")
    return "returned"
