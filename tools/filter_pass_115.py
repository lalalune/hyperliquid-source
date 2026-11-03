"""Python model of node #115 filter pass 0x5f6d700 (RE-001).

The pass iterates the group's slot array and, for each element, consults
the later-group predicate 0x5f6d600 (pinned by the RE-001 later-group
predicate item; here it is an oracle callable, exactly the input the
native loop consults). A predicate-true element is skipped; a
predicate-false element is appended to the scan list at obj+0xd30 /
obj+0xdb8 (inline) / obj+0xdc0 (heap).

Object model (all addresses are offsets into the pass's object):
  cursor: obj+0x30, number of inline group slots in use (0..8 in the
      pipeline invariant; the native loop just adds it to the heap
      slot count, so the model does the same literally).
  inline_slots: 8 group slots at obj+0xb8, 16 bytes each:
      (limit, element_base). limit is the first qword, compared
      UNSIGNED against the per-group true/false counter.
  heap_slots: group slots at obj+0xc0, 16 bytes each, same shape.
  elements: mapping (element_base, index) -> element record with raw
      qwords f28, f30, f38, f40, f48 (the fields at element+0x28,
      +0x30, +0x38, +0x40, +0x48).
  scan_inline: scan-list records stored inline at obj+0xdb8 (at most 8).
  scan_heap: scan-list records stored in the heap vector at obj+0xdc0.
  scan_heap_capacity: heap vector capacity in records (obj+0xdd0 minus
      obj+0xdc0, in records).

Native details reproduced literally:
  - The iteration total is cursor + heap slot count, recomputed from
    the object at the start of every outer (group) iteration; a total
    of 0 returns at once with no predicate call.
  - Group i uses inline slot i when i <= 7 (unsigned), else heap slot
    i - 8.
  - Inside a group, the counter r12 starts at 0 and the element offset
    starts at 0; each predicate consultation advances both (r12 += 1,
    offset += 0x50), whether the predicate returns true or false, and
    the loop continues while r12 < limit (unsigned).
  - The predicate is called as (obj, rsi, rdx, rcx, r8) with
    rsi = (element+0x30, element+0x38 - 8 wrapping),
    rdx = (element+0x40, element+0x48 - 8 wrapping),
    rcx = the group index i, r8 = r12 when i == 0 else -1
    (the native code moves r12d into r8d only on the i == 0 arm; the
    heap path, taken only for i > 7, always passes -1).
  - A predicate-false element appends the 16-byte record (group index
    as a 32-bit value, element+0x28) to the scan list: inline while
    the scan count <= 7, otherwise to the heap vector, growing it
    (capacity 1 when empty, else twice the size, capped at
    0x7ffffffffffffff records; growing at the maximum raises the
    native length error) exactly like the native append arms.
  - The malformed-vector arm (heap vector with 0 < end - begin < 16,
    i.e. size 0 but begin != end) is out of the model contract: for a
    well-formed 16-byte-record vector it cannot occur, and the native
    code there does not follow the grow path. The model raises
    ValueError for it instead of reproducing it.

Only established semantics are implemented; the predicate's own
decision is an oracle input, not a claim of this item.
"""

MASK64 = (1 << 64) - 1
MAX_RECORDS = 0x7FFFFFFFFFFFFFF
INLINE_SCAN_CAPACITY = 8
ELEMENT_STRIDE = 0x50


class LengthError_(Exception):
    """Model-side stand-in for the native length_error throw."""


def _wrap64(value):
    return value & MASK64


class Element(object):
    """Raw qwords of one 0x50-stride element (offsets from its base)."""

    def __init__(self, f28, f30, f38, f40, f48):
        self.f28 = f28
        self.f30 = f30
        self.f38 = f38
        self.f40 = f40
        self.f48 = f48


class PassObject(object):
    """The pass's object fields, in model form."""

    def __init__(self, cursor, inline_slots, heap_slots, elements):
        self.cursor = cursor
        self.inline_slots = list(inline_slots)
        self.heap_slots = list(heap_slots)
        self.elements = dict(elements)
        self.scan_inline = []
        self.scan_heap = []
        self.scan_heap_capacity = 0

    @property
    def scan_count(self):
        return len(self.scan_inline) + len(self.scan_heap)

    @property
    def scan_records(self):
        return list(self.scan_inline) + list(self.scan_heap)


def _grow_scan_heap(obj):
    size = len(obj.scan_heap)
    if size == MAX_RECORDS:
        raise LengthError_("scan heap at maximum record count")
    if size == 0:
        new_capacity = 1
    else:
        doubled = 2 * size
        if doubled < size or doubled > MAX_RECORDS:
            # Native unsigned-wrap arm (2*size < size) and the
            # min(2*size, maximum) cap both land on the maximum.
            new_capacity = MAX_RECORDS
        else:
            new_capacity = doubled
    obj.scan_heap_capacity = new_capacity


def _append_scan(obj, record):
    if obj.scan_count <= 7:
        obj.scan_inline.append(record)
        return
    if len(obj.scan_heap) >= obj.scan_heap_capacity:
        _grow_scan_heap(obj)
    obj.scan_heap.append(record)


def filter_pass(obj, predicate):
    """Run the 0x5f6d700 pass over obj, consulting predicate as oracle.

    predicate(obj, rsi, rdx, group_index, r8) returns truthy for skip
    (predicate 1) and falsy for append (predicate 0). Returns None;
    the scan list on obj is mutated in place.
    """
    i = 0
    while True:
        # Total recomputed at every outer advance, as the native code
        # re-reads the heap vector and the cursor at 0x5f6d850; the
        # loop ends when the next index reaches the total (unsigned).
        total = obj.cursor + len(obj.heap_slots)
        if total == 0 or i >= total:
            return
        if i <= 7:
            if i >= len(obj.inline_slots):
                raise ValueError("group index beyond inline slots")
            limit, base = obj.inline_slots[i]
        else:
            slot_index = i - 8
            if slot_index >= len(obj.heap_slots):
                raise ValueError("group index beyond heap slots")
            limit, base = obj.heap_slots[slot_index]
        r12 = 0
        while r12 < limit:
            element = obj.elements.get((base, r12))
            if element is None:
                raise ValueError("missing element for group %d "
                                 "index %d" % (i, r12))
            rsi = (element.f30, _wrap64(element.f38 - 8))
            rdx = (element.f40, _wrap64(element.f48 - 8))
            r8 = r12 if i == 0 else -1
            if predicate(obj, rsi, rdx, i, r8):
                pass
            else:
                _append_scan(obj, (i, element.f28))
            r12 += 1
        i += 1
