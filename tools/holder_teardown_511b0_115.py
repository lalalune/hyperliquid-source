"""Model of node #115 routine 0x5d511b0: holder teardown (RE-001).

The routine takes a holder in rdi and returns nothing. It destroys,
in order: every record in the records array, then two holder pointer
lists, then a tail scalar. Every list follows one shape: an 8-slot
inline segment, a heap segment with begin/end fields, and an
inline-count field. Element i of a list comes from the inline segment
when i <= 7 and from the heap segment at index i - 8 otherwise, and
the loop runs heap_count + inline_count times. The binary's threshold
is the fixed constant 8, so well-formed inputs have inline_count == 8;
that is the case the tests exercise.

Data model (plain dicts, mirroring the binary's fields):
  item: {"ptr": int, "field10": int, "addr": int,
         "target_pairs": [slot, ...]}  # slot = vtable+0x100 value
  record: {"inline_items": [item], "heap_items": [item],
           "inline_count": int,
           "ptrs_inline": [int|None], "ptrs_heap": [int|None],
           "ptr_count": int}
  holder: {"records": [record],
           "phase2_inline": [int|None], "phase2_heap": [int|None],
           "phase2_count": int,
           "phase3_inline": [int|None], "phase3_heap": [int|None],
           "phase3_count": int,
           "tail_scalar": int|None}

Events recorded, in order: ("notify", slot, item_index) for virtual
calls, ("call", callee, ptr) for destructor calls, and
("delete", ptr, size) for sized deletes.
"""

NOOP_SLOT = 0x5D48450
REC_DTOR = 0x5D8D820
PHASE2_DTOR = 0x5F10D40
PHASE3_DTOR = 0x5F04800
TAIL_DTOR = 0x5F3C850


def _list_elements(inline, heap, inline_count):
    """Elements of one shaped list, in the binary's visiting order."""
    total = len(heap) + inline_count
    out = []
    for i in range(total):
        if i <= 7:
            out.append(inline[i])
        else:
            out.append(heap[i - 8])
    return out


def _teardown_record(record, events):
    # 1. Notify: virtual handler per pair, skipping the no-op slot.
    items = _list_elements(record["inline_items"], record["heap_items"],
                           record["inline_count"])
    for idx, item in enumerate(items):
        for slot in item["target_pairs"]:
            if slot == NOOP_SLOT:
                continue
            events.append(("notify", slot, idx))
    # 2. Pop inline items in reverse index order.
    count = record["inline_count"]
    while count != 0:
        count -= 1
        item = record["inline_items"][count]
        if item["ptr"] != item["addr"] + 0x10:
            events.append(("delete", item["ptr"], item["field10"] + 1))
    record["inline_count"] = 0
    # 3. Dispose heap items in forward order.
    for item in record["heap_items"]:
        if item["ptr"] != item["addr"] + 0x10:
            events.append(("delete", item["ptr"], item["field10"] + 1))
    record["heap_items_cleared"] = True
    # 4. Dispose the record's pointer array.
    ptrs = _list_elements(record["ptrs_inline"], record["ptrs_heap"],
                          record["ptr_count"])
    for ptr in ptrs:
        if ptr is None:
            continue
        events.append(("call", REC_DTOR, ptr))
        events.append(("delete", ptr, 0x290))
    if record["ptr_count"] != 0:
        record["ptr_count"] = 0
    record["ptrs_heap_cleared"] = True


def _teardown_pointer_list(inline, heap, count, dtor, size, events):
    for ptr in _list_elements(inline, heap, count):
        if ptr is None:
            continue
        events.append(("call", dtor, ptr))
        events.append(("delete", ptr, size))
    return 0  # count field cleared (when it was non-zero, as in the binary)


def teardown_holder(holder):
    """Run the whole routine on a holder dict; return the event list."""
    events = []
    for record in holder["records"]:
        _teardown_record(record, events)
    holder["phase2_count"] = _teardown_pointer_list(
        holder["phase2_inline"], holder["phase2_heap"],
        holder["phase2_count"], PHASE2_DTOR, 0xD20, events)
    holder["phase2_heap_cleared"] = True
    holder["phase3_count"] = _teardown_pointer_list(
        holder["phase3_inline"], holder["phase3_heap"],
        holder["phase3_count"], PHASE3_DTOR, 0x58, events)
    holder["phase3_heap_cleared"] = True
    scalar = holder["tail_scalar"]
    holder["tail_scalar"] = None
    if scalar is not None:
        events.append(("call", TAIL_DTOR, scalar))
        events.append(("delete", scalar, 0x10))
    return events


def empty_holder():
    return {"records": [], "phase2_inline": [], "phase2_heap": [],
            "phase2_count": 0, "phase3_inline": [], "phase3_heap": [],
            "phase3_count": 0, "tail_scalar": None}


def _item(ptr, field10, addr, pairs):
    return {"ptr": ptr, "field10": field10, "addr": addr,
            "target_pairs": pairs}
