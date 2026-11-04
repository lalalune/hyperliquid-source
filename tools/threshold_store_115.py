"""Node #115 threshold store with its minimum recompute.

Maps RE-001 windows 0x5f6c270 (threshold store, 29 bytes) and
0x5f6bfe0 (minimum recompute, 646 bytes) from the digest-verified
node #115 binary (work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

Object layout (all offsets are from the object base; values are
unsigned 64-bit unless noted):

  +0xf30  threshold: the value most recently stored by the setter.
  +0xf28  minimum: the smallest scanned element value that is >= the
         threshold, or the sentinel below when no such value exists.
  +0xdd8  collection size: number of records in the rebuilt collection.
  +0xe60  collection inline base: pointer to the array holding the
         first 8 collection records.
  +0xe68  collection heap begin, +0xe70 heap end, +0xe78 heap cap end:
         the heap array holding collection records past the first 8.
  +0xdb8  scan inline base: pointer to the array holding scan records
         with logical index 0..7.
  +0xdc0  scan heap begin, +0xdc8 scan heap end: the array holding
         scan records with logical index 8 and up.
  +0xd30  scan extra count: added to the scan heap length to give the
         total number of scan records.

A scan record is a 16-byte pair (ignored first qword, element). An
element carries the byte read at element+0xb4 (``flag``) and the
qword read at element+0x20 (``value``).

Setter rule, stated literally: store the new value at +0xf30 first;
if the old minimum at +0xf28 is unsigned-less than the new value,
tail-jump to the recompute; otherwise return. The fast path does not
rescan, so after a decrease the collection and the minimum still
reflect the previous threshold until a later increase triggers a
recompute.

Recompute rule, stated literally:
  1. If the collection size is nonzero, set it to 0; if the heap end
     differs from the heap begin, set the heap end to the heap begin
     (the heap capacity is retained).
  2. Set the minimum to the sentinel 0x00ffffffffffffff.
  3. Scan logical indices 0..total-1, where
     total = (scan heap length) + scan extra count; index <= 7 reads
     the scan inline array, index > 7 reads the scan heap array at
     index - 8.
  4. Per record, skip the record when the element flag byte is
     nonzero, and skip it when the element value is zero. When the
     value is unsigned-less than the threshold, append the whole
     16-byte record to the collection; otherwise set the minimum to
     the unsigned minimum of the current minimum and the value.
  5. Collection append: while the collection size is <= 7, store at
     the inline base + size * 16; past that, store at the heap end
     when it is below the heap cap end, otherwise grow the heap (new
     capacity 1 when the heap is empty, else twice the heap size,
     capped at 0x7ffffffffffffff elements; growing past that cap
     raises the native length error) and then store.

The native zero-new-capacity growth arm is unreachable for a
well-formed heap (it requires a nonempty heap of size 0) and is not
modelled beyond the guard below. A null element, a missing element
field, or a scan index past the supplied arrays is a model guard
error, not a native behavior: the native code reads those locations
without a check.
"""

MASK64 = (1 << 64) - 1
SENTINEL = 0x00FFFFFFFFFFFFFF
MAX_ELEMENTS = 0x7FFFFFFFFFFFFFF


class ThresholdStoreError(ValueError):
    """Guard error for inputs the native code would read unchecked."""


def _u64(value):
    return value & MASK64


def make_obj(f28=0, f30=0, coll_size=0, coll_inline=None,
             coll_heap=None, coll_heap_capacity=0,
             scan_inline=None, scan_heap=None, scan_extra=0):
    """Build an object dict in the layout above."""
    return {
        "f28": _u64(f28),
        "f30": _u64(f30),
        "coll_size": coll_size,
        "coll_inline": list(coll_inline) if coll_inline is not None else [],
        "coll_heap": list(coll_heap) if coll_heap is not None else [],
        "coll_heap_capacity": coll_heap_capacity,
        "scan_inline": list(scan_inline) if scan_inline is not None else [],
        "scan_heap": list(scan_heap) if scan_heap is not None else [],
        "scan_extra": scan_extra,
    }


def make_element(flag, value):
    return {"flag": flag, "value": _u64(value)}


def collection(obj):
    """The rebuilt collection in scan order."""
    size = obj["coll_size"]
    head = obj["coll_inline"][:min(size, 8)]
    tail = obj["coll_heap"][:max(size - 8, 0)] if size > 8 else []
    return head + tail


def _append_record(obj, record):
    size = obj["coll_size"]
    if size <= 7:
        inline = obj["coll_inline"]
        if len(inline) <= size:
            inline.append(record)
        else:
            inline[size] = record
    else:
        heap = obj["coll_heap"]
        if len(heap) >= obj["coll_heap_capacity"]:
            if len(heap) == MAX_ELEMENTS:
                raise OverflowError("length_error: heap at max elements")
            if len(heap) == 0:
                obj["coll_heap_capacity"] = 1
            else:
                obj["coll_heap_capacity"] = min(2 * len(heap), MAX_ELEMENTS)
        heap.append(record)
    obj["coll_size"] = size + 1


def recompute(obj):
    """The 0x5f6bfe0 minimum recompute, exactly as traced."""
    if obj["coll_size"] != 0:
        obj["coll_size"] = 0
    # Heap end := heap begin; capacity retained.
    obj["coll_heap"] = []
    obj["f28"] = SENTINEL
    total = len(obj["scan_heap"]) + obj["scan_extra"]
    for i in range(total):
        if i <= 7:
            if i >= len(obj["scan_inline"]):
                raise ThresholdStoreError(
                    "scan index %d past scan inline array" % i)
            record = obj["scan_inline"][i]
        else:
            j = i - 8
            if j >= len(obj["scan_heap"]):
                raise ThresholdStoreError(
                    "scan index %d past scan heap array" % i)
            record = obj["scan_heap"][j]
        try:
            element = record[1]
        except (TypeError, IndexError):
            raise ThresholdStoreError("scan record is not a pair: %r" % (record,))
        if element is None:
            raise ThresholdStoreError("scan record element is null")
        try:
            flag = element["flag"]
            value = _u64(element["value"])
        except (TypeError, KeyError):
            raise ThresholdStoreError("element missing flag/value: %r" % (element,))
        if flag != 0:
            continue
        if value == 0:
            continue
        if value < obj["f30"]:
            _append_record(obj, record)
        elif value < obj["f28"]:
            obj["f28"] = value
    return None


def set_threshold(obj, value):
    """The 0x5f6c270 threshold store with its recompute tail jump."""
    value = _u64(value)
    obj["f30"] = value
    if obj["f28"] < value:
        recompute(obj)
    return None
