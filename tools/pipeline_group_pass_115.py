"""Model of node #115 pipeline step 0x5f801f0 (RE-001).

The step prepares one 16-byte record per group and then calls the
per-group callee 0x5f6a630 once per group, in index order.

State (all offsets relative to the object pointer):

* ``count`` -- signed 32-bit value at obj+0x14 (the group count).
* ``f30`` -- the qword at obj+0x30, the inline-record fill cursor.
* ``inline`` -- eight 16-byte slots at obj+0xb8 (slot i at +0xb8+i*16).
* ``heap`` -- the overflow records: the vector whose begin is at
  obj+0xc0 and end at obj+0xc8, one 16-byte slot per group beyond 8.
* ``groups`` -- the 24-byte group entries at obj+0xa98, one per group.

The per-group callee and the heap-grow helper are NOT modelled: the
callee is recorded as a call tuple ``(index, record, group_index)``
where ``record`` is the slot the native code passes, and heap slots
created by the grow helper are recorded as ``None`` (content unpinned
by this item -- the helper's zeroing behaviour is not claimed).

Native order, stated literally (see the work-item README):

1. When count, read unsigned, is greater than 8, the heap vector is
   resized to exactly count-8 slots: truncated when longer, extended
   by the helper 0x5da8490 when shorter, unchanged when equal. The
   inline slots are then zero-filled from the old cursor up to slot 7
   and the cursor is set to 8.
2. When count, read unsigned, is 8 or less, the heap vector is
   truncated to zero slots (its end is set to its begin when they
   differ). The inline slots are zero-filled from the old cursor up
   to count-1 when the cursor is below count, and the cursor is set
   to count when it is above count.
3. When count is positive (signed), the group loop runs index 0 up to
   count-1: slot index <= 7 is the inline slot, index >= 8 is heap
   slot index-8, and the callee is called as
   ``callee(record, group_entry, obj+0x1a0)``. The loop stops after
   the call whose index+1 reaches count (signed compare).

Guards (model contract, not native outcomes): count must be a
non-negative signed 32-bit value, the group list must hold at least
count entries, the cursor must be non-negative, and the inline list
must hold exactly 8 slots. A negative count is out of contract: the
native code reads count unsigned for the >8 branch, so a negative
count would take the heap-resize path with a wrapped size, which no
valid group count reaches.
"""

ZERO = b"\x00" * 16


class PipelineGroupPass:
    """Mutable object state for the 0x5f801f0 step."""

    def __init__(self, count, f30, inline, heap, groups):
        self.count = count
        self.f30 = f30
        self.inline = list(inline)
        self.heap = list(heap)
        self.groups = list(groups)

    def _check(self):
        if not isinstance(self.count, int) or self.count < 0:
            raise ValueError("count must be a non-negative integer")
        if self.count > 0x7FFFFFFF:
            raise ValueError("count must fit in a signed 32-bit value")
        if not isinstance(self.f30, int) or self.f30 < 0:
            raise ValueError("f30 cursor must be a non-negative integer")
        if len(self.inline) != 8:
            raise ValueError("inline must hold exactly 8 slots")
        if len(self.groups) < self.count:
            raise ValueError("group list shorter than count")

    def run(self):
        """Run the step; return the per-group callee call list."""
        self._check()
        count = self.count
        if count > 8:
            need = count - 8
            if len(self.heap) < need:
                # Grow helper 0x5da8490: new slots' content unpinned.
                self.heap.extend([None] * (need - len(self.heap)))
            elif need < len(self.heap):
                self.heap = self.heap[:need]
            while self.f30 <= 7:
                self.inline[self.f30] = ZERO
                self.f30 += 1
            self.f30 = 8
        else:
            self.heap = []
            if self.f30 >= count:
                if self.f30 != count:
                    self.f30 = count
            else:
                while self.f30 < count:
                    self.inline[self.f30] = ZERO
                    self.f30 += 1
        calls = []
        for index in range(count):
            if index <= 7:
                record = self.inline[index]
            else:
                record = self.heap[index - 8]
            calls.append((index, record, index))
        return calls
