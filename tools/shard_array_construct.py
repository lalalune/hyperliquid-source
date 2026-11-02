"""Model of node #94 shard bucket array construction (RE-001, 0x516adf0).

The construction half of the sharded access mapped in
tools/shard_member_access.py: given a hardware_concurrency value,
this builds the bucket array the access function indexes (slots at
host +0xd10, shift at host +0xd18).

Semantics pinned from the window disassembly (see
research/work-items/RE-001-shard-array-construct-94/):
- prologue zeroes the slot field, then the shift is stored before
  allocation;
- concurrency <= 8 -> shift 3, count 8; otherwise the smallest
  shift >= 4 with 2**shift >= concurrency;
- allocation is 8 + 16 * count bytes: the count at the base, then
  count zero-filled 16-byte shared_ptr slots; the slots pointer
  (base + 8) is installed only after the zero-fill;
- the overflow guard fails the allocation when count >> 59;
- the release sequence walks a populated array in reverse and
  applies the shared_ptr control-block protocol to each slot's
  control block, then frees the old allocation (size count*16+8).
  On this function's own path the prologue null store makes the
  post-install release a no-op; the sequence is modelled because
  it is the live standalone helper 0x5169bac (host teardown).
"""

SENTINEL = 0x100000001


class AllocationFailure(Exception):
    """Raised when the overflow guard fails the allocation."""


def bucket_shift_and_count(concurrency):
    """Return (shift, count) for a hardware_concurrency value."""
    if concurrency <= 8:
        return 3, 8
    shift = 4
    while (1 << shift) < concurrency:
        shift += 1
    return shift, 1 << shift


def allocation_size(count):
    """Return the allocation size, or raise on the overflow guard."""
    if count >> 59:
        raise AllocationFailure("count overflows the size computation")
    return 8 + 16 * count


class ControlBlock:
    """A control block with a packed 64-bit strong/weak count word."""

    def __init__(self, count, log):
        self.count = count
        self.log = log

    def destroy_virtuals(self):
        self.count = 0
        self.log.append("virtuals")


class ShardArray:
    """The 16-byte array object: slots pointer (+0) and shift (+8)."""

    def __init__(self):
        self.slots = None  # list of slots, each [pointer, ControlBlock|None]
        self.shift = None

    @property
    def count(self):
        return 1 << self.shift if self.shift is not None else 0


def construct(array, concurrency, destroyer_log=None):
    """Run 0x516adf0 on a fresh (or re-initialised) array object.

    Returns the allocation size. The prologue null store means the
    post-install release observes no old array on this path; pass a
    populated array through release_array() to exercise the release
    sequence itself (the standalone helper 0x5169bac).
    """
    array.slots = None  # prologue store
    shift, count = bucket_shift_and_count(concurrency)
    array.shift = shift  # stored before allocation
    size = allocation_size(count)
    slots = [[None, None] for _ in range(count)]  # zero-filled slots
    array.slots = slots  # installed after the zero-fill
    return size


def release_slot(control, single_threaded, destroyer_log):
    """Apply the control-block protocol to one slot's control block.

    Returns nothing; appends the control block itself to the log
    when the destroyer fires (the destroyer receives the control
    block as its argument, so the log records the call order). A
    null control block is a no-op (the slot is skipped).
    """
    if control is None:
        return
    if control.count == SENTINEL:
        control.destroy_virtuals()
        return
    # Both native paths update a DWORD at control-block +8. The upper
    # (weak-count) DWORD survives; the destroyer tests the old low DWORD.
    old = control.count & 0xffffffff
    control.count = (control.count & 0xffffffff00000000) | ((old - 1) & 0xffffffff)
    if old == 1:
        destroyer_log.append(control)


def release_array(slots, single_threaded=True, destroyer_log=None):
    """Run the 0x5169bac release sequence over a populated array.

    Walks in reverse, applies the protocol to each slot, then frees
    the allocation. Returns the delete[] size (count * 16 + 8).
    """
    if destroyer_log is None:
        destroyer_log = []
    if slots is None:
        return 0
    for _ptr, control in reversed(slots):
        release_slot(control, single_threaded, destroyer_log)
    return 8 + 16 * len(slots)
