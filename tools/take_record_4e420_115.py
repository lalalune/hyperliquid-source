#!/usr/bin/env python3
"""Model of node #115 routine 0x5d4e420: take slot record.

The routine takes an out record (rdi) and a source object (rsi) and
moves the source's +0x650 slot record into the out record, guarded by
an acquire/release pair on the source's +0x658 field. When the slot is
empty it reports "No trace file to close" and moves the report
callee's record into the out record instead. Callees are injectable
so the model can be tested without the target binary; only argument
lists, call order and the field moves are pinned.

Out record layout, exactly as in the binary: a 32-bit value at +0x00,
a 16-bit flags field at +0x04, and a pointer at +0x08. The source
slot object is 56 (0x38) bytes when deleted.

Order, exactly as in the binary:
  1. acquire(source + 0x658)
  2. out = {0, 0, None} (a pre-filled out pointer is dropped here,
     with no delete call: the init overwrites it before the move's
     old-pointer check runs)
  3a. slot non-null: fill a temp record from the slot object, move
      the temp into out field by field (temp zeroed as it is moved),
      clear source + 0x650, destroy the slot object, delete it with
      size 0x38
  3b. slot null: report into a temp record (level 5, message and
      path below), move-assign out from the temp with the 0x5d49b10
      helper semantics (temp zeroed; the temp-pointer delete check
      then finds None), source + 0x650 untouched (already null),
      no destroy, no delete
  4. release(source + 0x658); return the out pointer
"""

REPORT_MESSAGE = "No trace file to close"
REPORT_MESSAGE_LENGTH = 22
# The block stores the path pointer 0x4376fd, whose byte is NUL; the
# path string itself begins at the next byte, 0x4376fe.
REPORT_PATH = "/home/ubuntu/hl/code_Mainnet/z_vendor/futures-channel/src/oneshot.rs"
REPORT_LEVEL = 5
SLOT_DELETE_SIZE = 0x38


class ModelError(ValueError):
    """Raised on null or malformed model inputs (stated openly)."""


class Record:
    """One (value, flags, pointer) record: +0x00 u32, +0x04 u16, +0x08 ptr."""

    def __init__(self, value=0, flags=0, pointer=None):
        self.value = value
        self.flags = flags
        self.pointer = pointer

    def zero(self):
        self.value = 0
        self.flags = 0
        self.pointer = None


class Source:
    """The source object: a +0x650 slot object (or None) and a guard."""

    def __init__(self, slot=None, guard="source+0x658"):
        self.slot = slot
        self.guard = guard


def move_assign(dest, src, delete_array):
    """The 0x5d49b10 helper, exactly as its body reads.

    If dest is src, return at once (self-move guard). Otherwise copy
    the six bytes (value + flags) zeroing the source bytes, move the
    +0x08 pointer zeroing the source's, and delete the destination's
    old +0x08 pointer with delete[] when it is non-null.
    """
    if dest is src:
        return
    old_pointer = dest.pointer
    dest.value = src.value
    dest.flags = src.flags
    dest.pointer = src.pointer
    src.value = 0
    src.flags = 0
    src.pointer = None
    if old_pointer is not None:
        delete_array(old_pointer)


def run(out, source, acquire, release, fill, destroy, delete_object,
        report, delete_array):
    """Run the take, returning the out record."""
    if out is None or source is None:
        raise ModelError("null out or source")
    guard = source.guard
    acquire(guard)
    out.value = 0
    out.flags = 0
    out.pointer = None
    slot = source.slot
    if slot is not None:
        temp = Record()
        fill(temp, slot)
        out.value = temp.value
        out.flags = temp.flags
        out.pointer = temp.pointer
        temp.value = 0
        temp.flags = 0
        temp.pointer = None
        source.slot = None
        destroy(slot)
        delete_object(slot, SLOT_DELETE_SIZE)
    else:
        temp = Record()
        report(temp, REPORT_LEVEL, REPORT_MESSAGE, REPORT_PATH)
        move_assign(out, temp, delete_array)
        if temp.pointer is not None:
            delete_array(temp.pointer)
    release(guard)
    return out
