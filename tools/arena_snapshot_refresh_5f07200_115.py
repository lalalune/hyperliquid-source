"""Node #115 arena snapshot refresh (window 0x5f07200) — literal model.

The window is a single branchless helper of the outer arena object
(the object whose allocation windows 0x5f117a0 and 0x5f11c40 were
mapped by the shard-allocate and allocate packets). It takes the
object in rdi, reads nothing else, calls nothing, and returns no
value. Its whole body is three 64-bit copies, in this order:

    this + 0x958 <- this + 0x930   (snapshot remaining <- member remaining)
    this + 0x960 <- this + 0x940   (snapshot field     <- member field)
    this + 0x968 <- this + 0x918   (snapshot counter   <- member counter)

The three destination offsets are the snapshot triple both caller
packets describe: the shard-allocation window performs the same
three copies inline on its global-lock path, and its grow path
describes the step as "the three snapshot fields are refreshed from
the member fields". This helper is the shared form, called by the
two direct-refill paths (sites 0x5f11b70 and 0x5f12083) after the
carve and before the global lock byte at this + 0x950 is cleared.

The model below runs over a bytearray standing in for the object.
Only the 24 destination bytes change; the source fields and every
other byte are left untouched, and a second run is a no-op because
the destinations already equal the sources. The window performs no
bounds check: the smallest object it can touch spans the highest
destination byte, 0x970 bytes.
"""

import struct

MEMBER_COUNTER = 0x918
MEMBER_REMAINING = 0x930
MEMBER_FIELD_940 = 0x940
SNAP_REMAINING = 0x958
SNAP_FIELD_960 = 0x960
SNAP_COUNTER = 0x968

OBJECT_MIN_SIZE = 0x970

# (source offset, destination offset) in window order.
COPIES = (
    (MEMBER_REMAINING, SNAP_REMAINING),
    (MEMBER_FIELD_940, SNAP_FIELD_960),
    (MEMBER_COUNTER, SNAP_COUNTER),
)


def _load_qword(obj, offset):
    return struct.unpack_from("<Q", obj, offset)[0]


def _store_qword(obj, offset, value):
    struct.pack_into("<Q", obj, offset, value & 0xFFFFFFFFFFFFFFFF)


def snapshot_refresh(obj):
    """Run the window over ``obj`` (a bytearray of >= 0x970 bytes).

    Performs the three copies in window order and returns None,
    like the window, which returns no value.
    """
    for src, dst in COPIES:
        _store_qword(obj, dst, _load_qword(obj, src))
    return None
