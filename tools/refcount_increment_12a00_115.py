"""Model of node #115 routine 0x5f12a00: the refcount increment.

The routine is three instructions long (FDE
0x5f12a00..0x5f12a09, 9 bytes):

    endbr64
    addl $0x1, 0x40(%rdi)
    ret

It takes one argument, an object pointer in rdi, and its entire
observable effect is: the unsigned 32-bit dword at object +0x40 is
incremented by one, wrapping modulo 2**32 (a plain `addl`: no
saturation, no overflow trap, no lock prefix, so the
read-modify-write is not atomic). It reads no other field, writes
no other byte, makes no calls, takes no branch, uses no stack
beyond the return address, and writes no register (the flags are
set by the addl per its result; rax and every other register are
preserved, and callers treat the routine as void).

The +0x40 dword is the shared reference count whose decrement
pair lives at 0x5f13ea0 (read by the merged drain-driver packet
RE-001-drain-driver-115: it decrements the same dword and runs
its destroy path only when the result reaches zero). The merged
drain-driver packet left this routine by contract only -- "the
field-by-field contents ... established by 0x5f12a00 are
unknown" -- and this model pins the answer: the routine
establishes no field contents at all; in the copy-on-write
prepare at 0x5f13f90 its call is the last state change before the
tail jump into the release, and the only change it makes to the
fresh object is this increment.
"""

COUNT_OFFSET = 0x40

UINT32_MAX = 2 ** 32 - 1


def _check_count(value):
    if not isinstance(value, int) or isinstance(value, bool) \
            or not 0 <= value <= UINT32_MAX:
        raise ValueError("count must be an unsigned 32-bit integer")


def refcount_increment(count):
    """Return the dword at +0x40 after the routine runs:
    ``count`` incremented by one, wrapping modulo 2**32.

    ``count`` is the unsigned 32-bit value stored at object
    +0x40 before the call. The routine changes nothing else in
    the object; that memory-level claim is exercised by the
    packet's Unicorn differential, which compares the whole
    object page.
    """
    _check_count(count)
    return (count + 1) & UINT32_MAX
