"""Node #115 guard release (window 0x5f0b5e0) — literal model.

The window is the guard-release callee both merged allocation
packets cite "by contract, internals not modelled": the
shard-allocation window 0x5f117a0 and the allocation window
0x5f11c40 each call it twice from their shared cleanup pad, each
time on a 16-byte stack lock slot whose held-flag byte the pad has
just tested nonzero. The RE-002 vendor census registers this exact
FDE interval as the published-crate rebuild match for
librocksdb-sys 0.11.0+8.1.1
``std::unique_lock<rocksdb::SpinMutex>::unlock()``, and the body
below is exactly that shape, stated literally:

    slot layout (16 bytes, the argument in rdi):
        +0x00  device pointer (the lock byte's address)
        +0x08  owns byte (the held flag)
        +0x09..+0x0f  padding — never read or written in-window

    if owns == 0:
        call std::__throw_system_error(1) and never return
        (the push/mov/call tail at 0x5f0b5fa; the call is noreturn)
    device = qword at slot + 0
    if device != 0:
        byte at device <- 0        (the lock byte is cleared)
        owns byte <- 0             (the slot no longer owns)
    return                         (no value; rax holds the device
                                    pointer on the normal exits and
                                    is the throw scratch on the tail)

Note the null-device arm: with owns set and a null device pointer
the window writes nothing and returns with the owns byte still
set — it does NOT clear the flag on that path. Both caller pads
only reach the window with owns nonzero, so the throw arm is
unreachable from all four call sites; it is pinned anyway because
it is half of the window's contract for any other caller.

The model below takes the slot as a bytearray of 16 bytes and a
``mem`` bytearray standing in for the address space the device
pointer indexes: the pointer is interpreted as an offset into
``mem``. A throw is modelled by raising SystemErrorThrow with the
error code, leaving slot and memory untouched, exactly as the
native tail leaves them before the noreturn call.
"""

import struct

SLOT_SIZE = 16
DEVICE_OFFSET = 0x00
OWNS_OFFSET = 0x08
THROW_CODE = 1


class SystemErrorThrow(Exception):
    """The window's tail call to std::__throw_system_error(code)."""

    def __init__(self, code):
        super().__init__("__throw_system_error(%d)" % code)
        self.code = code


def _load_qword(buf, offset):
    return struct.unpack_from("<Q", buf, offset)[0]


def guard_release(slot, mem):
    """Run the window over ``slot`` (bytearray of 16 bytes).

    ``mem`` is the byte space the device pointer indexes (the
    pointer is read as an offset into it); the byte at that offset
    is the lock byte. Returns None like the window. Raises
    SystemErrorThrow(1) on the not-owning arm, with slot and mem
    untouched.
    """
    if slot[OWNS_OFFSET] == 0:
        raise SystemErrorThrow(THROW_CODE)
    device = _load_qword(slot, DEVICE_OFFSET)
    if device != 0:
        mem[device] = 0
        slot[OWNS_OFFSET] = 0
    return None
