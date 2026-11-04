"""Model of node #115 routine 0x5d50a70: refresh one destination
from one source.

Pinned from the digest-verified node #115 binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The routine takes two arguments: a destination pointer in rdi and
a source pointer in rsi, and returns the destination pointer.
End to end, in order:

1. Enter: call 0x606ca40 with source +0x700. The callee is
   opaque; only its argument is pinned.
2. Counter: the dword at source +0x1938 decides the path:
   - if it is non-zero at entry, increment it by 1 and skip
     the refresh sequence;
   - if it is zero at entry, build the refresh sequence below,
     then re-read the counter: if it still reads 0, refresh
     the +0x1930 pointer (see step 3), then increment the
     counter by 1 exactly once.
3. Refresh sequence (slow path only): two 0x100-byte record
   temps are initialized on the stack (temp1 at rsp +0x10,
   temp2 at rsp +0x110) with qword +0x08 = 0x400000000,
   qword +0x50 = 0x100, qword +0x60 = 0x00ffffffffffffff, and
   every other initialized slot zero; the range +0x88..+0xef
   of each temp is NOT written by the initializer. Then:
   - call 0x5fcbf90 with (source +0xd40, temp1, source +0x700);
   - if the byte at source +0x17b0 is non-zero, also call
     0x5fcbf90 with (source +0xf50, temp2, source +0x700);
   - if the counter still reads 0, call 0x5fc9520 with
     (out slot, source +0x1100); the new pointer it writes
     into the out slot replaces source +0x1930, the out slot
     is zeroed, the old +0x1930 pointer is disposed of (see
     step 4), and the zeroed out slot is disposed of again
     (a no-op);
   - increment the counter by 1;
   - if the +0x17b0 byte is non-zero, call 0x5fcbda0 with
     (source +0xf50, temp2);
   - call 0x5fcbda0 with (source +0xd40, temp1);
   - call the record teardown 0x5d509c0 on temp2, then on
     temp1 (a freshly initialized temp tears down to nothing:
     its +0x50 flag byte is 0 and its +0x70/+0x80 pointers
     are null, per the teardown mapped in the 0x5d509c0
     packet).
4. Old-pointer disposal: given a non-null old pointer, read
   its vtable slot +0x08 (the qword at *(old) + 0x08). If
   that value equals the relocated global at 0x64ed2d8
   (0x5d486c0, an R_X86_64_RELATIVE addend; the routine there
   is endbr64; mov $0x10,%esi; jmp operator delete), delete
   the old pointer with size 0x10 directly. Otherwise call
   the vtable slot value with the old pointer. A null old
   pointer is skipped, and so is the zeroed out slot.
5. Exit: call 0x60d52f0 with source +0x700. That callee
   calls pthread_mutex_unlock on its argument; only the
   argument and the call are pinned here.
6. Virtual finish: call the source object's vtable slot
   +0x300 with (destination, source, 0). If the destination's
   first byte is non-zero, call vtable slot +0x318 with
   (stack temp, source) and, if the qword at temp +0x08 is
   non-null, delete[] it. The third argument of the +0x318
   call is NOT pinned: rdx is set to 0 before the +0x300
   call but may be clobbered by it before the +0x318 call.
7. Return the destination pointer.

The routine has no direct call or tail-jump site anywhere in
the binary: it is reached only through four R_X86_64_RELATIVE
records (0x64c9678, 0x64cb3f0, 0x64cb8d0, 0x64cbed0) whose
addend is the routine address, i.e. vtable slots.

NOT modelled: what the source, the destination, or any field
denotes; what the opaque callees (0x606ca40, 0x5fcbf90,
0x5fcbda0, 0x5fc9520, the vtable slots) compute; the
exception path (three landing-pad entries inside the FDE
range jump to the separate-FDE cleanup fragment at
0x5d50a06, which tears down the temps, releases the +0x700
callee and resumes unwinding); or behaviour on dangling
pointers. A null destination or source raises in the model:
the binary would fault on the same reads.
"""

ENTER_CALLEE = 0x606CA40
EXIT_CALLEE = 0x60D52F0
LOCK_OFFSET = 0x700
BUILD_CALLEE = 0x5FCBF90
MERGE_CALLEE = 0x5FCBDA0
REFRESH_CALLEE = 0x5FC9520
TEARDOWN_CALLEE = 0x5D509C0
VTABLE_SLOT_FINISH = 0x300
VTABLE_SLOT_PRODUCE = 0x318
COUNTER_OFFSET = 0x1938
FLAG_OFFSET = 0x17B0
PTR_OFFSET = 0x1930
FIELD_D40 = 0xD40
FIELD_F50 = 0xF50
FIELD_1100 = 0x1100
GLOBAL_ADDRESS = 0x64ED2D8
GLOBAL_VALUE = 0x5D486C0
DELETE_SIZE = 0x10
TEMP_SIZE = 0x100
TEMP_INIT_08 = 0x400000000
TEMP_INIT_50 = 0x100
TEMP_INIT_60 = 0x00FFFFFFFFFFFFFF
TEMP_UNINITIALIZED = (0x88, 0xEF)


class Temp:
    """One 0x100-byte record temp exactly as the initializer
    leaves it: only the written slots exist as values; the
    range +0x88..+0xef is explicitly unwritten."""

    def __init__(self):
        self.fields = {0x00: 0, 0x08: TEMP_INIT_08, 0x10: 0,
                       0x18: 0, 0x28: 0, 0x38: 0, 0x48: 0,
                       0x50: TEMP_INIT_50, 0x58: 0,
                       0x60: TEMP_INIT_60, 0x68: 0, 0x70: 0,
                       0x78: 0, 0x80: 0, 0xF0: 0}

    def flag_byte(self):
        return self.fields[0x50] & 0xFF


class Dest:
    """The destination: only its first byte is read."""

    def __init__(self, byte0=0):
        self.byte0 = byte0


class Source:
    """The source: counter, flag byte, +0x1930 pointer, the
    three opaque field tokens, and the +0x700 lock token."""

    def __init__(self, counter=0, flag=0, ptr_field=None,
                 field_d40="d40", field_f50="f50",
                 field_1100="f1100", lock="lock"):
        self.counter = counter
        self.flag = flag
        self.ptr_field = ptr_field
        self.field_d40 = field_d40
        self.field_f50 = field_f50
        self.field_1100 = field_1100
        self.lock = lock


def init_temp():
    return Temp()


def dispose_pointer(ptr, hooks):
    """The old-pointer disposal of step 4. A null pointer
    produces no event, matching the binary's null skips."""
    if ptr is None:
        return
    value = hooks.vtable1(ptr)
    if value == GLOBAL_VALUE:
        hooks.delete(ptr, DELETE_SIZE)
    else:
        hooks.call_vtable1(ptr, value)


def refresh(dest, source, hooks):
    """Run the whole routine. Hooks is an object with methods
    enter, exit, build, merge, refresh, teardown, virtual300,
    virtual318, vtable1, delete, delete_array, call_vtable1."""
    if dest is None or source is None:
        raise ValueError("null destination or source")
    hooks.enter(source.lock)
    if source.counter != 0:
        source.counter += 1
    else:
        temp1 = init_temp()
        temp2 = init_temp()
        hooks.build(source.field_d40, temp1, source.lock)
        if source.flag != 0:
            hooks.build(source.field_f50, temp2, source.lock)
        if source.counter == 0:
            new_ptr = hooks.refresh(source.field_1100)
            old = source.ptr_field
            source.ptr_field = new_ptr
            dispose_pointer(old, hooks)
            dispose_pointer(None, hooks)
        source.counter += 1
        if source.flag != 0:
            hooks.merge(source.field_f50, temp2)
        hooks.merge(source.field_d40, temp1)
        hooks.teardown(temp2)
        hooks.teardown(temp1)
    hooks.exit(source.lock)
    hooks.virtual300(dest, source, 0)
    if dest.byte0 != 0:
        ptr08 = hooks.virtual318(source)
        if ptr08 is not None:
            hooks.delete_array(ptr08)
    return dest
