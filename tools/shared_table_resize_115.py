"""Python model of node #115 shared-pointer table replace (0x5f0b420).

One whole function from the digest-verified node #115 work binary
(work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):
given an object holding a table of 16-byte shared-pointer entries
(pointer at +0x00, control-block pointer at +0x08), it sizes a fresh
table from std::thread::hardware_concurrency(), allocates and
zero-fills it, and installs it.

Window, in order:

1. Entry zero-store: the object's array field (+0x00) is set to 0
   (0x5f0b431). This happens BEFORE allocation and is the fact the
   rest of the window turns on.
2. Sizing: k = 3 and N = 8 when hardware_concurrency() returns 8 or
   less (including 0); otherwise k is the smallest value >= 4 with
   2**k >= the returned count, and N = 2**k. The log field
   (object + 0x08) is set to k before allocation.
3. Allocation: 16*N + 8 bytes (an 8-byte count header holding N,
   then N zeroed 16-byte entries). When N >> 59 is nonzero the
   window instead calls operator new with -1, which throws; that
   guard is unreachable for a 32-bit hardware_concurrency return
   but present in the code and modelled as a raising guard.
4. Install: the fresh table is stored to the array field. The
   window then loads the "old" array from that same field
   (0x5f0b4b5) — which it zeroed in step 1 — so the load always
   yields null, the release loop and the sized free that follow
   are unreachable from this window, and a previous table, if the
   object ever held one, leaks instead of being released.
5. Allocation failure: the only landing pad covers the operator-new
   call; it destroys the object's current array via helper
   0x5f0a1dc and resumes unwinding — but the array field is
   already null at that point, so the helper is skipped and the
   object is left with array null and log k.

The release loop is modelled separately as release_table(),
exactly as written: entries visited last-to-first; a null control
block skipped; a control block whose combined (use, weak) qword
equals 0x100000001 zeroed and then given the dispose virtual
(+0x10) and the destroy virtual (+0x18) directly; otherwise the
use count decremented (plainly when __libc_single_threaded is
nonzero, with LOCK XADD otherwise) and an old use count of 1
calling the dispose helper 0x5d35070 (dispose virtual, then a
weak-count decrement, then the destroy virtual when the old weak
count was 1). A zero use count wraps to 2**32 - 1 with no call.
That loop is unreachable from replace() but executes for real in
the standalone helper 0x5f0a1dc, whose body is excerpted whole in
this packet; release_table() is the shared semantics of both.

The replace() result dict reports the dropped previous table only
so tests can assert the leak; the real window returns void and
exposes no such value.
"""

MASK32 = (1 << 32) - 1
SENTINEL = 0x100000001


class AllocationError(Exception):
    """operator new called with -1 (the N >> 59 guard tripped)."""


def size_for_hw(hw):
    """(k, N) for a hardware_concurrency() return value.

    Mirrors the window's branches: hw <= 8 gives k = 3, N = 8;
    otherwise k is the smallest value >= 4 with 2**k >= hw.
    """
    if hw <= 8:
        return (3, 8)
    k = 4
    while (1 << k) < hw:
        k += 1
    return (k, 1 << k)


def allocation_bytes(n):
    """Allocation size for N entries, or raise on the overflow guard."""
    if n >> 59:
        raise AllocationError("N %d overflows the size guard" % n)
    return 16 * n + 8


class Control:
    """A libstdc++-shaped control block (vtable + use/weak counts)."""

    def __init__(self, use, weak):
        self.use = use & MASK32
        self.weak = weak & MASK32
        self.dispose_calls = 0
        self.destroy_calls = 0
        self.call_order = []

    def dispose(self):
        self.dispose_calls += 1
        self.call_order.append("dispose")

    def destroy(self):
        self.destroy_calls += 1
        self.call_order.append("destroy")


class Table:
    """A table allocation: header count plus (pointer, control) entries."""

    def __init__(self, header_count, entries):
        self.header_count = header_count
        self.entries = entries


class Obj:
    """The object the window operates on: array field + log field."""

    def __init__(self, array=None, log=None):
        self.array = array
        self.log = log


def dispose_helper(control):
    """The 0x5d35070 helper: dispose, weak decrement, maybe destroy."""
    control.dispose()
    old_weak = control.weak
    control.weak = (old_weak - 1) & MASK32
    if old_weak == 1:
        control.destroy()


def release_entry(control, single_threaded):
    """One entry of the release loop, exactly as written.

    single_threaded selects the plain decrement (nonzero) versus
    LOCK XADD (zero); the observable result is the same in this
    model, and both arms are tested.
    """
    if ((control.weak << 32) | control.use) == SENTINEL:
        control.use = 0
        control.weak = 0
        control.dispose()
        control.destroy()
        return
    old_use = control.use
    control.use = (old_use - 1) & MASK32
    if old_use == 1:
        dispose_helper(control)


def release_table(table, single_threaded):
    """The release loop as written: last entry to first, nulls skipped."""
    for _ptr, control in reversed(table.entries):
        if control is None:
            continue
        release_entry(control, single_threaded)


def free_size(header_count):
    """Sized delete[] bytes for a released table (header base)."""
    return 16 * header_count + 8


def replace(obj, hw, single_threaded=False):
    """The window as written: zero, size, allocate, install, return.

    The release loop never runs here: the old array is loaded from
    the field zeroed at entry, so it is always null. The returned
    dict reports the dropped previous table (model-only
    observability for the leak) and whether anything was freed
    (never, from this window).
    """
    dropped_old = obj.array
    obj.array = None  # entry zero-store (0x5f0b431)
    k, n = size_for_hw(hw)
    obj.log = k  # log field set before allocation
    allocation_bytes(n)  # raises on the overflow guard; obj left {None, k}
    new_table = Table(n, [(None, None)] * n)  # zeroed entries
    obj.array = new_table  # install (0x5f0b4b8)
    old = None  # load from the zeroed field (0x5f0b4b5): always null
    if old is None:
        return {"dropped_old": dropped_old, "freed": None, "released": False}
    raise AssertionError("unreachable: the zeroed field cannot hold a table")
