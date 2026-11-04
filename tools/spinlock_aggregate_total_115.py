"""Python model of node #115 0x5f0e2d0: spinlock-guarded aggregate total.

RE-001 work item (see research/work-items/RE-001-spinlock-aggregate-115/).
The window is one whole function, 0x5f0e2d0..0x5f0e51b (FDE .eh_frame
offset 0x358c14), extracted from the digest-verified #115 work binary.

Behaviour, in order (all arithmetic wraps at 64 bits; sar is an
arithmetic shift of the wrapped signed difference):

1. Spinlock acquire on the byte at this+0x9f0. The loop reads the
   byte; a nonzero byte means "held": it executes PAUSE, and once
   the pause counter passes 100 it calls sched_yield before the next
   check. A zero byte is claimed with a LOCK CMPXCHG of 1; if the
   byte changed between the read and the cmpxchg, the loop pauses
   and retries. The lock is held only for step 2.
2. Aggregate: capacity = 1 << (byte at this+0xf0, masked to 6 bits
   the way x86 shift counts are); sum the +0x38 field of each of
   the capacity entries of the table at this+0xe8 (64-byte stride).
3. Release the lock (store 0 to this+0x9f0). Everything after this
   point runs unlocked.
4. Value0 from host pointer fields (literal formula, roles of the
   fields beyond the formula are unresolved):
       n960 = (f960 - f940) >> 3 (arithmetic)
       rax  = n960 - 1, except rax = n960 when f960 == 0 (the adc
              after cmp $1, %r11 adds the carry of f960 < 1)
       value0 = (f9e0 - f9d0) + 8 * ((rax << 6)
                  + ((f948 - f950) >> 3) + ((f938 - f928) >> 3))
                  - sum38
5. Two queried values: the +0x78 virtual of the object at this+0xa50,
   then the +0x78 virtual of the object at this+0xa58. Only the
   receiver is deliberately set; both callees are pinned by slot
   only, so the model takes them as callables.
6. Buffer size = 8 * (f_c88 + 4 * f_c98 + 7).
7. Overflow-checked total over [value0, q_a50, q_a58, bufsize]:
   running starts at 0; each value v passes only if
   v < ~running (unsigned); otherwise the function returns -1 at
   once, stores nothing to this+0xcd0, and skips the cleanup.
   On success the total is stored to this+0xcd0 and returned.
8. Cleanup of the stack triple (pointer, stored, end), all zeroed
   in-window and never written otherwise, so in-window it is a
   no-op: if pointer != stored, stored becomes pointer; if pointer
   is nonzero, a sized delete of (end - pointer) bytes fires.

The stack canary (fs:0x28, checked at the epilogue) is not modelled.
"""

MASK = (1 << 64) - 1


def u64(x):
    return x & MASK


def s64(x):
    x &= MASK
    return x - (1 << 64) if x >> 63 else x


def sar_diff(a, b, shift=3):
    """Arithmetic shift of the wrapped signed difference a - b."""
    return s64(a - b) >> shift


class FakeLock:
    """Scriptable byte lock exposing the cmpxchg the window uses.

    ``read()`` returns the current byte. ``cmpxchg(expected, new)``
    stores ``new`` and returns (True, expected) when the byte still
    equals ``expected``; otherwise it returns (False, actual) and
    leaves the byte unchanged, exactly like LOCK CMPXCHG.
    """

    def __init__(self, initial=0):
        self.byte = initial

    def read(self):
        return self.byte

    def cmpxchg(self, expected, new):
        if self.byte == expected:
            self.byte = new
            return True, expected
        return False, self.byte


def spin_acquire(lock, on_pause=None, on_yield=None):
    """Mirror the window's acquire loop; return (pauses, yields).

    ``lock`` needs ``read()`` and ``cmpxchg(expected, new)``.
    ``on_pause``/``on_yield`` are optional hooks called with the
    pause counter at each PAUSE / sched_yield, so tests can script
    a contender (e.g. clearing the byte after N observations).
    """
    pauses = yields = 0
    counter = 0
    while True:
        observed = lock.read()
        if observed != 0:
            if on_pause is not None:
                on_pause(counter)
            pauses += 1
            if counter > 100:
                if on_yield is not None:
                    on_yield(counter)
                yields += 1
            counter += 1
            continue
        ok, _actual = lock.cmpxchg(observed, 1)
        if ok:
            return pauses, yields
        # Lost the race between the read and the cmpxchg: pause and
        # retry, exactly as the window does (counter is NOT reset).
        if on_pause is not None:
            on_pause(counter)
        pauses += 1
        if counter > 100:
            if on_yield is not None:
                on_yield(counter)
            yields += 1
        counter += 1


def aggregate_total(host, entry_fields, query_a50, query_a58,
                    triple=(0, 0, 0)):
    """Run steps 2-8. ``host`` maps field offsets to values; ``entry_fields``
    is the list of +0x38 fields in table order; ``query_a50`` /
    ``query_a58`` are the +0x78 virtual results (callables taking no
    arguments). Returns a dict with the outcome and intermediates.
    """
    capacity = 1 << (host["f0_shift"] & 0x3F)
    if len(entry_fields) < capacity:
        raise ValueError("table holds fewer entries than capacity")
    total38 = 0
    for i in range(capacity):
        total38 = u64(total38 + entry_fields[i])
    # Lock release happens here, before the rest (step 3).
    n960 = sar_diff(host["f960"], host["f940"])
    rax = n960 - 1 + (1 if host["f960"] < 1 else 0)
    value0 = u64(
        u64(host["f9e0"] - host["f9d0"])
        + u64(8 * u64(u64(rax << 6)
                      + sar_diff(host["f948"], host["f950"])
                      + sar_diff(host["f938"], host["f928"])))
        - total38)
    q1 = u64(query_a50())
    q2 = u64(query_a58())
    bufsize = u64(8 * u64(host["c88"] + 4 * host["c98"] + 7))
    values = [value0, q1, q2, bufsize]
    running = 0
    for v in values:
        if v < (~running & MASK):
            running = u64(running + v)
        else:
            return {"result": -1, "stored_cd0": None, "value0": value0,
                    "q_a50": q1, "q_a58": q2, "bufsize": bufsize,
                    "cleanup": None, "cleanup_skipped": True}
    ptr, stored, end = triple
    cleanup = None
    if ptr != stored:
        stored = ptr
    if ptr != 0:
        cleanup = ("delete", ptr, u64(end - ptr))
    return {"result": running, "stored_cd0": running, "value0": value0,
            "q_a50": q1, "q_a58": q2, "bufsize": bufsize,
            "cleanup": cleanup, "cleanup_skipped": False,
            "triple_stored": stored}
