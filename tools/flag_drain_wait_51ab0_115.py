"""Python model of the RE-001 flag-gated drain-and-wait routine 0x5d51ab0 (node #115).

Models only the established control flow from
research/work-items/RE-001-flag-drain-wait-51ab0-115/: the routine takes
one argument, a holder pointer in rdi, and returns nothing. Its
observable outcome is the sequence of lock, teardown, wait and unlock
operations it performs, driven by two flag bytes and one watched field
that other threads write. The hooks (teardown, wait, lock) are the
points where other threads act: a hook may clear a flag or the watched
field, exactly as another thread would between the routine's own steps.

What is NOT modeled: the internals of the teardown callee 0x5fcbe20
(called with H+0xd40, return ignored), of the lock-shaped callees, or
of the condition-variable wait; the unwind landing pads (exception
edges, recorded in the packet but not normal flow); the stack canary
check, which passes on every normal return.
"""

ADDRESS = 0x5D51AB0
SIZE_BYTES = 357

LOCK_SLOT = 0x700
FLAG_DRAIN = 0x489
FLAG_WAIT = 0x48A
TEARDOWN_ARG = 0xD40
CONDVAR_OFFSET = 0x14B0
MUTEX_OFFSET = 0x14E0
WATCHED_OFFSET = 0x1508


class Holder:
    """The holder's fields the routine reads; other threads write them."""

    def __init__(self, flag_drain=False, flag_wait=False, watched=None):
        self.flag_drain = flag_drain
        self.flag_wait = flag_wait
        self.watched = watched


class DrainWait:
    """The routine's control flow, with hooks for the outside world.

    Hooks, all optional:
      on_teardown() -- called for each drain iteration (the 0x5fcbe20 call)
      on_wait() -- called for each condition-variable wait
      on_mutex_lock() -- returns an errno (0 means the lock was acquired)
      on_mutex_unlock(), on_lock_700(), on_unlock_700() -- lock operations
    Every observable step is also appended to `trace` in order.
    """

    def __init__(self, on_teardown=None, on_wait=None, on_mutex_lock=None,
                 on_mutex_unlock=None, on_lock_700=None, on_unlock_700=None):
        self.on_teardown = on_teardown or (lambda: None)
        self.on_wait = on_wait or (lambda: None)
        self.on_mutex_lock = on_mutex_lock or (lambda: 0)
        self.on_mutex_unlock = on_mutex_unlock or (lambda: None)
        self.on_lock_700 = on_lock_700 or (lambda: None)
        self.on_unlock_700 = on_unlock_700 or (lambda: None)
        self.trace = []

    def run(self, holder):
        """Run the routine to its normal return; returns None."""
        # Entry: call the five-byte no-op stub 0x60d5390 on H+0x700.
        self.trace.append(("entry_noop", LOCK_SLOT))
        # Drain path: while the drain flag reads nonzero, release the
        # H+0x700 lock, run the teardown on H+0xd40, re-acquire the
        # lock, then re-test both flags.
        while holder.flag_drain:
            self.trace.append(("unlock", LOCK_SLOT))
            self.on_unlock_700()
            self.trace.append(("teardown", TEARDOWN_ARG))
            self.on_teardown()
            self.trace.append(("lock", LOCK_SLOT))
            self.on_lock_700()
        # Wait path: only reached when the drain flag reads zero.
        if not holder.flag_wait:
            return None
        if holder.watched is None:
            return None
        errno = self.on_mutex_lock()
        self.trace.append(("mutex_lock", MUTEX_OFFSET, errno))
        if errno != 0:
            # Landing at 0x5d51be6: the system-error thrower; no
            # normal return, no wait, no unlock.
            self.trace.append(("throw_system_error", errno))
            raise SystemError(errno)
        while holder.watched is not None:
            self.trace.append(("condvar_wait", CONDVAR_OFFSET))
            self.on_wait()
        self.trace.append(("mutex_unlock", MUTEX_OFFSET))
        self.on_mutex_unlock()
        return None
