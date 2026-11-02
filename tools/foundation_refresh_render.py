"""Model of node #94 0x514fd60: refresh-then-render BlockCache accessor.

The window (0x514fd60..0x514ffd8, FDE 0x006341b0) takes an outer
object, a destination string and a flag byte, and renders the
BlockCache report that 0x514f770 formats into the destination:

  1. if [outer+0x128] (the inner object) is null, return 0 with the
     destination untouched and no refresh, lock or render attempted;
  2. otherwise call the timed snapshot refresh 0x514f270 with the
     flag INVERTED (flag ^ 1), then re-read [outer+0x128];
  3. lock the inner object's mutex (pthread_mutex_lock on the inner
     object itself); a nonzero lock result throws system_error;
  4. copy the whole 0x138-byte published snapshot at inner+0x28
     onto the stack at rsp+0x20, with the string slot at snapshot
     +0x20 copied by _M_assign (not by raw bytes) and the tail
     fields at snapshot+0x120/+0x128 filled from inner+0x148 /
     inner+0x150; the stack slots at snapshot+0x120 and +0x128 are
     zeroed before the lock and then overwritten by the copy;
  5. unlock the inner mutex -- the render happens AFTER the unlock;
  6. call the report formatter 0x514f770 with (temp string at
     rsp+0x00, stack snapshot at rsp+0x20, clock holder at
     [outer+0x780]); the formatter constructs the temp string in
     place, so it needs no prior initialization;
  7. move-assign the temp string into the destination (0x514b4f0);
  8. dispose the temp string (sized delete only when it is not
     SSO: pointer != its own buffer, size = length + 1) and the
     snapshot's identity string the same way, then return 1.

Exception cleanup (0x514fd30..0x514fd60, FDE 0x006341fc) has two
entries: the full entry unlocks the mutex and then disposes the
snapshot identity string, the dispose-only entry disposes just
that string; both check the canary and call _Unwind_Resume. The
cleanup never disposes the temp string. Which landing stub serves
which call site is not claimed (LSDA mapping).

The window is reached through two tail-jump thunks that fix the
flag byte: 0x514ffe0 passes flag 0 (so the refresh gets flag 1)
and 0x514fff0 passes flag 1 (so the refresh gets flag 0). Neither
thunk has a direct caller, tail jump or absolute pointer in .text,
so their reaching path is left unclaimed, as is the window's own
direct-caller census (no direct call, tail jump or qword
reference exists for 0x514fd60 itself).

The refresh (RE-001-timed-snapshot-94) and the formatter
(RE-001-blockcache-report-94) are callees here only; their
internals are bound by their own packets, not re-claimed here.
"""


class LockFailed(Exception):
    """pthread_mutex_lock returned nonzero; the binary throws."""


class CString:
    """A std::string-like value: content plus an SSO/heap flag.

    ``sso`` True means the string lives in its own buffer, so
    disposal frees nothing; False means disposal is a sized delete
    of (pointer, length + 1), matching the binary's SSO check
    (pointer compared against the object's own buffer) and its
    ``lea 1(%rax)`` sized-delete argument.
    """

    def __init__(self, content="", sso=True):
        self.content = content
        self.sso = sso

    def __eq__(self, other):
        return isinstance(other, CString) and self.content == other.content

    def __repr__(self):
        return "CString(%r, sso=%r)" % (self.content, self.sso)


SNAPSHOT_FIELDS = (
    # (snapshot offset, published offset, kind) for the whole copy.
    # The string slot at +0x20 is assigned, not raw-copied.
    (0x00, 0x28, "words"), (0x10, 0x38, "words"),
    (0x20, 0x48, "string"),
    (0x40, 0x68, "words"), (0x50, 0x78, "words"),
    (0x60, 0x88, "words"), (0x70, 0x98, "words"),
    (0x80, 0xa8, "words"), (0x90, 0xb8, "words"),
    (0xa0, 0xc8, "words"), (0xb0, 0xd8, "words"),
    (0xc0, 0xe8, "words"), (0xd0, 0xf8, "words"),
    (0xe0, 0x108, "words"), (0xf0, 0x118, "words"),
    (0x100, 0x128, "words"), (0x110, 0x138, "words"),
    (0x120, 0x148, "tail"), (0x128, 0x150, "words"),
)


def copy_snapshot(published):
    """Copy a published snapshot dict into a fresh stack snapshot.

    ``published`` maps published offsets (inner+0x28 + k) to values;
    the string at published +0x20 (snapshot +0x20) is copied by
    assignment, so the copy owns an equal but independent string.
    Returns a dict keyed by snapshot offset.
    """
    snap = {}
    for snap_off, pub_off, kind in SNAPSHOT_FIELDS:
        value = published[pub_off]
        if kind == "string":
            snap[snap_off] = CString(value.content, value.sso)
        else:
            snap[snap_off] = value
    return snap


def refresh_then_render(outer, dest, flag, refresh, render,
                        lock, unlock, events):
    """Run the 0x514fd60 behavior. Returns 1 on success, 0 on null.

    ``outer`` is a dict with keys ``inner`` (None or a dict with a
    ``published`` snapshot dict) and ``clock_holder``. ``dest`` is a
    one-element list holding a CString. ``refresh(outer, flag)``,
    ``render(temp, snapshot, clock_holder)``, ``lock(inner)`` (0 on
    success) and ``unlock(inner)`` are callbacks; every observable
    step appends to ``events``. ``render`` writes the report into
    the temp CString it receives.
    """
    inner = outer["inner"]
    if inner is None:
        return 0
    refresh_flag = flag ^ 1
    events.append(("refresh", refresh_flag))
    refresh(outer, refresh_flag)
    inner = outer["inner"]
    if lock(inner) != 0:
        raise LockFailed("pthread_mutex_lock returned nonzero")
    events.append(("lock",))
    snapshot = copy_snapshot(inner["published"])
    events.append(("copy",))
    unlock(inner)
    events.append(("unlock",))
    temp = CString()
    render(temp, snapshot, outer["clock_holder"])
    events.append(("render", temp.content))
    dest[0] = CString(temp.content, temp.sso)
    events.append(("move_assign",))
    events.append(("dispose_temp", temp.sso))
    events.append(("dispose_snapshot_string", snapshot[0x20].sso))
    return 1


def thunk_flag(thunk_address):
    """Flag byte fixed by each tail-jump thunk into 0x514fd60."""
    if thunk_address == 0x514FFE0:
        return 0
    if thunk_address == 0x514FFF0:
        return 1
    raise ValueError("not a 0x514fd60 thunk: %#x" % thunk_address)


def thunk_refresh_flag(thunk_address):
    """Refresh flag the timed refresh receives via each thunk."""
    return thunk_flag(thunk_address) ^ 1
