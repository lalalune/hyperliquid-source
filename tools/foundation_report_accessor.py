"""Model of node #94 0x5158ef0: refresh-then-render report accessor.

The window (0x5158ef0..0x5159130, FDE 0x00634b88) takes an outer
object, a render target and a flag byte, and renders the report
that 0x5157d30 builds from a fresh snapshot:

  1. if [outer+0x128] (the inner object) is null, return 0 with the
     target untouched and no refresh, lock or render attempted;
  2. otherwise call the timed snapshot refresh 0x514f270 with the
     flag INVERTED (flag ^ 1), then re-read [outer+0x128];
  3. lock the inner object's mutex (pthread_mutex_lock on the inner
     object itself); a nonzero lock result throws system_error;
  4. copy the whole 0x138-byte published snapshot at inner+0x28
     onto the stack at rsp+0x00, with the string slot at snapshot
     +0x20 copied by _M_assign (not by raw bytes) and the tail
     fields at snapshot+0x120/+0x128 filled from inner+0x148 /
     inner+0x150; the stack slots at snapshot+0x00/+0x10/+0x120/
     +0x128 are zeroed before the lock and then overwritten by
     the copy (recorded as observed dead writes);
  5. unlock the inner mutex -- the render happens AFTER the unlock;
  6. call the report builder 0x5157d30 with (stack snapshot at
     rsp+0x00, the render target, clock holder at [outer+0x780]);
     the builder mutates the target in place, so this window
     performs no temp-string construction and no move-assign;
  7. dispose the snapshot's identity string (sized delete only
     when it is not SSO: pointer != its own buffer at rsp+0x30,
     size = capacity + 1), then return 1.

Exception cleanup (0x5158ebe..0x5158eee, FDE 0x00634bd4) has two
entries: the full entry unlocks the mutex and then disposes the
snapshot identity string, the dispose-only entry disposes just
that string; both check the canary and call _Unwind_Resume. Which
landing stub serves which call site is not claimed (LSDA mapping).

The window is reached through two tail-jump thunks that fix the
flag byte: 0x5159130 passes flag 0 (so the refresh gets flag 1)
and 0x5159140 passes flag 1 (so the refresh gets flag 0). Neither
thunk has a direct caller, tail jump or absolute pointer in .text,
so their reaching path is left unclaimed, as is the window's own
direct-caller census (no direct call exists for 0x5158ef0 itself;
it is reached only via the two thunks).

The refresh (RE-001-timed-snapshot-94) and the report builder
0x5157d30 are callees here only; their internals are bound by
their own packets, not re-claimed here. The builder's own packet
is not yet written; this window passes its target through
unchanged and claims nothing about the builder's internals.
"""


class LockFailed(Exception):
    """pthread_mutex_lock returned nonzero; the binary throws."""


class CString:
    """A std::string-like value: content plus an SSO/heap flag.

    ``sso`` True means the string lives in its own buffer, so
    disposal frees nothing; False means disposal is a sized delete
    of (pointer, capacity + 1), matching the binary's SSO check
    (pointer compared against the object's own buffer) and its
    ``lea 1(%rax)`` sized-delete argument, where rax holds the
    capacity field of the stack string.
    """

    def __init__(self, content="", sso=True, capacity=None):
        self.content = content
        self.sso = sso
        self.capacity = len(content) if capacity is None else capacity

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
            snap[snap_off] = CString(value.content, value.sso,
                                     value.capacity)
        else:
            snap[snap_off] = value
    return snap


def refresh_then_render(outer, target, flag, refresh, render,
                        lock, unlock, events):
    """Run the 0x5158ef0 behavior. Returns 1 on success, 0 on null.

    ``outer`` is a dict with keys ``inner`` (None or a dict with a
    ``published`` snapshot dict) and ``clock_holder``. ``target`` is
    passed through to ``render`` unchanged. ``refresh(outer, flag)``,
    ``render(snapshot, target, clock_holder)``, ``lock(inner)`` (0 on
    success) and ``unlock(inner)`` are callbacks; every observable
    step appends to ``events``. ``render`` mutates the target in
    place, as 0x5157d30 does with the object it receives.
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
    render(snapshot, target, outer["clock_holder"])
    events.append(("render",))
    string = snapshot[0x20]
    if string.sso:
        events.append(("dispose_snapshot_string", True, None))
    else:
        events.append(("dispose_snapshot_string", False,
                       string.capacity + 1))
    return 1


def thunk_flag(thunk_address):
    """Flag byte fixed by each tail-jump thunk into 0x5158ef0."""
    if thunk_address == 0x5159130:
        return 0
    if thunk_address == 0x5159140:
        return 1
    raise ValueError("not a 0x5158ef0 thunk: %#x" % thunk_address)


def thunk_refresh_flag(thunk_address):
    """Flag the refresh receives when reached via a thunk."""
    return thunk_flag(thunk_address) ^ 1
