"""Python model of the RE-001 rebuild-and-replace routine 0x5d56120 (node #115).

Models only the established semantics from
research/work-items/RE-001-rebuild-replace-56120-115/:
destination pair rebuild, fresh 0x58-byte object construction, lazy
singleton link, install of the (view, owner) pair, and release of the
previous owner. Refcount increments follow the guard-byte rule only as
event counts (plain vs locked increment is not observable in the model).
The 0x6099ce0 subobject call is recorded as an event; its inner effect
is unknown and is not modelled.
"""

PACKED_SENTINEL = 0x100000001
DERIVED_TABLE = 0x64D08A8
MIDDLE_TABLE = 0x64CF200
OUTER_TABLE = 0x64C9830


class Ref:
    """A refcounted pointer target; owners counts owning references."""

    def __init__(self, name, owners=0):
        self.name = name
        self.owners = owners
        self.destroyed = False

    def __repr__(self):
        return f"Ref({self.name!r}, owners={self.owners})"


def incref(ref, events):
    if ref is not None:
        ref.owners += 1
        events.append(("incref", ref.name))


def release(ref, events):
    """Shared release helper 0x5d350c0, simplified: decrement, destroy at zero."""
    if ref is None:
        return
    ref.owners -= 1
    name = getattr(ref, "name", "installed-object")
    events.append(("release", name))
    if ref.owners == 0:
        ref.destroyed = True
        events.append(("destroy", name))


class Dest:
    """Destination struct: pair A, pair B, view, owner."""

    def __init__(self, a0=None, a1=None, b0=None, b1=None, view=None, owner=None):
        self.a0, self.a1 = a0, a1
        self.b0, self.b1 = b0, b1
        self.view, self.owner = view, owner


class SubObject:
    def __init__(self):
        self.table = None
        self.a0 = self.a1 = None


class NewObject:
    def __init__(self):
        self.table = OUTER_TABLE
        self.packed = PACKED_SENTINEL
        self.sub = SubObject()
        self.b0 = self.b1 = None
        self.singleton_link = None
        self.owners = 1  # the destination +0x28 slot's single reference


class Singleton:
    """Lazy singleton accessor 0x5fe2680."""

    def __init__(self):
        self.guard = False
        self.cached = None
        self.builds = 0

    def get(self, events):
        if self.guard:
            return self.cached
        self.builds += 1
        record_a = {"table": 0x64CED00, "packed": PACKED_SENTINEL,
                    "slot_10": 0x64CE930}
        record_b = {"first_slot": "record_a+0x10", "second": record_a}
        self.cached = record_b
        self.guard = True
        events.append(("singleton_build",))
        return self.cached


def init_subobject(sub, dest, events):
    """Initializer 0x5fe7210 (minus the unknown 0x6099ce0 inner effect)."""
    sub.table = MIDDLE_TABLE
    sub.a0, sub.a1 = dest.a0, dest.a1
    incref(sub.a1, events)
    events.append(("sub_init_string_call",))


def apply(dest, src_a, src_b, singleton, emit):
    """Routine 0x5d56120. src_a / src_b are (first_word, ref_or_None) pairs.

    emit is an event callback; the routine collects its events in order
    and emits them through it.
    """
    events = []
    dest.a0, dest.a1 = src_a
    incref(dest.a1, events)
    dest.b0, dest.b1 = src_b
    incref(dest.b1, events)
    dest.view = None
    new = NewObject()
    init_subobject(new.sub, dest, events)
    new.sub.table = DERIVED_TABLE
    new.b0, new.b1 = dest.b0, dest.b1
    incref(new.b1, events)
    new.singleton_link = singleton.get(events)["first_slot"]
    old_owner = dest.owner
    dest.view = new.sub
    dest.owner = new
    if old_owner is not None:
        release(old_owner, events)
    else:
        events.append(("return_no_release",))
    for event in events:
        emit(event)
    return new


def cleanup_full(new, dest, events):
    """Landing pad at 0x5d5624f + resume path."""
    release(new.b1, events)
    new.sub.table = MIDDLE_TABLE
    release(new.sub.a1, events)
    events.append(("base_destroy_sub",))
    events.append(("delete_new", 0x58))
    cleanup_resume(dest, events)


def cleanup_delete(new, dest, events):
    """Landing pad at 0x5d56261 + resume path."""
    events.append(("delete_new", 0x58))
    cleanup_resume(dest, events)


def cleanup_resume(dest, events):
    """Landing pad at 0x5d56258 + resume path at 0x5d562ad."""
    release(dest.owner, events)
    release(dest.b1, events)
    release(dest.a1, events)
    events.append(("unwind_resume",))
