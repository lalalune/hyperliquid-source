"""Model of node #94 WAL writer close 0x5163e20 (RE-001).

Faithful to the observed binary behavior; the status helper 0x52b2550,
the destroyer 0x4f94a40 and the virtuals are used by contract only
(they are injected as callables / recorded events, not implemented).

Status record (16 bytes): u16 at +0, u8 at +2 (always 0 on return),
u16 at +3, u8 at +5, two padding bytes at +6 (never written here),
message pointer at +8.

Shared object: vtable pointer at +0, count word at +8. The release
protocol: null is a no-op; count word 0x100000001 zeroes the count and
calls virtual +0x10 then +0x18; otherwise the low 32 bits are
decremented (plain when __libc_single_threaded is nonzero, lock xadd
when zero) and an old low value of 1 calls the destroyer 0x4f94a40.
"""

SENTINEL = 0x100000001
MEMBER30_DISPATCH = 0x505D960
MEMBER30_VTABLE_FIRST = 0x575F768
MEMBER30_VTABLE_SECOND = 0x5759318
OBJECT_SIZE = 0xE0
MEMBER30_SIZE = 0x70


class Status:
    """A 16-byte status record."""

    def __init__(self, f0=0, f2=0, f3=0, f5=0, msg=None):
        self.f0 = f0 & 0xFFFF
        self.f2 = f2 & 0xFF
        self.f3 = f3 & 0xFFFF
        self.f5 = f5 & 0xFF
        self.msg = msg

    def reset(self):
        # Entry init: u32 0 at +0 (covers f0 and f2), u16 0 at +4
        # (covers f3's high byte region), qword 0 at +8. Bytes 6-7
        # are untouched; the model leaves padding unmodelled.
        self.f0 = 0
        self.f2 = 0
        self.f3 = 0
        self.f5 = 0
        self.msg = None

    def move_from(self, other):
        # Fields +0, +3, +5, +8 are copied; byte +2 is not copied
        # and stays 0 from the reset.
        self.f0 = other.f0
        self.f3 = other.f3
        self.f5 = other.f5
        self.msg = other.msg
        other.msg = None


class Shared:
    """A refcounted object: vtable pointer at +0, count word at +8."""

    def __init__(self, count_word, name="shared"):
        self.count_word = count_word
        self.name = name
        self.destroyed = False


class Str:
    """A std::string-shaped value: pointer +0, capacity-or-buffer +0x10.

    heap=False means the pointer equals the address of the capacity
    slot (inline/empty form): freeing it is skipped by the binary.
    """

    def __init__(self, heap, cap, name="str"):
        self.heap = heap
        self.cap = cap
        self.name = name


class VecElement:
    def __init__(self, ref):
        self.ref = ref


class Vector:
    """The +0xb0 vector: begin +0xb0, end +0xb8, capacity end +0xc0.

    The backing array is freed with size = capacity end minus begin
    (not length-based), whenever begin is non-null. vec=None models a
    null begin: no walk and no array free.
    """

    def __init__(self, elements, alloc_bytes):
        self.elements = elements
        self.alloc_bytes = alloc_bytes


class Member30:
    """The +0x30 member: a 0x70-byte polymorphic object."""

    def __init__(self, vtable_second, string, ref40, sub30):
        self.vtable_second = vtable_second
        self.string = string
        self.ref40 = ref40
        self.sub30 = sub30
        self.vtable = None
        self.deleted = False


class WriterObject:
    """The 0xe0-byte object closed by 0x5163e20."""

    def __init__(self, string, ref28, member30, arr48, vec, c8):
        self.string = string
        self.ref28 = ref28
        self.member30 = member30
        self.arr48 = arr48
        self.vec = vec
        self.c8 = c8
        self.deleted = False


class Handle:
    def __init__(self, obj):
        self.obj = obj


def free_string(s, log):
    """The binary's string free rule: skip the inline form, else
    sized delete with size = capacity + 1."""
    if s is None:
        return
    if not s.heap:
        log.append(("string-skip-inline", s.name))
        return
    log.append(("delete", s.name, s.cap + 1))


def release_shared(ref, single_threaded, log):
    """The shared-release protocol, exactly as observed."""
    if ref is None:
        log.append(("release-noop", None))
        return
    if ref.count_word == SENTINEL:
        ref.count_word = 0
        log.append(("dispose", ref.name))
        log.append(("destroy", ref.name))
        ref.destroyed = True
        return
    use = ref.count_word & 0xFFFFFFFF
    weak = ref.count_word & 0xFFFFFFFF00000000
    mode = "plain-dec" if single_threaded else "lock-xadd"
    log.append((mode, ref.name, use))
    ref.count_word = weak | ((use - 1) & 0xFFFFFFFF)
    if use == 1:
        log.append(("destroyer-4f94a40", ref.name))
        ref.destroyed = True


def close(out, handle, helper, single_threaded, log):
    """The close routine. helper(obj, log) returns a Status.

    Returns the out status record. The event log records every
    observable effect in binary order.
    """
    out.reset()
    if handle.obj is None:
        log.append(("early-return-null-handle",))
        return out
    tmp = helper(handle.obj, log)
    out.move_from(tmp)
    # The two delete[] calls emitted after this move free null
    # pointers only (out was just zeroed, temp slot just cleared).
    log.append(("free-null", "out-msg-slot"))
    log.append(("free-null", "temp-msg-slot"))
    obj = handle.obj
    handle.obj = None
    if obj is None:
        return out
    tmp2 = helper(obj, log)
    if tmp2.msg is not None:
        log.append(("delete", "second-helper-msg", tmp2.msg))
    if obj.c8 is not None:
        log.append(("virtual-8", obj.c8))
    if obj.vec is not None:
        for el in obj.vec.elements:
            release_shared(el.ref, single_threaded, log)
        log.append(("delete", "vec-array", obj.vec.alloc_bytes))
    if obj.arr48 is not None:
        log.append(("delete-array", obj.arr48))
    m = obj.member30
    if m is not None:
        if m.vtable_second != MEMBER30_DISPATCH:
            log.append(("virtual-second", m))
        else:
            m.vtable = MEMBER30_VTABLE_FIRST
            log.append(("vtable-set", "member30", MEMBER30_VTABLE_FIRST))
            free_string(m.string, log)
            release_shared(m.ref40, single_threaded, log)
            m.vtable = MEMBER30_VTABLE_SECOND
            log.append(("vtable-set", "member30", MEMBER30_VTABLE_SECOND))
            if m.sub30 is not None:
                log.append(("virtual-8", m.sub30))
            log.append(("delete", "member30", MEMBER30_SIZE))
            m.deleted = True
    release_shared(obj.ref28, single_threaded, log)
    free_string(obj.string, log)
    log.append(("delete", "writer-object", OBJECT_SIZE))
    obj.deleted = True
    return out
