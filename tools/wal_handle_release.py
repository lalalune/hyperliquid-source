"""Model of node #94 WAL handle release 0x51641d0 (RE-001).

Faithful to the observed binary behavior; the status helper 0x52b2550,
the completion step 0x52b13f0, the destroyer 0x4f94a40, the member
teardown helper 0x5566950 and the virtuals are used by contract only
(they are injected as callables / recorded events, not implemented).

Handle: a 0x58-byte struct with an inner-object pointer at +0x00, a
polymorphic member at +0x48 and a heap array at +0x50. The release
routine frees the handle's members and the whole inner object, but
never the handle shell itself (both sampled callers free the shell
with size 0x58 after the call returns).

Inner object: 0xe0 bytes with a string at +0x00, a shared member at
+0x28, a polymorphic member at +0x30, a heap array at +0x48, a vector
at +0xb0 (begin +0xb0, end +0xb8, capacity end +0xc0) and a pointer
member at +0xc8.

Shared object: vtable pointer at +0, count word at +8. The release
protocol: null is a no-op; count word 0x100000001 zeroes the count and
calls virtual +0x10 then +0x18; otherwise the low 32 bits are
decremented (plain when __libc_single_threaded is nonzero, lock xadd
when zero) and an old low value of 1 calls the destroyer 0x4f94a40.
"""

SENTINEL = 0x100000001
MEMBER48_DISPATCH = 0x51633E0
MEMBER48_VTABLE = 0x5766018
MEMBER48_SIZE = 0x70
MEMBER30_DISPATCH = 0x505D960
MEMBER30_VTABLE_FIRST = 0x575F768
MEMBER30_VTABLE_SECOND = 0x5759318
MEMBER30_SIZE = 0x70
INNER_SIZE = 0xE0
HANDLE_SIZE = 0x58
FINALIZE_ERROR_MESSAGE = "Seen error. Skip writing buffer."


class Status:
    """A 16-byte status record: code u32 +0, sub u16 +4, msg ptr +8."""

    def __init__(self, code=0, sub=0, msg=None):
        self.code = code
        self.sub = sub
        self.msg = msg


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


class Member48:
    """The handle +0x48 member: a 0x70-byte polymorphic object."""

    def __init__(self, vtable_second, field50):
        self.vtable_second = vtable_second
        self.field50 = field50
        self.vtable = None
        self.deleted = False


class Member30:
    """The inner +0x30 member: a 0x70-byte polymorphic object."""

    def __init__(self, vtable_second, string, ref40, sub30):
        self.vtable_second = vtable_second
        self.string = string
        self.ref40 = ref40
        self.sub30 = sub30
        self.vtable = None
        self.deleted = False


class InnerObject:
    """The 0xe0-byte object the handle points to."""

    def __init__(self, string, ref28, member30, arr48, vec, c8, seen_error):
        self.string = string
        self.ref28 = ref28
        self.member30 = member30
        self.arr48 = arr48
        self.vec = vec
        self.c8 = c8
        self.seen_error = seen_error
        self.deleted = False


class Handle:
    def __init__(self, obj, member48=None, arr50=None):
        self.obj = obj
        self.member48 = member48
        self.arr50 = arr50


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


def finalize_helper(inner, completion, log):
    """Helper 0x5163460. completion(log) fills the record on the
    flag-clear path; it is injected, not implemented here."""
    if inner.seen_error:
        log.append(("finalize-error-record", 5, 0, FINALIZE_ERROR_MESSAGE))
        return Status(5, 0, FINALIZE_ERROR_MESSAGE)
    log.append(("finalize-completion-step", 4))
    return completion(log)


def teardown_member48(m, log):
    if m is None:
        return
    if m.vtable_second != MEMBER48_DISPATCH:
        log.append(("virtual-second", m))
        return
    m.vtable = MEMBER48_VTABLE
    log.append(("vtable-set", "member48", MEMBER48_VTABLE))
    if m.field50 is not None:
        log.append(("helper-5566950", m.field50))
    log.append(("delete", "member48", MEMBER48_SIZE))
    m.deleted = True


def teardown_member30(m, single_threaded, log):
    if m is None:
        return
    if m.vtable_second != MEMBER30_DISPATCH:
        log.append(("virtual-second", m))
        return
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


def release(handle, status_helper, completion, single_threaded, log):
    """The release routine 0x51641d0.

    status_helper(inner, log) stands for 0x52b2550 and returns a
    Status; completion(log) stands for 0x52b13f0 on the finalize
    flag-clear path. The event log records every observable effect
    in binary order. The handle shell is never freed here.
    """
    if handle.obj is not None:
        tmp = finalize_helper(handle.obj, completion, log)
        if tmp.msg is not None:
            log.append(("delete-array", "finalize-msg", tmp.msg))
    teardown_member48(handle.member48, log)
    if handle.arr50 is not None:
        log.append(("delete-array", handle.arr50))
    inner = handle.obj
    if inner is None:
        log.append(("early-return-null-inner",))
        log.append(("shell-not-freed", HANDLE_SIZE))
        return
    tmp2 = status_helper(inner, log)
    if tmp2.msg is not None:
        log.append(("delete-array", "status-helper-msg", tmp2.msg))
    if inner.c8 is not None:
        log.append(("virtual-8", inner.c8))
    if inner.vec is not None:
        for el in inner.vec.elements:
            release_shared(el.ref, single_threaded, log)
        log.append(("delete", "vec-array", inner.vec.alloc_bytes))
    if inner.arr48 is not None:
        log.append(("delete-array", inner.arr48))
    teardown_member30(inner.member30, single_threaded, log)
    release_shared(inner.ref28, single_threaded, log)
    free_string(inner.string, log)
    log.append(("delete", "inner-object", INNER_SIZE))
    inner.deleted = True
    log.append(("shell-not-freed", HANDLE_SIZE))
