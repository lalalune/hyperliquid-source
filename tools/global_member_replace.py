"""Python model for RE-001 node #94 global member replace (0x5169da0).

The replace function takes one argument, the host object. It either
does nothing (the host +0xa60 guard byte is set) or it builds a fresh
0x80 member, builds a 0xe8 wrapper around it, installs the wrapper at
host +0xce0, and destroys the previous wrapper. The wrapper builder
(0x5196de0), the hook-object constructor (0x5311bc0), the +0x60-list
helper (0x5165380), the array reorder helpers (0x5164da0/0x5164af0)
and the member virtuals are by contract: only their call order,
arguments and branching are modelled, not their internals.

Field offsets are the raw member/wrapper offsets from the window.
"""

# Vtable address points installed by the construction prologue.
VT_00 = 0x575B230
VT_38 = 0x575B1F8
VT_40 = 0x5757BE0
# Vtable point the exception cleanup resets a member to.
VT_CLEANUP = 0x57593F8


class A58Object:
    """The host +0xa58 object; its +0x90 virtual supplies member +0x50."""

    def __init__(self, v90_result):
        self.v90_result = v90_result

    def v90(self):
        return self.v90_result


class Member:
    """The 0x80 member built by the replace function."""

    def __init__(self):
        self.vt00 = None
        self.vt38 = None
        self.vt40 = None
        self.f28 = None
        self.f30 = None
        self.f48 = None
        self.f50 = None
        self.f58 = None
        self.f5a = None
        self.f60 = None
        self.f68 = None
        self.f6c = None
        self.f70 = None
        self.f78 = None
        self.released = False


class Hook:
    """The stack hook object built by 0x5311bc0.

    ``field38`` is the value passed twice to the hook; ``fn`` is the
    +0x48 field, invoked with (field38, field38, 3) when set.
    """

    def __init__(self, field38=None, fn=None):
        self.field38 = field38
        self.fn = fn


class Node60:
    """A 0x28-byte node of the old wrapper's +0x60 list."""

    def __init__(self, arg18, nxt=None):
        self.arg18 = arg18
        self.nxt = nxt


class Node80:
    """A 0x30-byte node of the old wrapper's +0x80 intrusive list.

    ``string`` is (heap_ptr, heap_size) for a heap string, or None for
    the inline case (the +0x10 pointer equals the node's +0x20 address,
    so no heap free happens). ``nxt`` is the next node, or the
    SENTINEL for the list end.
    """

    def __init__(self, string=None, nxt=None):
        self.string = string
        self.nxt = nxt


class VecElem:
    """One 16-byte element of the old wrapper's +0xc0 array."""

    def __init__(self, key):
        self.key = key
        self.released = False


class NodeB0:
    """A 0x20-byte node of the old wrapper's +0xb0 list."""

    def __init__(self, fn, arg8, arg10, nxt=None):
        self.fn = fn
        self.arg8 = arg8
        self.arg10 = arg10
        self.nxt = nxt


class Wrapper:
    """The 0xe8 wrapper installed at host +0xce0."""

    def __init__(self):
        # Three (ptr, end) strings; None means the null pointer.
        self.s00 = None
        self.s18 = None
        self.s30 = None
        self.list60 = None
        self.list80 = None  # first node, or SENTINEL when empty
        self.vec = None  # list of VecElem, or None for a null buffer
        self.b8 = 0
        self.cb98 = None  # callable or None
        self.cb_a0 = None
        self.cb_a8 = None
        self.list_b0 = None


SENTINEL = object()


class Host:
    """The host object the replace function operates on."""

    def __init__(self, a60=0, a58=None, c58=None, f10=None, b31=0,
                 f6c=0, f60=None, ce0=None):
        self.a60 = a60
        self.a58 = a58
        self.c58 = c58
        self.f10 = f10
        self.b31 = b31
        self.f6c = f6c
        self.f60 = f60
        self.ce0 = ce0


def build_member(host):
    """Build the fresh 0x80 member from the host fields.

    This is the same construction prologue as the #2011 member
    construction, with three pinned differences: +0x58 is 0 (not
    0x100), +0x50 comes from the host +0xa58 object's +0x90 virtual
    directly (no +0x98 dispatch), and +0x28 stays 0 (no probe gate).
    The member +0x8/+0x20 pair is zeroed by 0x541ca90 first.
    """
    m = Member()
    m.vt00 = VT_00
    m.vt38 = VT_38
    m.vt40 = VT_40
    m.f28 = 0
    m.f30 = host.c58
    m.f48 = host.f10
    m.f50 = host.a58.v90()
    m.f58 = 0
    m.f5a = (host.b31 ^ 1) & 0xFF
    m.f60 = host.f6c & 0xFFFFFFFF
    m.f68 = 0
    m.f6c = 0
    m.f70 = 0
    m.f78 = host.f60
    return m


def destroy_old(old, trace):
    """Destroy a displaced wrapper, recording each step in order."""
    if old.b8 != 0:
        old.b8 = 0
        trace.append("b8_cleared")
        # The +0xc0 array is reordered by 0x5164da0/0x5164af0 and the
        # insertion/search/shift loops (by contract); each remaining
        # element is then released through its +0x8 field.
        trace.append("array_reordered")
        if old.vec:
            for elem in old.vec:
                elem.released = True
                trace.append("element_released")
        trace.append("array_end_reset")
        if old.cb98 is not None:
            old.cb98(old.cb_a0, old.cb_a8)
            trace.append("callback_called")
        node = old.list_b0
        while node is not None:
            node.fn(node.arg8, node.arg10)
            trace.append("b0_node_freed")
            node = node.nxt
        old.cb98 = None
        old.list_b0 = None
        trace.append("cb_fields_zeroed")
    # Common tail, shared by both +0xb8 arms.
    if old.vec is not None:
        trace.append("array_buffer_freed")
    trace.append("drain_98")
    node = old.list80
    while node is not SENTINEL and node is not None:
        if node.string is None:
            trace.append("node80_string_inline_skipped")
        else:
            trace.append("node80_string_freed")
        trace.append("node80_freed")
        node = node.nxt
    node = old.list60
    while node is not None:
        # 0x5165380 is called on the node's +0x18 field (by contract),
        # then the 0x28-byte node itself is freed.
        trace.append("list60_node_serviced")
        node = node.nxt
    for name in ("s30", "s18", "s00"):
        if getattr(old, name) is not None:
            trace.append("string_freed")
    trace.append("wrapper_freed")


def replace(host, hook=None, temp_string=None):
    """Run the 0x5169da0 replace on ``host``.

    Returns (member, wrapper, trace). When the host +0xa60 guard byte
    is set, nothing happens and all three results are (None, None,
    ["guard_noop"]). ``hook`` is the Hook object built by 0x5311bc0;
    ``temp_string`` is the 16-byte stack string handed to the wrapper
    builder, freed afterwards when it is a heap string (not None).
    """
    trace = []
    if host.a60 != 0:
        trace.append("guard_noop")
        return None, None, trace
    member = build_member(host)
    trace.append("member_built")
    if hook is not None and hook.fn is not None:
        hook.fn(hook.field38, hook.field38, 3)
        trace.append("hook_called")
    else:
        trace.append("hook_skipped")
    wrapper = Wrapper()
    trace.append("wrapper_built")
    # The construction reference on the new member is released through
    # its +0x8 virtual once the wrapper owns it.
    member.released = True
    trace.append("member_release")
    if temp_string is not None:
        trace.append("temp_string_freed")
    old = host.ce0
    host.ce0 = wrapper
    trace.append("swapped")
    if old is None:
        trace.append("old_none")
        return member, wrapper, trace
    destroy_old(old, trace)
    return member, wrapper, trace
