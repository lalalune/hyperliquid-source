"""Python model of node #94's seek driver (0x516c7e0) and the generic
loop (0x51651e0) it compares its +0x60 slot against.

Pinned from the digest-verified work binary (SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
The Seek callback (0x516b130) and the iterator virtuals are by
contract: the model reproduces their call order, arguments and
branching, not their internals.
"""

KNOWN_LOOP = 0x51651E0
KNOWN_98 = 0x5164750
GOT_98 = 0x57783C0
SENTINEL = 0xFFFFFFFFFFFFFF
DRIVER = 0x516C7E0
GENERIC_LOOP = 0x51651E0
SEEK = 0x516B130


class SliceStruct:
    """The driver's rsi argument: fields +0x00, +0x08, +0x10."""

    def __init__(self, first, start, end):
        self.first = first
        self.start = start
        self.end = end

    def target(self):
        """Target slice passed to the iterator +0x30 virtual."""
        return (self.start, self.end - self.start)


class Host:
    """Host fields the driver reads (roles, not class names)."""

    def __init__(self, f50=None, f58=None, f60=None, b31=0, f68=0,
                 f6c=0, c70=None, a50=None):
        self.f50 = f50
        self.f58 = f58
        self.f60 = f60
        self.b31 = b31
        self.f68 = f68
        self.f6c = f6c
        self.c70 = c70
        self.a50 = a50


class A50Object:
    """The host +0xa50 object: vtable slots +0x60, +0x90, +0x98.

    slot60 is either KNOWN_LOOP or a callable delegate with
    signature (obj, slice_struct, context, callback).  slot90 is a
    callable returning an iterator; slot98 is either KNOWN_98
    (meaning: use slot90) or a callable returning an iterator.
    """

    def __init__(self, slot60, slot90, slot98):
        self.slot60 = slot60
        self.slot90 = slot90
        self.slot98 = slot98


class Iterator:
    """Test-double iterator with the four virtual slots the loop uses."""

    def __init__(self, valid_sequence, values):
        self._valid = list(valid_sequence)
        self._values = list(values)
        self.seek_calls = []
        self.next_calls = 0
        self.slot18_calls = 0

    def seek30(self, target, first):
        self.seek_calls.append((target, first))

    def slot18(self):
        self.slot18_calls += 1
        return self._values.pop(0) if self._values else None

    def next20(self):
        self.next_calls += 1

    def valid10(self):
        return self._valid.pop(0) if self._valid else False


def acquire_iterator(obj):
    """The +0x90/+0x98 dispatch shared by driver and generic loop."""
    if obj.slot98 == KNOWN_98:
        return obj.slot90(obj)
    return obj.slot98(obj)


def build_context(host, slice_struct, rdx, cl_byte, r8, r9, stack):
    """Build the driver's rsp+0x10 context struct from its arguments.

    stack is the eight stack arguments in caller order (stack0..7).
    """
    s0, s1, s2, s3, s4, _s5, s6, s7 = stack
    return {
        0x00: s3,
        0x08: slice_struct,
        0x10: s6,
        0x18: s7,
        0x20: s0,
        0x28: s1,
        0x30: SENTINEL,
        0x38: (s2, host.f58),
        0x48: s4,
        0x50: rdx,
        0x58: (host, host.f60),
        0x68: host.f50,
        0x70: (host.b31 & 0xFF) | ((cl_byte & 0xFF) << 8),
        0x78: (host.c70, r8),
        0x88: r9,
        0x90: host.f68 & 0xFF,
        0x98: host.f6c & 0xFFFFFFFF,
    }


def run_loop(iterator, slice_struct, callback, context):
    """The generic loop (0x51651e0): seek, then valid-gated callback.

    callback(context, slot18_value) -> bool.  Returns None, as the
    generic loop returns void.
    """
    iterator.seek30(slice_struct.target(), slice_struct.first)
    while iterator.valid10():
        if not callback(context, iterator.slot18()):
            break
        iterator.next20()


def drive(host, slice_struct, rdx, cl_byte, r8, r9, stack, seek_callback):
    """The driver (0x516c7e0).  Returns the out value (context +0x30).

    The caller passes a mutable one-element out list as stack[5]'s
    target; this model returns the value directly and the tests
    check the same value lands in the out slot.
    """
    context = build_context(host, slice_struct, rdx, cl_byte, r8, r9,
                            stack)
    obj = host.a50
    if obj.slot60 != KNOWN_LOOP:
        # Direct arm: delegate, then fall through to the exit write.
        obj.slot60(obj, slice_struct, context, seek_callback)
    else:
        iterator = acquire_iterator(obj)
        run_loop(iterator, slice_struct, seek_callback, context)
    return context[0x30]
