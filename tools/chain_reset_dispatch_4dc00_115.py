#!/usr/bin/env python3
"""Model of node #115 routine 0x5d4dc00: chain reset and dispatch.

The routine tears down a chain held by its fourth argument, resets
that struct, calls the second argument's vtable slot 0x30, and
dispatches through callee 0x5eeea60, with an acquire/release pair
around the dispatch only when the lookup result's first byte is
zero. Callees are injectable so the model can be tested without
the target binary; only argument lists and call order are pinned.

Fourth-struct reset, exactly as in the binary: +0x10 = 0,
+0x18 = the address of the struct's own +0x08 field, +0x20 = that
same address, +0x28 = 0. The sentinel "struct+0x08" stands for
that address in the model.
"""

INLINE = "struct+0x08"


class ModelError(ValueError):
    """Raised on null or malformed model inputs (stated openly)."""


class ChainString:
    """One SSO string: pointer field plus capacity-or-inline-buffer.

    ``inline`` is True when the pointer field equals the address of
    the string's own +0x10-equivalent field, i.e. the string lives
    inline and frees nothing.
    """

    def __init__(self, pointer, capacity, inline):
        self.pointer = pointer
        self.capacity = capacity
        self.inline = inline

    def dispose(self, trace):
        if self.inline:
            return
        trace.append(("delete", self.pointer, self.capacity + 1))


class ChainNode:
    """One chain node: next pointer, dispose argument, two strings."""

    def __init__(self, next_node, field18, string40, string20):
        self.next_node = next_node
        self.field18 = field18
        self.string40 = string40
        self.string20 = string20


class FourthStruct:
    """The fourth argument: chain head at +0x10 plus reset fields."""

    def __init__(self, head):
        self.head = head
        self.field10 = None
        self.field18 = None
        self.field20 = None
        self.field28 = None


class LookupResult:
    """The 0x5eee790 return value: first byte plus +0x28 qword."""

    def __init__(self, first_byte, field28):
        self.first_byte = first_byte
        self.field28 = field28


class ProduceResult:
    """The vtable slot 0x30 return value: only +0x8d8 is read."""

    def __init__(self, field8d8):
        self.field8d8 = field8d8


def run(first_object, second_object, third_value, fourth_struct,
        lookup, dispose, produce, acquire, dispatch, release):
    """Run the modelled routine. Returns (return_value, trace).

    ``lookup`` takes the third value; ``dispose`` takes a node's
    +0x18 field; ``produce`` takes the second object; ``acquire``
    and ``release`` take the saved first object + 0x700 (the model
    forms that address from the integer ``first_object`` base);
    ``dispatch`` takes (produce +0x8d8, lookup result, third
    value, fourth struct). The trace records every modelled call
    in order. Null inputs raise ModelError.
    """
    if fourth_struct is None or second_object is None:
        raise ModelError("null struct or second object")
    trace = []
    lookup_result = lookup(third_value)
    trace.append(("lookup", third_value))

    node = fourth_struct.head
    while node is not None:
        next_node = node.next_node  # read before any deletion
        dispose(node.field18)
        trace.append(("dispose", node.field18))
        node.string40.dispose(trace)
        node.string20.dispose(trace)
        trace.append(("delete-node", node, 0x60))
        node = next_node

    fourth_struct.field10 = 0
    fourth_struct.field18 = INLINE
    fourth_struct.field20 = INLINE
    fourth_struct.field28 = 0
    trace.append(("reset", fourth_struct))

    produced = produce(second_object)
    trace.append(("produce", second_object))

    if lookup_result is None or lookup_result.field28 == 0:
        return 0, trace
    acquire_arg = first_object + 0x700
    if lookup_result.first_byte == 0:
        acquire(acquire_arg)
        trace.append(("acquire", acquire_arg))
        value = dispatch(produced.field8d8, lookup_result,
                         third_value, fourth_struct)
        trace.append(("dispatch", produced.field8d8, lookup_result,
                      third_value, fourth_struct))
        release(acquire_arg)
        trace.append(("release", acquire_arg))
        return value, trace
    value = dispatch(produced.field8d8, lookup_result,
                     third_value, fourth_struct)
    trace.append(("dispatch", produced.field8d8, lookup_result,
                  third_value, fourth_struct))
    return value, trace
