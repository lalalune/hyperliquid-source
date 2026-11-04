"""Python model of the node #115 slot replace routine (0x5d4cc80).

The routine replaces the node held in one slot. It takes an
owner in rdi (returned unchanged), a key object in rsi, two
values in rdx and rcx, and a slot pointer in r8 (the address
of a pointer variable, not the node itself). The key object's
flag byte at +0x4c9 selects which of two node shapes is built
and which insert callee runs; the slot's old node, when
present, is released through its vtable slot +0x8, and the new
node is then announced to the owner through its vtable slot
+0x38. The insert callees, the release, and the notify call
are opaque here: only their argument lists and order are
pinned. The stack canary check before the return is not
modelled: it cannot change the observable semantics on the
non-fault path.
"""

NODE_SIZE = 0x70
FLAG_OFFSET = 0x4C9
VTABLE_FLAG_ZERO = 0x64D2C38
VTABLE_FLAG_NONZERO = 0x64D2CA0
INSERT_CALLEE_FLAG_ZERO = 0x606C680
INSERT_CALLEE_FLAG_NONZERO = 0x606EF50
REPORT_CALLEE = 0x61CF670
OPERATOR_NEW = 0x63F0DD0
# The null-slot report block, as four qwords on the stack:
# message pointer, message length, path pointer, zero.
REPORT_BLOCK = (0x960EE0, 0x20, 0x4376FD, 0)
REPORT_MESSAGE = b"stats_iterator not preallocated."
REPORT_PATH = b"/home/ubuntu/hl/code_Mainnet/z_vendor/futures-channel/src/oneshot.rs"
# Register arguments of the report call besides the block:
# esi = 4, edx = 0, rcx = &block, r8 = &block + 0x10, r9 = 0.
REPORT_REGS = {"esi": 4, "edx": 0, "r9": 0}

FIELD_ADDR = "field_addr"


class Key:
    """A key object carrying only its +0x4c9 flag byte."""

    def __init__(self, flag_byte):
        self.flag_byte = flag_byte


class Node:
    """A freshly allocated node: its fields as written by the routine."""

    def __init__(self):
        self.fields = {}


class RecordingHooks:
    """Stand-in callees that record every call in order."""

    def __init__(self):
        self.events = []

    def alloc(self, size):
        self.events.append(("alloc", size))
        return Node()

    def insert_a(self, node, a, b):
        self.events.append(("insert_a", node, a, b))

    def insert_b(self, node, a, b):
        self.events.append(("insert_b", node, a, b))

    def release(self, node):
        self.events.append(("release", node))

    def notify(self, owner, node):
        self.events.append(("notify", owner, node))

    def report(self, block, regs):
        self.events.append(("report", block, regs))


def slot_replace(owner, key, a, b, slot, hooks):
    """Replace the node in slot, following 0x5d4cc80.

    slot is None (a null slot pointer) or a one-element list
    holding the current node or None. Returns the owner.
    """
    if slot is None:
        # The binary builds the report block and calls the
        # report callee, then returns the owner unchanged:
        # no allocation, no slot write, no release, no notify.
        hooks.report(REPORT_BLOCK, REPORT_REGS)
        return owner
    if key is None:
        # The binary reads the flag byte unconditionally once
        # the slot pointer is non-null; there is no null check.
        raise ValueError("key object must be non-null: the routine "
                         "reads its +0x4c9 flag byte unconditionally")
    node = hooks.alloc(NODE_SIZE)
    flag_zero = (key.flag_byte == 0)
    node.fields[0x00] = VTABLE_FLAG_NONZERO
    if flag_zero:
        node.fields[0x00] = VTABLE_FLAG_ZERO
    else:
        # Only the flag-nonzero path zeroes +0x08; the
        # flag-zero path leaves it untouched by this routine.
        node.fields[0x08] = 0
    node.fields[0x10] = a
    node.fields[0x18] = b
    node.fields[0x28] = 0
    node.fields[0x30] = 0
    node.fields[0x38] = (FIELD_ADDR, 0x28)
    node.fields[0x40] = (FIELD_ADDR, 0x28)
    node.fields[0x48] = 0
    node.fields[0x50] = 0
    node.fields[0x54] = 0
    node.fields[0x58] = 0
    node.fields[0x60] = 1
    node.fields[0x68] = key
    if flag_zero:
        hooks.insert_a(node, a, b)
    else:
        hooks.insert_b(node, a, b)
    old = slot[0]
    slot[0] = node
    if old is not None:
        hooks.release(old)
    hooks.notify(owner, node)
    return owner
