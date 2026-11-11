"""Python model of node #115 routine 0x5d516f0 (RE-001 object teardown).

The routine takes an object pointer and returns nothing. It frees the
object's heap members in a fixed order through a sized delete, and it
never frees the object itself. The model records each free as an
operation instead of freeing memory: ("delete", pointer, size) for a
sized-delete call, and ("teardown_call", value) for the internal
callee 0x5d4c8d0, which is pinned by call shape only.

A string is (pointer, capacity, is_heap): heap form frees
(pointer, capacity + 1); short form frees nothing. A buffer is
(begin, end) with begin None meaning null: null begin frees nothing,
otherwise it frees (begin, end - begin). Loop elements and records
are plain dicts keyed by member offset; the linked list is a chain
of Node objects carrying a pointer token, a teardown argument
(field_18) and a successor.
"""


class String:
    """A string member: heap form carries (pointer, capacity)."""

    def __init__(self, pointer, capacity, is_heap):
        self.pointer = pointer
        self.capacity = capacity
        self.is_heap = is_heap


class Node:
    """A node of the +0xa8 list: pointer token, field_18, successor."""

    def __init__(self, pointer, field_18, nxt=None):
        self.pointer = pointer
        self.field_18 = field_18
        self.next = nxt


def _free_string(ops, string):
    if string.is_heap:
        ops.append(("delete", string.pointer, string.capacity + 1))


def _free_buffer(ops, buf):
    begin, end = buf
    if begin is not None:
        ops.append(("delete", begin, end - begin))


def object_teardown(obj):
    """Run the ten phases of 0x5d516f0 over obj; return the op list."""
    ops = []
    _free_string(ops, obj["str_160"])
    _free_string(ops, obj["str_138"])
    _free_buffer(ops, obj["buf_110"])
    _free_buffer(ops, obj["buf_f8"])
    for elem in obj["elems_e0"]:
        _free_string(ops, elem["str_38"])
        _free_string(ops, elem["str_18"])
    _free_buffer(ops, obj["buf_e0"])
    for rec in obj["records_c8"]:
        _free_string(ops, rec["str_100"])
        _free_string(ops, rec["str_e0"])
        _free_string(ops, rec["str_50"])
        _free_string(ops, rec["str_30"])
    _free_buffer(ops, obj["buf_c8"])
    node = obj["list_a8"]
    while node is not None:
        ops.append(("teardown_call", node.field_18))
        nxt = node.next
        ops.append(("delete", node.pointer, 0x30))
        node = nxt
    for elem in obj["elems_80"]:
        _free_string(ops, elem["str_08"])
    _free_buffer(ops, obj["buf_80"])
    _free_string(ops, obj["str_28"])
    _free_string(ops, obj["str_08"])
    return ops


def empty_obj():
    """An object with every member short-form, null or empty."""
    short = lambda: String(None, 0, False)
    return {
        "str_160": short(),
        "str_138": short(),
        "buf_110": (None, 0),
        "buf_f8": (None, 0),
        "elems_e0": [],
        "buf_e0": (None, 0),
        "records_c8": [],
        "buf_c8": (None, 0),
        "list_a8": None,
        "elems_80": [],
        "buf_80": (None, 0),
        "str_28": short(),
        "str_08": short(),
    }
