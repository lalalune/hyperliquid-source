"""Python model of node #115 routine 0x5d50170 (RE-001 object teardown).

The routine takes an object pointer and returns nothing. It frees the
object's heap members in a fixed order through a sized delete, and it
never frees the object itself. The model records each free as an
operation instead of freeing memory: ("delete", pointer, size) for a
sized-delete call, and ("call", value) for the internal callee
0x5d4cfd0, which is pinned by call shape only.

A string is (pointer, capacity, is_heap): heap form frees
(pointer, capacity + 1); short form frees nothing. A chain node
carries a pointer token, the callee argument (field_18), its two
strings (fields +0x40 and +0x20) and a successor; each node is freed
with size 0x60 after its strings.
"""


class String:
    """A string member: heap form carries (pointer, capacity)."""

    def __init__(self, pointer, capacity, is_heap):
        self.pointer = pointer
        self.capacity = capacity
        self.is_heap = is_heap


class Node:
    """A node of either chain: pointer token, field_18, strings, successor."""

    def __init__(self, pointer, field_18, str_40, str_20, nxt=None):
        self.pointer = pointer
        self.field_18 = field_18
        self.str_40 = str_40
        self.str_20 = str_20
        self.next = nxt


def _free_string(ops, string):
    if string.is_heap:
        ops.append(("delete", string.pointer, string.capacity + 1))


def _free_chain(ops, node):
    while node is not None:
        ops.append(("call", node.field_18))
        _free_string(ops, node.str_40)
        _free_string(ops, node.str_20)
        nxt = node.next
        ops.append(("delete", node.pointer, 0x60))
        node = nxt


def object_teardown(obj):
    """Run the phases of 0x5d50170 over obj; return the op list."""
    ops = []
    _free_chain(ops, obj["chain_288"])
    _free_chain(ops, obj["chain_258"])
    for key in ("str_228", "str_208", "str_1e8", "str_1c8", "str_1a8",
                "str_188", "str_168", "str_148", "str_128", "str_108",
                "str_e8", "str_c8"):
        _free_string(ops, obj[key])
    return ops


def empty_obj():
    """An object with every member short-form, null or empty."""
    short = lambda: String(None, 0, False)
    return {
        "chain_288": None,
        "chain_258": None,
        "str_228": short(),
        "str_208": short(),
        "str_1e8": short(),
        "str_1c8": short(),
        "str_1a8": short(),
        "str_188": short(),
        "str_168": short(),
        "str_148": short(),
        "str_128": short(),
        "str_108": short(),
        "str_e8": short(),
        "str_c8": short(),
    }
