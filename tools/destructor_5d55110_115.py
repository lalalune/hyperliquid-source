"""Python model of the node #115 object destructor at 0x5d55110.

The routine takes one object pointer in rdi and returns void. It
writes nothing itself and never deletes the object itself.

Order, stated literally:
1. The tree list at obj+0x2f0 is handed whole to the 0x5d4cfd0
   teardown (site 0x5d55122; teardown semantics pinned by open
   PR #2409, referenced here, not re-claimed).
2. The tree list at obj+0x2c0 is walked inline with exactly the
   same per-node sequence: the child list at node+0x18 is handed
   to the teardown (site 0x5d55137), string B is disposed, string
   A is disposed, the node is deleted with size 0x60, and the
   walk advances to the +0x10 successor loaded before the node's
   own deletes. A null head destroys nothing.
3. Fifteen string fields, in descending offset order: +0x290,
   +0x270, +0x250, +0x230, +0x210, +0x1f0, +0x1d0, +0x1b0,
   +0x190, +0x170, +0x150, +0x130, +0x40, +0x20, +0x00. The last
   field reaches the operator delete PLT by tail jump (site
   0x5d55380) with identical effect.

A string field is a std::string-shaped triple: pointer at +X,
size at +X+0x08, capacity-or-inline at +X+0x10. It is inline
exactly when its stored pointer equals the address of its own
capacity/inline slot; a heap string is freed as
delete(ptr, capacity + 1). The binary never reads a string
field's size for the delete.

The model raises ValueError on a missing field, a cyclic tree,
or a dangling (unknown) node reference; the binary would loop
or dereference on such inputs instead.
"""

STRING_OFFSETS = (0x290, 0x270, 0x250, 0x230, 0x210, 0x1F0, 0x1D0,
                  0x1B0, 0x190, 0x170, 0x150, 0x130, 0x40, 0x20, 0x00)
NODE_SIZE = 0x60


class StringField:
    """A std::string-shaped field: 'inline' or 'heap' with capacity."""

    def __init__(self, kind, capacity=0):
        if kind not in ("inline", "heap"):
            raise ValueError("bad string kind %r" % (kind,))
        self.kind = kind
        self.capacity = capacity

    def delete_size(self):
        if self.kind != "heap":
            return None
        return self.capacity + 1


class Node:
    """One 0x60-byte tree node. `label` only identifies deletes."""

    def __init__(self, label, child=None, nxt=None, str_a=None, str_b=None):
        self.label = label
        self.child = child
        self.next = nxt
        self.str_a = str_a if str_a is not None else StringField("inline")
        self.str_b = str_b if str_b is not None else StringField("inline")


def _destroy_list(head, deletes, seen):
    node = head
    while node is not None:
        if not isinstance(node, Node):
            raise ValueError("dangling node reference")
        if id(node) in seen:
            raise ValueError("cyclic tree at node %r" % (node.label,))
        seen.add(id(node))
        _destroy_list(node.child, deletes, seen)
        size = node.str_b.delete_size()
        if size is not None:
            deletes.append(("delete-string-B", node.label, size))
        size = node.str_a.delete_size()
        if size is not None:
            deletes.append(("delete-string-A", node.label, size))
        deletes.append(("delete-node", node.label, NODE_SIZE))
        node = node.next


def destroy_object(obj):
    """Return the ordered delete list for one destructor run.

    obj is a dict with "teardown_list" (head Node or None),
    "inline_list" (head Node or None) and "strings" (dict
    offset -> StringField for all fifteen offsets). The input
    is not mutated.
    """
    if not isinstance(obj, dict) or "teardown_list" not in obj \
            or "inline_list" not in obj or "strings" not in obj:
        raise ValueError("object must carry 'teardown_list', "
                         "'inline_list' and 'strings'")
    for offset in STRING_OFFSETS:
        if offset not in obj["strings"]:
            raise ValueError("missing string field %#x" % offset)
        if not isinstance(obj["strings"][offset], StringField):
            raise ValueError("bad string field %#x" % offset)
    deletes = []
    seen = set()
    _destroy_list(obj["teardown_list"], deletes, seen)
    _destroy_list(obj["inline_list"], deletes, seen)
    for offset in STRING_OFFSETS:
        size = obj["strings"][offset].delete_size()
        if size is not None:
            deletes.append(("delete-string", "%#x" % offset, size))
    return deletes
