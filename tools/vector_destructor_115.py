"""Python model of the node #115 vector destructor at 0x5d5e220.

The routine takes one vector pointer in rdi and returns void. The
vector triple is begin at obj+0x00, end at obj+0x08, capacity-end
at obj+0x10. It destroys every element in [begin, end) in order,
advancing by 0x3f0 per element, then frees the storage itself. It
writes nothing itself and never deletes the vector object itself.

Per element, the field sequence is the one open PR #2421 pins for
a single object (same offsets, same order), reproduced here
because it is literally this routine's loop body: three string
fields (+0x3b8, +0x398, +0x368), two tree lists (+0x318, then
+0x2e8), then fifteen string fields in descending offset order
(+0x2b8 down to +0x00).

Per tree list the routine walks the +0x10 chain inline: per node,
the child list at node+0x18 is handed to the 0x5d4cfd0 teardown
(pinned by open PR #2409, referenced here, not re-claimed), then
string B is disposed, string A is disposed, the node is deleted
with size 0x60, and the walk advances to the +0x10 successor
loaded before the node's own deletes. A null list head destroys
nothing. The teardown's own destroy order is the same rule
applied to the child list, so one recursive destroy function
models both levels.

A string field is a std::string-shaped triple: pointer at +X,
size at +X+0x08, capacity-or-inline at +X+0x10. It is inline
exactly when its stored pointer equals the address of its own
capacity/inline slot; a heap string is freed as
delete(ptr, capacity + 1).

Tail: if begin is null the routine returns with no further
effect. Otherwise it tail-jumps to operator delete with
(begin, capacity_end - begin) — the full allocation byte count,
not the element count times 0x3f0.

The model raises ValueError on a missing field, a cyclic tree,
or a dangling (unknown) node reference, and on a vector whose
begin is null while elements are present; the binary would
dereference or loop on such inputs instead.
"""

STRINGS_BEFORE_TREES = (0x3B8, 0x398, 0x368)
TREE_OFFSETS = (0x318, 0x2E8)
STRINGS_AFTER_TREES = (0x2B8, 0x298, 0x278, 0x258, 0x238, 0x218,
                       0x1F8, 0x1D8, 0x1B8, 0x198, 0x178, 0x158,
                       0x40, 0x20, 0x00)
STRING_OFFSETS = STRINGS_BEFORE_TREES + STRINGS_AFTER_TREES
ELEMENT_STRIDE = 0x3F0
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


def _destroy_element(element, deletes, seen):
    if not isinstance(element, dict) or "trees" not in element \
            or "strings" not in element:
        raise ValueError("element must carry 'trees' and 'strings'")
    for offset in TREE_OFFSETS:
        if offset not in element["trees"]:
            raise ValueError("missing tree field %#x" % offset)
    for offset in STRING_OFFSETS:
        if offset not in element["strings"]:
            raise ValueError("missing string field %#x" % offset)
        if not isinstance(element["strings"][offset], StringField):
            raise ValueError("bad string field %#x" % offset)
    for offset in STRINGS_BEFORE_TREES:
        size = element["strings"][offset].delete_size()
        if size is not None:
            deletes.append(("delete-string", "%#x" % offset, size))
    for offset in TREE_OFFSETS:
        _destroy_list(element["trees"][offset], deletes, seen)
    for offset in STRINGS_AFTER_TREES:
        size = element["strings"][offset].delete_size()
        if size is not None:
            deletes.append(("delete-string", "%#x" % offset, size))


def destroy_vector(vector):
    """Return the ordered delete list for one vector destructor run.

    vector is a dict with "begin_present" (bool), "elements" (list
    of element dicts, in order) and "capacity_bytes" (int, the
    capacity_end - begin byte count; required when begin is
    present, ignored when it is not). The input is not mutated.
    """
    if not isinstance(vector, dict) or "begin_present" not in vector \
            or "elements" not in vector or "capacity_bytes" not in vector:
        raise ValueError("vector must carry 'begin_present', "
                         "'elements' and 'capacity_bytes'")
    elements = vector["elements"]
    if not isinstance(elements, list):
        raise ValueError("elements must be a list")
    if not vector["begin_present"]:
        if elements:
            raise ValueError("null begin with a nonzero range")
        return []
    if not isinstance(vector["capacity_bytes"], int) \
            or vector["capacity_bytes"] < len(elements) * ELEMENT_STRIDE:
        raise ValueError("bad capacity_bytes %r"
                         % (vector["capacity_bytes"],))
    deletes = []
    seen = set()
    for element in elements:
        _destroy_element(element, deletes, seen)
    deletes.append(("delete-storage", vector["capacity_bytes"]))
    return deletes
