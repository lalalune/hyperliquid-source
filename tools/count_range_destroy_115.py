"""Python model of the node #115 two-collection element destroy at 0x5d5e860.

The routine takes one object pointer in rdi and returns void. It
destroys two collections of 0x3f0-byte elements that live on the
same object, in two phases, and writes nothing else:

Phase A -- counted drain, in reverse. The count is the qword at
obj+0x00 and the base is the qword at obj+0x1f88. While the count
is nonzero, the routine decrements the stored count first, then
destroys the element at base + (count - 1) * 0x3f0. The stride
computation in the bytes is (count - 1) * 64 - (count - 1), then
times 16, which is (count - 1) * 0x3f0. So element count-1 is
destroyed first and element 0 last, and the stored count ends at
0. The counted base buffer itself is never freed.

Phase B -- range destroy, forward. The begin pointer is the qword
at obj+0x1f90 and the end pointer the qword at obj+0x1f98, both
read once at phase entry. If begin == end nothing is destroyed
and the routine returns. Otherwise each element from begin,
advancing by 0x3f0, is destroyed until the cursor equals end,
and then begin is stored into obj+0x1f98, so the range is left
empty (end = begin). The range storage itself is never freed,
and the object itself is never deleted.

Per element, the field sequence is the one open PR #2421 pins for
a single object (same offsets, same order), reproduced here
because it is literally this routine's loop body in both phases:
three string fields (+0x3b8, +0x398, +0x368), two tree lists
(+0x318, then +0x2e8), then fifteen string fields in descending
offset order (+0x2b8 down to +0x00).

Per tree list the routine walks the +0x10 chain inline: per node,
the child list at node+0x18 is handed to the 0x5d4cfd0 teardown
(pinned by open PR #2409, referenced here, not re-claimed), then
string B is disposed, string A is disposed, the node is deleted
with size 0x60, and the walk advances to the +0x10 successor
loaded before the node's own deletes. A null list head destroys
nothing.

A string field is a std::string-shaped triple: pointer at +X,
size at +X+0x08, capacity-or-inline at +X+0x10. It is inline
exactly when its stored pointer equals the address of its own
capacity/inline slot; a heap string is freed as
delete(ptr, capacity + 1). For the element's +0x00 field the
inline case rejoins the loop-head count test through a separate
tail block (0x5d5ef50) while the heap case deletes then rejoins
it directly; both paths are the same loop test.

The model raises ValueError on a missing field, a cyclic tree,
a dangling (unknown) node reference, a counted collection whose
element list length differs from its count, a nonzero count with
no counted base, or a nonzero range with no range begin; the
binary would dereference or loop on such inputs instead.
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


def destroy_counted_and_range(obj):
    """Return the ordered delete list for one 0x5d5e860 run.

    obj is a dict with "count" (int), "counted_base_present"
    (bool), "counted_elements" (list, index order 0..count-1),
    "range_begin_present" (bool) and "range_elements" (list, in
    forward order). The input is not mutated. The returned list
    ends with ("reset-range-end", "begin") exactly when the range
    was non-empty, matching the store at 0x5d5ef39; no storage
    delete and no object delete ever appear.
    """
    if not isinstance(obj, dict) or "count" not in obj \
            or "counted_base_present" not in obj \
            or "counted_elements" not in obj \
            or "range_begin_present" not in obj \
            or "range_elements" not in obj:
        raise ValueError("obj must carry 'count', 'counted_base_present', "
                         "'counted_elements', 'range_begin_present' and "
                         "'range_elements'")
    count = obj["count"]
    counted = obj["counted_elements"]
    ranged = obj["range_elements"]
    if not isinstance(count, int) or count < 0:
        raise ValueError("bad count %r" % (count,))
    if not isinstance(counted, list) or len(counted) != count:
        raise ValueError("counted element list length must equal count")
    if not isinstance(ranged, list):
        raise ValueError("range elements must be a list")
    if count > 0 and not obj["counted_base_present"]:
        raise ValueError("nonzero count with no counted base")
    if ranged and not obj["range_begin_present"]:
        raise ValueError("nonzero range with no range begin")
    deletes = []
    seen = set()
    for index in range(count - 1, -1, -1):
        _destroy_element(counted[index], deletes, seen)
    for element in ranged:
        _destroy_element(element, deletes, seen)
    if ranged:
        deletes.append(("reset-range-end", "begin"))
    return deletes
