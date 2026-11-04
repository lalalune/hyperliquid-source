"""Python model of the node #115 object destructor at 0x5d5e5d0.

The routine takes one object pointer in rdi and returns void. It
destroys, in order: three string fields (+0x3b8, +0x398, +0x368),
two tree lists through the 0x5d4cfd0 teardown (+0x318, then
+0x2e8), then fifteen string fields in descending offset order
(+0x2b8 down to +0x00). It writes nothing itself and never
deletes the object itself; every effect is an operator delete
or a call to the teardown (pinned by open PR #2409, referenced
here, not re-claimed).

Node layout (0x60 bytes, per #2409): tag dword at +0x00 (never
read by the teardown), link at +0x08 (never read by the
teardown), next sibling at +0x10, child-list head at +0x18,
string A at +0x20 (pointer +0x20, size +0x28,
capacity-or-inline +0x30), string B at +0x40 (pointer +0x40,
size +0x48, capacity-or-inline +0x50). A string is inline
exactly when its stored pointer equals the address of its own
capacity/inline slot; a heap string is freed as
delete(ptr, capacity + 1).

Teardown destroy order per list (per #2409): walk the +0x10
chain in order; per node, first destroy the whole list at its
+0x18 child head by the same rule, then dispose string B, then
string A, then delete the node itself with size 0x60. The
successor is loaded before the node's own deletes, so the chain
survives the free. A null list head destroys nothing.

The model raises ValueError on a missing field, a cyclic tree,
or a dangling (unknown) node reference, matching the binary's
unchecked dereferences only in the sense that such inputs have
no defined destroy order; the binary itself would dereference
or loop on them.
"""

STRINGS_BEFORE_TREES = (0x3B8, 0x398, 0x368)
TREE_OFFSETS = (0x318, 0x2E8)
STRINGS_AFTER_TREES = (0x2B8, 0x298, 0x278, 0x258, 0x238, 0x218,
                       0x1F8, 0x1D8, 0x1B8, 0x198, 0x178, 0x158,
                       0x40, 0x20, 0x00)
STRING_OFFSETS = STRINGS_BEFORE_TREES + STRINGS_AFTER_TREES
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

    obj is a dict with keys "trees" (dict offset -> head Node or
    None, required for 0x318 and 0x2e8) and "strings" (dict offset
    -> StringField, required for all eighteen offsets). The input
    is not mutated.
    """
    if not isinstance(obj, dict) or "trees" not in obj or "strings" not in obj:
        raise ValueError("object must carry 'trees' and 'strings'")
    for offset in TREE_OFFSETS:
        if offset not in obj["trees"]:
            raise ValueError("missing tree field %#x" % offset)
    for offset in STRING_OFFSETS:
        if offset not in obj["strings"]:
            raise ValueError("missing string field %#x" % offset)
        if not isinstance(obj["strings"][offset], StringField):
            raise ValueError("bad string field %#x" % offset)
    deletes = []
    seen = set()
    for offset in STRINGS_BEFORE_TREES:
        size = obj["strings"][offset].delete_size()
        if size is not None:
            deletes.append(("delete-string", "%#x" % offset, size))
    for offset in TREE_OFFSETS:
        _destroy_list(obj["trees"][offset], deletes, seen)
    for offset in STRINGS_AFTER_TREES:
        size = obj["strings"][offset].delete_size()
        if size is not None:
            deletes.append(("delete-string", "%#x" % offset, size))
    return deletes
