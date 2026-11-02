"""Model of node #94 0x5165b80: callback flush-and-teardown.

The window destroys the 0xe8-byte record pointed to by a wrapper's +0x38
member (a null member is a no-op). When the dirty flag at record +0xb8 is
set, it first flushes: it sorts the callback-pair array at +0xc0/+0xc8
ascending by (arg, fn) with std::sort (introsort 0x5164da0, insertion
sort 0x5164af0, inline unguarded insert), removes adjacent duplicate
pairs keeping the first, records the deduped end at +0xc8, invokes each
pair's fn(arg) in sorted order, and drains the callback list at +0x98
before the common teardown. When the flag is clear, the array callbacks
are skipped and the array storage is freed before the list drain.

Callback functions are identified by integer keys (the binary compares
raw pointer values); the caller supplies a registry mapping each key to
a callable. The model records an ordered event log instead of freeing
real memory, so tests can pin the exact observable order.

Layout of the 0xe8-byte record (offsets pinned by the window; fields the
window never reads are marked unknown and are not modeled):
  +0x00/+0x10  vector A (begin/end), freed with size end-begin
  +0x18/+0x28  vector B, freed with size end-begin
  +0x30/+0x40  vector C, freed with size end-begin
  +0x48/+0x50/+0x58  unknown, never read here
  +0x60        head pointer of the 0x28-node tree list
  +0x68/+0x70/+0x78  unknown, never read here
  +0x80        sentinel of the 0x30-node string list
  +0x98        inline callback-list head: fn +0x98, arg0 +0xa0,
               arg1 +0xa8, next +0xb0 (tail nodes 0x20 bytes:
               fn +0, arg0 +8, arg1 +0x10, next +0x18)
  +0xb8        dirty flag byte
  +0xc0/+0xc8/+0xd0  callback-pair array (begin/end/capacity end);
               pairs are 16 bytes: arg +0, fn +8

Common teardown order (both paths): free the array storage, drain the
callback list (0x541cab0), drain the string list, drain the tree list,
free vectors C, B, A in that order, sized-delete the record (0xe8).
The wrapper itself is never freed here.

Assumptions, stated explicitly: states are consistent (a non-null array
begin has end >= begin; capacity covers the pairs; a callback list with
a null head fn and a non-empty tail is the one inconsistent shape the
binary handles by leaking the tail, modeled faithfully below).
"""

INNER_SIZE = 0xE8
STRING_NODE_SIZE = 0x30
TREE_NODE_SIZE = 0x28
LIST_NODE_SIZE = 0x20
PAIR_SIZE = 0x10


class TreeNode:
    """A 0x28-byte tree node: child at +0x18, successor at +0x10.

    Fields at +0x00/+0x08 are never read by the teardown and are not
    modeled.
    """

    def __init__(self, child=None, successor=None):
        self.child = child
        self.successor = successor


class StringNode:
    """A 0x30-node string-list node.

    The string sits at node +0x10 (pointer +0x10, size +0x18,
    capacity-or-inline-buffer +0x20). ``inline`` means the pointer
    equals the address of the +0x20 field, so no heap buffer is freed.
    The node +0x08 field is never read here and is not modeled.
    """

    def __init__(self, inline, capacity=0):
        self.inline = inline
        self.capacity = capacity


class CallbackNode:
    """One callback-list tail node: fn, arg0, arg1, next."""

    def __init__(self, fn, arg0, arg1, nxt=None):
        self.fn = fn
        self.arg0 = arg0
        self.arg1 = arg1
        self.next = nxt


class Record:
    """The 0xe8-byte record at wrapper +0x38."""

    def __init__(self, dirty=False, array=None, array_capacity_pairs=0,
                 callback_fn=None, callback_arg0=0, callback_arg1=0,
                 callback_tail=None, string_nodes=None, tree_nodes=None,
                 vec_a=None, vec_b=None, vec_c=None):
        # array: None (begin null) or a list of (arg, fn_key) pairs.
        self.dirty = dirty
        self.array = array
        self.array_capacity_pairs = array_capacity_pairs
        self.array_end_pairs = len(array) if array is not None else 0
        self.callback_fn = callback_fn
        self.callback_arg0 = callback_arg0
        self.callback_arg1 = callback_arg1
        self.callback_tail = list(callback_tail or [])
        self.string_nodes = list(string_nodes or [])
        # tree_nodes: list of (tree_root_or_None) per 0x28 list node.
        self.tree_nodes = list(tree_nodes or [])
        # Vectors: None (begin null) or a byte size (end - begin).
        self.vec_a = vec_a
        self.vec_b = vec_b
        self.vec_c = vec_c
        self.deleted = False


def drain_callback_list(record, events, registry):
    """Model of 0x541cab0 on the record's +0x98 list head.

    If the head fn is null, this returns immediately and the tail nodes
    are left untouched (the binary's early return). Otherwise the head
    fn(arg0, arg1) runs first, then each tail node in +0x18 order is
    invoked and freed (0x20). Nothing is zeroed here.
    """
    if record.callback_fn is None:
        return
    events.append(("list_callback", record.callback_arg0,
                   record.callback_arg1, record.callback_fn))
    registry[record.callback_fn](record.callback_arg0, record.callback_arg1)
    for node in record.callback_tail:
        events.append(("list_callback", node.arg0, node.arg1, node.fn))
        registry[node.fn](node.arg0, node.arg1)
        events.append(("list_node_freed", LIST_NODE_SIZE))
    record.callback_tail = []


def teardown_tree(node, events):
    """Model of 0x5165380: recursive teardown of a 0x28-node tree.

    teardown(n): teardown(n.child at +0x18); delete n (0x28); then
    teardown(n.successor at +0x10). A null node is a no-op. The free
    order is therefore children before parents, successors in order.
    """
    if node is None:
        return
    teardown_tree(node.child, events)
    nxt = node.successor
    events.append(("tree_node_freed", TREE_NODE_SIZE))
    teardown_tree(nxt, events)


def flush_and_destroy(record, registry):
    """Model of 0x5165b80. Returns the ordered event log.

    ``registry`` maps fn keys to callables: array callbacks take one
    argument (the pair's arg), list callbacks take two (arg0, arg1).
    """
    events = []
    if record is None:
        return events

    if record.dirty:
        events.append(("flag_cleared",))
        record.dirty = False
        if record.array:
            pairs = sorted(record.array, key=lambda p: (p[0], p[1]))
            deduped = []
            for pair in pairs:
                if not deduped or deduped[-1] != pair:
                    deduped.append(pair)
            record.array = deduped
            record.array_end_pairs = len(deduped)
            for arg, fn in deduped:
                events.append(("array_callback", arg, fn))
                registry[fn](arg)
        # Inline list drain, then the head fn and tail head are zeroed
        # even when the head fn was null (in which case the tail nodes
        # are orphaned, not freed).
        if record.callback_fn is not None:
            drain_callback_list(record, events, registry)
        else:
            record.callback_tail = []
        record.callback_fn = None

    # Common teardown.
    if record.array is not None:
        events.append(("array_freed", record.array_capacity_pairs * PAIR_SIZE))
    # The 0x541cab0 call: a no-op after a dirty pre-drain (head fn was
    # zeroed), the real drain on the clean path.
    drain_callback_list(record, events, registry)
    for node in record.string_nodes:
        if not node.inline:
            events.append(("string_heap_freed", node.capacity + 1))
        events.append(("string_node_freed", STRING_NODE_SIZE))
    record.string_nodes = []
    for root in record.tree_nodes:
        teardown_tree(root, events)
        events.append(("tree_list_node_freed", TREE_NODE_SIZE))
    record.tree_nodes = []
    for name, size in (("vec_c", record.vec_c), ("vec_b", record.vec_b),
                       ("vec_a", record.vec_a)):
        if size is not None:
            events.append(("vector_freed", name, size))
    events.append(("inner_deleted", INNER_SIZE))
    record.deleted = True
    return events
