#!/usr/bin/env python3
"""Model for node #94's 0x68-byte tree-node teardown 0x514cd00 (RE-001).

The window function destroys a whole sibling list of 0x68-byte nodes.
Each node carries two strings and two links:

  +0x10  next sibling (the list link)
  +0x18  first child (the subtree link)
  +0x28  string 1: pointer +0x28, length +0x30, capacity/SSO +0x38
  +0x48  string 2: pointer +0x48, length +0x50, capacity/SSO +0x58

Fields +0x00 and +0x08 are never read by this function and are not
modelled. There is no stack canary and no endbr64 at the entry (the
function starts with a null test on rdi).

Traversal, transliterated from the bytes (the +0x18 descent is unrolled
six links deep in the code and recurses through the self-call at
0x514cd9c for deeper levels, but the observable order is the plain
recursion below):

  destroy_list(head):
      while head is not None:
          destroy_list(head.child)   # whole +0x18 child list first
          dispose(head)              # then the node itself
          head = head.sibling        # then the +0x10 sibling

dispose(node), in the order the bytes dispose them (string 2 first,
then string 1, then the node itself):

  * string 2 (+0x48): _M_dispose -- a heap buffer is sized-deleted
    with size capacity + 1, an SSO buffer (pointer == node + 0x58)
    deletes nothing.
  * string 1 (+0x28): the same rule, inlined in most blocks -- a heap
    buffer is sized-deleted with size capacity + 1, an SSO buffer
    (pointer == node + 0x38) deletes nothing.
  * the node itself: sized-deleted with size 0x68.

A null head returns immediately (the second ret at 0x514d005) and
frees nothing.

Consumers (cited, not re-modelled as separate semantics -- both reduce
to destroy_list):

  * 0x514d010 (wrapper): for each node in the list at [container+0x10],
    it calls 0x514cd00 on that node's +0x18 child list, then disposes
    the node itself with the same string-then-node order and advances
    via +0x10. Observable effect: destroy_list([container+0x10]).
  * 0x5150b34 (exception cleanup in 0x5150870..0x5150baf): after
    __cxa_end_catch it calls 0x514cd00 on [r14+0x10], i.e. it destroys
    that list before the canary check and _Unwind_Resume.

A node is modelled as a dict with keys ``child`` (a node or None),
``sibling`` (a node or None), ``str1_heap`` / ``str1_capacity`` and
``str2_heap`` / ``str2_capacity``. Disposal events are recorded as
("string2", size-or-None), ("string1", size-or-None) and ("node", 0x68)
tuples, in order. Stdlib only.
"""

NODE_SIZE = 0x68


def dispose_string(heap, capacity):
    """Return the sized-delete size for one string, or None for SSO."""
    if not heap:
        return None
    return capacity + 1


def dispose_node(node, events):
    """Dispose one node's two strings and then the node itself."""
    events.append(("string2", dispose_string(node["str2_heap"],
                                             node["str2_capacity"])))
    events.append(("string1", dispose_string(node["str1_heap"],
                                             node["str1_capacity"])))
    events.append(("node", NODE_SIZE))


def destroy_list(head, events):
    """Destroy a sibling list: children first, node second, sibling next."""
    node = head
    while node is not None:
        destroy_list(node["child"], events)
        dispose_node(node, events)
        node = node["sibling"]


def destroy_tree(head):
    """Destroy the list rooted at ``head``; return the event list."""
    events = []
    destroy_list(head, events)
    return events


def destroy_container_list(head):
    """Model the 0x514d010 wrapper: destroy_list of [container+0x10].

    ``head`` is the node at [container+0x10]; the wrapper calls the
    window function on each node's child list and disposes the node
    itself, which is exactly destroy_list(head).
    """
    return destroy_tree(head)


def make_node(child=None, sibling=None, str1_heap=False, str1_capacity=0,
              str2_heap=False, str2_capacity=0):
    """Build a node dict for the model."""
    return {
        "child": child,
        "sibling": sibling,
        "str1_heap": str1_heap,
        "str1_capacity": str1_capacity,
        "str2_heap": str2_heap,
        "str2_capacity": str2_capacity,
    }
