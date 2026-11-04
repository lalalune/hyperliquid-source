"""Python model of the node #115 0x60-byte tree family.

Routines (node #115 work binary, digest
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):
  * string construct 0x5d4a6a0: build a string at dst from [begin, end).
  * tree teardown 0x5d4cfd0: free a tree of 0x60-byte nodes.
  * tree copy 0x5d4d050: deep-copy such a tree.

Node layout (0x60 bytes):
  +0x00 dword tag (copied verbatim by copy, never read by teardown)
  +0x04..+0x07 untouched by both routines
  +0x08 link value (copy stores the incoming link / previous copy)
  +0x0c..+0x0f untouched by both routines
  +0x10 next sibling (teardown walks it, copy chains through it)
  +0x18 child-list head (teardown recurses into it, copy recurses)
  +0x20 string A: ptr +0x20, size +0x28, capacity-or-inline +0x30
  +0x40 string B: ptr +0x40, size +0x48, capacity-or-inline +0x50

A string is inline when its stored pointer equals the address of
its own capacity/inline slot (+0x30 for A, +0x50 for B); the
binary compares exactly that. A heap string is freed with
operator delete(ptr, capacity + 1).

Model guards (not binary behaviour): the binary dereferences a
null copy source and recurses forever on a cyclic tree; the
model raises ValueError for a null source, a missing field, an
inverted string range, or a revisited node, so tests stay finite.
"""

SSO_LIMIT = 15
NODE_SIZE = 0x60


class Node:
    """One 0x60-byte tree node: tag, link, next, child, strings."""

    def __init__(self, name, tag=0, link=None, next_node=None,
                 child=None, s20=b"", s40=b""):
        self.name = name
        self.tag = tag & 0xFFFFFFFF
        self.link = link
        self.next = next_node
        self.child = child
        self.s20 = bytes(s20)
        self.s40 = bytes(s40)

    def __repr__(self):
        return "Node(%r)" % self.name


def construct_string(data):
    """Model of 0x5d4a6a0 for a byte string given as bytes.

    Returns (buffer, size, inline, capacity): buffer is the byte
    content plus the binary's trailing NUL is NOT part of the
    returned content; size is the length; inline is True when
    length <= 15 (the binary's short path, writing into the
    caller's preset inline buffer); capacity is None for inline
    strings and the requested length for heap strings. The
    binary's _M_create may reserve more than the requested
    length; the model normalizes heap capacity to the requested
    length, which does not change any observable byte, size, or
    NUL-terminator behaviour.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("string input must be bytes")
    data = bytes(data)
    size = len(data)
    if size <= SSO_LIMIT:
        return (data, size, True, None)
    return (data, size, False, size)


def _require(node, field):
    value = getattr(node, field, None)
    if node is None:
        raise ValueError("null node")
    return value


def teardown(head):
    """Model of 0x5d4cfd0. Returns the ordered freed-block list.

    Each entry is ("node", name, 0x60) or ("string", owner, which,
    capacity + 1) for a heap string. A null head frees nothing.
    Order per node: the whole child subtree first (child head's
    own chain in order), then string B, then string A, then the
    node itself, then the next sibling. Note the binary disposes
    string B (+0x40) before string A (+0x20) inside one node.
    Inline strings (length <= 15 in the model, matching the
    binary's pointer-equality rule) free nothing.
    """
    freed = []
    seen = set()

    def walk(node):
        if node is None:
            return
        if id(node) in seen:
            raise ValueError("cycle in tree: %r revisited" % node.name)
        seen.add(id(node))
        walk(node.child)
        for which, data in (("B", node.s40), ("A", node.s20)):
            _buffer, _size, inline, capacity = construct_string(data)
            if not inline:
                freed.append(("string", node.name, which, capacity + 1))
        freed.append(("node", node.name, NODE_SIZE))
        walk(node.next)

    walk(head)
    return freed


def copy_tree(head, link):
    """Model of 0x5d4d050. Returns (head copy, allocation order).

    The head copy's link is the incoming link value; every
    sibling copy's link is the previous copy. Strings are
    rebuilt by construct_string, so a copy's string is inline
    exactly when its length is <= 15, whatever the source form
    was. Allocation order: head, then the head's child subtree
    (depth-first, siblings in order), then each sibling in
    order, each with its own child subtree. Fresh copies leave
    +0x10/+0x18 zeroed until the loop links them, matching the
    binary's explicit zero stores.
    """
    if head is None:
        raise ValueError("null copy source")
    order = []
    seen = set()

    def build(source, link_value):
        if source is None:
            return None
        if id(source) in seen:
            raise ValueError("cycle in tree: %r revisited" % source.name)
        seen.add(id(source))
        result = Node(source.name + "'", tag=source.tag, link=link_value)
        order.append(result.name)
        result.s20 = construct_string(source.s20)[0]
        result.s40 = construct_string(source.s40)[0]
        if source.child is not None:
            result.child = build(source.child, result)
        previous = result
        sibling = source.next
        while sibling is not None:
            if id(sibling) in seen:
                raise ValueError(
                    "cycle in tree: %r revisited" % sibling.name)
            seen.add(id(sibling))
            made = Node(sibling.name + "'", tag=sibling.tag,
                        link=previous)
            order.append(made.name)
            made.s20 = construct_string(sibling.s20)[0]
            made.s40 = construct_string(sibling.s40)[0]
            previous.next = made
            if sibling.child is not None:
                made.child = build(sibling.child, made)
            previous = made
            sibling = sibling.next
        return result

    return build(head, link), order
