"""Python model of node #115's visited-element teardown routine at 0x5d516f0.

RE-001 work item: research/work-items/RE-001-element-teardown-115/.
The routine takes one element pointer in rdi and returns void. It
destroys the element's fields in descending offset order: two
strings, two plain vectors, three element vectors, one linked
list, then two more strings. It is the callee the 0x5f6eac0
element-visit-and-reset routine calls once per visited element
(open PR #2383); that visit routine is its documented consumer.

A string field is modelled as ``{"ptr", "cap", "cap_addr"}``:
``ptr`` is the data pointer, ``cap`` the qword at the field's
+0x10 slot, ``cap_addr`` the address of that slot. When
``ptr == cap_addr`` the string is in its inline (small-string)
form and no delete runs; otherwise operator delete runs with
``(ptr, cap + 1)``. The +1 is the capacity-plus-terminator size
the binary passes, not a length.

A plain vector is ``{"begin", "cap"}``: its end field is never
read by this routine, so it is not part of the model. When
``begin`` is zero no delete runs; otherwise operator delete runs
with ``(begin, cap - begin)`` modulo 2**64.

A loop vector is ``{"begin", "end", "cap", "elements"}``: the
routine walks ``begin`` to ``end`` in fixed steps, destroying
each element's strings, then deletes the array with
``(begin, cap - begin)`` when ``begin`` is nonzero. An
end-before-begin range, a range whose span is not a multiple
of the step, or an element count that does not match the span
raises instead of being silently modelled.

The linked list is ``{"head", "nodes"}``: ``nodes`` maps a node
address to ``{"next", "field18"}``. For each node in chain
order the routine calls the 0x5d4c8d0 callee with the node's
+0x18 qword (that callee's own semantics are NOT modelled;
its return is discarded), then deletes the node with
``(node, 0x30)`` and follows ``next``. A missing node, a
repeated node, or a chain that does not end at zero raises.

The full object dict must carry every field named in
``element_teardown``; a missing field raises ValueError. The
routine reads nothing else: in particular it never reads
obj+0x00, and the plain vectors' end fields are never read.
"""

MASK64 = (1 << 64) - 1


def _require(mapping, key):
    if not isinstance(mapping, dict) or key not in mapping:
        raise ValueError("missing field %r" % (key,))
    return mapping[key]


def destroy_string(string):
    """Apply the string rule; return a delete tuple or None."""
    ptr = _require(string, "ptr") & MASK64
    cap = _require(string, "cap") & MASK64
    cap_addr = _require(string, "cap_addr") & MASK64
    if ptr == cap_addr:
        return None
    return (ptr, (cap + 1) & MASK64)


def destroy_plain_vector(vector):
    """Apply the plain-vector rule; return a delete tuple or None."""
    begin = _require(vector, "begin") & MASK64
    if begin == 0:
        return None
    cap = _require(vector, "cap") & MASK64
    return (begin, (cap - begin) & MASK64)


def destroy_loop_vector(vector, step, element_strings):
    """Destroy one loop vector; return (deletes, external_calls).

    ``element_strings`` lists, per element, the string keys in
    the order the routine destroys them (descending offsets).
    """
    begin = _require(vector, "begin") & MASK64
    end = _require(vector, "end") & MASK64
    cap = _require(vector, "cap") & MASK64
    elements = _require(vector, "elements")
    if end < begin or (end - begin) % step != 0:
        raise ValueError("loop vector range is not a multiple of %#x" % step)
    if begin == 0 and end != 0:
        raise ValueError("loop vector with a zero begin and nonzero end")
    if len(elements) != (end - begin) // step:
        raise ValueError("loop vector element count does not match its span")
    deletes = []
    for element in elements:
        for key in element_strings:
            delete = destroy_string(_require(element, key))
            if delete is not None:
                deletes.append(delete)
    if begin != 0:
        deletes.append((begin, (cap - begin) & MASK64))
    return deletes, []


def destroy_list(linked):
    """Destroy the linked list; return (deletes, external_calls)."""
    head = _require(linked, "head") & MASK64
    nodes = _require(linked, "nodes")
    deletes = []
    external_calls = []
    seen = set()
    node_addr = head
    while node_addr != 0:
        if node_addr in seen:
            raise ValueError("linked list revisits %#x" % node_addr)
        seen.add(node_addr)
        node = _require(nodes, node_addr)
        external_calls.append(_require(node, "field18"))
        nxt = _require(node, "next") & MASK64
        deletes.append((node_addr, 0x30))
        node_addr = nxt
    return deletes, external_calls


def element_teardown(obj):
    """Apply the whole 0x5d516f0 rule to ``obj``.

    Returns ``{"deletes": [...], "external_calls": [...]}`` in
    code order. ``deletes`` holds ``(pointer, size)`` pairs for
    operator delete calls, including the two tail-jumped calls
    for the strings at +0x28 and +0x08, which return through
    delete. ``external_calls`` holds the +0x18 qwords passed to
    the 0x5d4c8d0 callee, in chain order.
    """
    deletes = []
    external_calls = []

    def add(delete):
        if delete is not None:
            deletes.append(delete)

    # Descending offset order, exactly as the binary runs.
    add(destroy_string(_require(obj, "string_0x160")))
    add(destroy_string(_require(obj, "string_0x138")))
    add(destroy_plain_vector(_require(obj, "vector_0x110")))
    add(destroy_plain_vector(_require(obj, "vector_0xf8")))
    loop_deletes, _ = destroy_loop_vector(
        _require(obj, "vector_0xe0"), 0x58,
        ("string_0x38", "string_0x18"))
    deletes.extend(loop_deletes)
    loop_deletes, _ = destroy_loop_vector(
        _require(obj, "vector_0xc8"), 0x130,
        ("string_0x100", "string_0xe0", "string_0x50", "string_0x30"))
    deletes.extend(loop_deletes)
    list_deletes, list_calls = destroy_list(_require(obj, "list_0xa8"))
    deletes.extend(list_deletes)
    external_calls.extend(list_calls)
    loop_deletes, _ = destroy_loop_vector(
        _require(obj, "vector_0x80"), 0x28, ("string_0x08",))
    deletes.extend(loop_deletes)
    add(destroy_string(_require(obj, "string_0x28")))
    add(destroy_string(_require(obj, "string_0x08")))
    return {"deletes": deletes, "external_calls": external_calls}
