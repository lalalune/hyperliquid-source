"""Python model of node #115's recursive list-tree copy at 0x5d4caa0.

RE-001 work item: research/work-items/RE-001-list-tree-copy-115/.
The routine takes a source list head in rdi and a link value in
rsi, and returns the head copy in rax. Each node is 0x30 bytes.
For every copied node the routine allocates one fresh 0x30-byte
node (PLT 0x63f0dd0, ``_Znwm``), copies the source +0x00 dword
and the 16 tail bytes at +0x20..+0x2f, sets +0x10 and +0x18 to 0,
then fills them in: +0x08 is the incoming link for the head copy,
the previous copy for a sibling copy, and the copy of the parent
node for a child-list head copy; +0x18 becomes the recursive copy
of the source node's child list, or stays 0 when that list is
null; +0x10 links each sibling copy to the next. The source
node's own +0x08 is never read, and the +0x04..+0x07 bytes are
neither read nor written, so a copy carries no value there.

Walk order, stated literally: copy the head node, then copy its
whole child list, then walk the source +0x10 chain in order,
copying each sibling (linking it to the previous copy) and its
child list before moving on. Allocation order for a head A with
next B and child list C -> D (D having child E) is A, C, D, E, B.

The routine assumes a non-null source head: its first
instructions dereference the source node, and the only observed
caller guards a null head before calling. A null head therefore
raises ValueError instead of being silently modelled. A missing
node, a missing field, or a source cycle likewise raises
ValueError; the binary would loop or fault on such input.

On an allocation failure, the binary's landing pad tears down
the partial head copy held in r12 with the list-tree teardown
(0x5d4c8d0, post-order: child list, then node, then sibling)
and rethrows. Each nested copy invocation tears down its own
partial head first, innermost first. The model mirrors that:
an allocation failure raises CopyFailed, whose ``deletes``
attribute is the ordered list of ``(node_address, 0x30)`` teardown
deletes, innermost invocation first. Failure is modelled only
once a head copy exists; a failure on the very first allocation
of an invocation leaves that invocation with no head copy to
tear down.
"""

MASK64 = (1 << 64) - 1


class CopyFailed(Exception):
    """An allocation failure, carrying the teardown deletes."""

    def __init__(self, deletes):
        super().__init__("list-tree copy failed after %d teardown deletes"
                         % len(deletes))
        self.deletes = deletes


class _AllocFailed(Exception):
    pass


def _require(mapping, key):
    if not isinstance(mapping, dict) or key not in mapping:
        raise ValueError("missing field %r" % (key,))
    return mapping[key]


def _destroy(copies, head, deletes):
    """Post-order teardown of a copy chain: child, node, sibling."""
    node = head & MASK64
    while node != 0:
        entry = _require(copies, node)
        _destroy(copies, _require(entry, "child") & MASK64, deletes)
        deletes.append((node, 0x30))
        node = _require(entry, "next") & MASK64


def _check_source(nodes, address):
    entry = _require(nodes, address)
    word = _require(entry, "w0") & 0xFFFFFFFF
    tail = _require(entry, "tail")
    if not isinstance(tail, bytes) or len(tail) != 16:
        raise ValueError("tail of %#x must be 16 bytes" % address)
    nxt = _require(entry, "next") & MASK64
    child = _require(entry, "child") & MASK64
    return word, tail, nxt, child


def copy_list(head, nodes, link, alloc):
    """Copy the +0x10 list headed by ``head``.

    ``nodes`` maps a source address to
    ``{"w0": dword, "tail": 16 bytes, "next": addr, "child": addr}``.
    ``link`` is stored verbatim at the head copy's +0x08.
    ``alloc`` is a zero-argument callable returning a fresh copy
    address; any exception it raises counts as an allocation
    failure. Returns ``(head_copy_address, copies)`` where
    ``copies`` maps a copy address to
    ``{"w0", "tail", "prev", "next", "child"}``.
    """
    if (head & MASK64) == 0:
        raise ValueError("null source head: the routine dereferences it")
    copies = {}
    active = set()

    def chain(src_head, first_link):
        head_copy = 0
        try:
            seen = set()
            current = src_head & MASK64
            previous = 0
            current_link = first_link
            while current != 0:
                if current in seen or current in active:
                    raise ValueError("list-tree cycle through %#x" % current)
                seen.add(current)
                active.add(current)
                word, tail, nxt, child = _check_source(nodes, current)
                try:
                    fresh = alloc()
                except Exception:
                    raise _AllocFailed()
                fresh = fresh & MASK64
                copies[fresh] = {"w0": word, "tail": tail,
                                 "prev": current_link, "next": 0, "child": 0}
                if head_copy == 0:
                    head_copy = fresh
                if previous != 0:
                    copies[previous]["next"] = fresh
                if child != 0:
                    copies[fresh]["child"] = chain(child, fresh)
                active.discard(current)
                previous = fresh
                current_link = fresh
                current = nxt
            return head_copy
        except CopyFailed as exc:
            outer = []
            if head_copy != 0:
                _destroy(copies, head_copy, outer)
            raise CopyFailed(exc.deletes + outer)
        except _AllocFailed:
            outer = []
            if head_copy != 0:
                _destroy(copies, head_copy, outer)
            raise CopyFailed(outer)

    head_copy = chain(head, link)
    return head_copy, copies


def site_tails(copies, head_copy):
    """Post-call walks of the 0x5d80ee3 site's caller.

    Walks the copy's +0x10 chain from the head copy to its last
    node, and the copy's +0x18 chain from the head copy to its
    last node. Returns ``(last_next, last_child)``.
    """
    if (head_copy & MASK64) == 0:
        raise ValueError("null head copy")
    node = head_copy & MASK64
    while _require(copies, node)["next"] & MASK64 != 0:
        node = _require(copies, node)["next"] & MASK64
    last_next = node
    node = head_copy & MASK64
    while _require(copies, node)["child"] & MASK64 != 0:
        node = _require(copies, node)["child"] & MASK64
    return last_next, node
