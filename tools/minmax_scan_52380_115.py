"""Python model of node #115 routine 0x5d52380 (RE-001).

Faithful step-for-step model of the routine's observable behaviour:
the circular-list min/max scan, the (min, max) emit, the record
zeroing, the computed-but-unconsumed quotient, the chain walk, and
the tail build choice. Lock/unlock, emit, builders and assign are
call-shape only in the binary, so the model reports them as events
rather than executing their internals.
"""
MAGIC = 0x28F5C28F5C28F5C3
MASK64 = (1 << 64) - 1


class OutOfRange(Exception):
    """The routine's out_of_range throw."""


def scan_list(nodes, root):
    """Circular-list scan.

    nodes: id -> {"next": id, "a": int, "b": int, "flag": int}.
    root: the sentinel id; nodes[root]["next"] is the first node.
    Returns (mn, mx) over qualifying nodes, or None when no node
    qualifies (empty list, all flagged, or all zero values).
    """
    start = nodes[root]["next"]
    if start == root:
        return None
    mn = None
    mx = None
    cur = start
    while True:
        node = nodes[cur]
        if node["flag"] == 0:
            v = node["a"] if node["a"] < node["b"] else node["b"]
            if v != 0:
                mn = v if mn is None or v < mn else mn
                mx = v if mx is None or v > mx else mx
        cur = node["next"]
        if cur == root:
            break
    if mn is None:
        return None
    return (mn, mx)


def quotient(min_value):
    """The routine's multiply-shift quotient from mn.

    rbx = mn + 99 (mod 2^64); rdx = rbx >> 2; rdx:rax = MAGIC * rdx;
    result = (rdx:rax >> 64) >> 2. Ordinary values give
    floor((mn + 99) / 100); the wrap corner gives 0.
    """
    rbx = (min_value + 0x63) & MASK64
    rdx = rbx >> 2
    return ((MAGIC * rdx) >> 64) >> 2


def _check(node, nodes, sentinel):
    if node == sentinel:
        raise OutOfRange("walk backed up to the sentinel")
    if nodes[node]["kind"] > 3:
        raise OutOfRange("end node kind above 3")
    return ("found", node)


def walk_chain(nodes, head, sentinel):
    """The routine's chain walk, step for step.

    nodes: id -> {"kind": int, "nxt": id | None, "down": id | None}.
    head: the [H+0x1790] node id, or None for a null head.
    sentinel: the H+0x1788 id (never a node).
    Returns ("found", node_id); raises OutOfRange on the throw paths.
    """
    if head is None:
        raise OutOfRange("null walk head")
    rcx = head
    rdx = sentinel
    while True:
        # Outer loop head (0x5d524a8).
        kind = nodes[rcx]["kind"]
        rsi = nodes[rcx]["nxt"]
        rax = nodes[rcx]["down"]
        if kind > 2:
            # Step via +0x10 (0x5d524d0).
            if rsi is None:
                return _check(rcx, nodes, sentinel)
            rdx = rcx
            rcx = rsi
            continue
        if rax is None:
            return _check(rdx, nodes, sentinel)
        rcx = rax
        # Inner loop (0x5d524b6).
        while True:
            kind = nodes[rcx]["kind"]
            rsi = nodes[rcx]["nxt"]
            rax = nodes[rcx]["down"]
            if kind <= 2:
                if rax is None:
                    return _check(rdx, nodes, sentinel)
                rcx = rax
                continue
            # Kind > 2: step via +0x10 (0x5d524d0).
            if rsi is None:
                return _check(rcx, nodes, sentinel)
            rdx = rcx
            rcx = rsi
            break


def run(scan_nodes, scan_root, walk_nodes, walk_head, sentinel):
    """Run the whole routine over abstract holders.

    Returns a dict with the emit pair, the zeroed record fields, the
    quotient (None on the empty path), the walk outcome, and which
    temp builder the tail uses.
    """
    scanned = scan_list(scan_nodes, scan_root)
    out = {"dword0": 0, "word4": 0, "qword8": 0}
    if scanned is None:
        return {"emit": (0, 0), "out": out, "quotient": None,
                "walk": "skipped", "temp_builder": "default"}
    mn, mx = scanned
    q = quotient(mn)
    rbx = (mn + 0x63) & MASK64
    if rbx <= 0x63:
        return {"emit": (mn, mx), "out": out, "quotient": q,
                "walk": "skipped-wrap", "temp_builder": "default"}
    found = walk_chain(walk_nodes, walk_head, sentinel)
    return {"emit": (mn, mx), "out": out, "quotient": q,
            "walk": found, "temp_builder": "found"}
