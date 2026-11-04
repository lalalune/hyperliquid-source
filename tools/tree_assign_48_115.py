"""Node #115 0x48-byte tree assign: 0x5d4e140 with its rebuilder 0x5d4de20
and the leftover teardown 0x5d4cba0.

RE-001 work item. Transliteration of the three routines, stated literally.

Node layout (0x48 bytes):
  +0x00 tag (dword), +0x08 link, +0x10 next sibling, +0x18 first child,
  +0x20/+0x28/+0x30 string, +0x38 never read or written by this
  component, +0x40 extra qword.
A string is inline exactly when its pointer equals its own capacity
slot address; a heap string is freed as delete(ptr, capacity + 1).
The builder 0x5d4a6a0 (open PR #2409) copies length bytes and stores
them inline when the length is at most 15, else in a fresh heap
buffer; the model records a heap string's capacity as its length,
so its delete size is length + 1.

Container (header embedded at dst+0x08):
  +0x10 root, +0x18 last node of the root's +0x10 walk,
  +0x20 last node of the root's +0x18 walk, +0x28 node count.
A fresh root's link is the header address; an empty tree has root 0
and +0x18/+0x20 both equal to the header address.

Assign 0x5d4e140, end to end:
  1. Self-assign (dst is src) returns with no effect.
  2. The old tree is detached into a stack pool pair: pool[0] is the
     old root, pool[1] is the old +0x20 node's +0x10 successor when
     that successor exists, else the old +0x20 node itself; the old
     root's link is cleared. The destination is reset to empty.
  3. When the source root exists, the rebuilder rebuilds it into the
     destination, reusing pool nodes while the pool lasts and
     allocating fresh 0x48-byte nodes after it runs dry. The
     destination's +0x10/+0x18/+0x20/+0x28 are then set from the
     rebuilt root and the source count.
  4. Whatever pool nodes remain are destroyed from pool[0] by the
     0x5d4cba0 teardown: per node, the +0x18 child subtree is torn
     down first, then the string is disposed, then the node is
     deleted with size 0x48, advancing to the +0x10 successor
     loaded before the node's own deletes.
  Observed consequence, stated plainly: a simple-case pop clears
  the new pool head's +0x10 link, and a splice-case pop clears
  the spliced node's +0x18 link. A node reachable only through
  a cleared link is then neither reused nor destroyed: it is
  orphaned by the binary's own cuts. Concretely, an old root
  whose first child has siblings A -> B -> C, assigned a
  single-node source, reuses B, destroys A and the root, and
  orphans C, because the new node's +0x10 is cleared on reuse
  and the leftover walk never reaches C. The model reproduces
  this exactly as the branch code dictates; it is a property
  of the target's assign, not a modeling choice.

Rebuilder 0x5d4de20 (src, link, pool) -> node, end to end:
  * A pool node is taken by _pop below, or a fresh node is
    allocated when the pool is empty. A reused node's old string
    is disposed and rebuilt from the source node. The tag and the
    +0x40 qword are copied, link is the link argument, next and
    child start as 0. The +0x38 slot is never touched: a reused
    node keeps its old value, a fresh node leaves it unspecified
    (modelled as None).
  * The source's child subtree is rebuilt recursively and stored
    at the new node's +0x18.
  * Each source sibling is then rebuilt the same way: its link is
    the previous rebuilt sibling, the previous sibling's +0x10 is
    the new node, and its child subtree is rebuilt recursively.

_pop (the pool take, identical in the head and sibling paths):
  head = pool[1]; when head is 0 there is no node to take.
  nxt = head's link; pool[1] = nxt.
  When nxt is 0, pool[0] is cleared (the pool is empty).
  When nxt's child is head, the take splices: nxt's child is
  cleared; when nxt's next exists, pool[1] walks from that next
  node down its +0x18 child chain to the deepest node, and then
  to that deepest node's +0x10 successor when one exists.
  Otherwise (nxt's child is not head) nxt's +0x10 is cleared.
  The taken node is head in every case.

NOT claimed: what the trees/nodes/tags/strings denote, the
_M_create internals behind a heap string build, caller semantics
beyond the call sites, or behavior on cyclic structures (the
model raises on a repeated node in the teardown path instead of
looping forever) or on inconsistent headers.
"""

HEADER = "header"


class Node:
    """One 0x48-byte node. ``link`` is a Node, HEADER, or None."""

    def __init__(self, label, tag=0, link=None, next_=None, child=None,
                 s="", extra40=0, raw38=None):
        self.label = label
        self.tag = tag
        self.link = link
        self.next = next_
        self.child = child
        self.s = s
        self.extra40 = extra40
        self.raw38 = raw38
        # Capacity of the string as built: inline strings carry no
        # heap buffer, so their dispose is a no-op; heap strings
        # free length + 1 bytes. The builder stores at most 15
        # bytes inline.
        self.s_inline = len(s) <= 15

    def __repr__(self):
        return "Node(%r)" % (self.label,)


class Container:
    """A tree container: root, +0x18 slot, +0x20 slot, count."""

    def __init__(self, root=None, slot18=HEADER, slot20=HEADER, count=0):
        self.root = root
        self.slot18 = slot18
        self.slot20 = slot20
        self.count = count


def _dispose(node, events):
    """Dispose one node's string (binary order: the only string)."""
    if not node.s_inline:
        events.append(("dispose", node.label, len(node.s) + 1))


def _build(node, src):
    """Rebuild the string from src."""
    node.s = src.s
    node.s_inline = len(src.s) <= 15


def _pop(pool):
    """Take one node from the pool, or return None when empty."""
    head = pool[1]
    if head is None:
        return None
    nxt = head.link
    pool[1] = nxt
    if nxt is None:
        pool[0] = None
        return head
    if nxt.child is head:
        rdx = nxt.next
        nxt.child = None
        if rdx is None:
            return head
        rax = rdx.child
        pool[1] = rdx
        if rax is not None:
            while True:
                rdx = rax
                rax = rax.child
                if rax is None:
                    break
            pool[1] = rdx
        rax = rdx.next
        if rax is None:
            return head
        pool[1] = rax
        return head
    nxt.next = None
    return head


def _teardown(node, events, seen):
    """0x5d4cba0: child subtree, string dispose, delete 0x48, next."""
    while node is not None:
        if id(node) in seen:
            raise ValueError("cyclic tree")
        seen.add(id(node))
        nxt = node.next
        _teardown(node.child, events, seen)
        _dispose(node, events)
        events.append(("delete", node.label, 0x48))
        node = nxt


def rebuilder(src, link, pool, events, counter):
    """Rebuild src's tree reusing pool nodes; return the new root."""
    node = _pop(pool)
    if node is None:
        node = Node("fresh%d" % counter[0])
        counter[0] += 1
        events.append(("alloc", node.label, 0x48))
        _build(node, src)
    else:
        _dispose(node, events)
        _build(node, src)
    node.tag = src.tag
    node.extra40 = src.extra40
    node.link = link
    node.next = None
    node.child = None
    if src.child is not None:
        node.child = rebuilder(src.child, node, pool, events, counter)
    prev = node
    cur = src.next
    while cur is not None:
        sib = _pop(pool)
        if sib is None:
            sib = Node("fresh%d" % counter[0])
            counter[0] += 1
            events.append(("alloc", sib.label, 0x48))
            _build(sib, cur)
        else:
            _dispose(sib, events)
            _build(sib, cur)
        sib.tag = cur.tag
        sib.extra40 = cur.extra40
        sib.link = prev
        sib.next = None
        sib.child = None
        prev.next = sib
        if cur.child is not None:
            sib.child = rebuilder(cur.child, sib, pool, events, counter)
        prev = sib
        cur = cur.next
    return node


def assign(dst, src, events):
    """Assign src's tree into dst, reusing dst's old nodes."""
    if dst is src:
        return
    old_root = dst.root
    old_last = dst.slot20
    pool = [old_root, None]
    if old_root is not None:
        if isinstance(old_last, Node):
            pool[1] = old_last.next if old_last.next is not None else old_last
        old_root.link = None
    dst.root = None
    dst.slot18 = HEADER
    dst.slot20 = HEADER
    dst.count = 0
    if src.root is not None:
        rebuilt = rebuilder(src.root, HEADER, pool, events, [0])
        last10 = rebuilt
        while last10.next is not None:
            last10 = last10.next
        last18 = rebuilt
        while last18.child is not None:
            last18 = last18.child
        dst.root = rebuilt
        dst.slot18 = last10
        dst.slot20 = last18
        dst.count = src.count
    _teardown(pool[0], events, set())
