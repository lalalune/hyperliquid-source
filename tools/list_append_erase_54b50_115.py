"""Model of node #115 routines 0x5d54b50 (list append) and 0x5d54ba0
(list erase by handle).

Layout (records.json):
  holder list sentinel next +0x1260, prev +0x1268, size +0x1270;
  node next +0x00, prev +0x08, value +0x10, 0x18 bytes total;
  value source [[holder + 0x68] + 0xd8] — the value itself is a model
  input, since its type is not pinned.
  A handle slot holds None or a cell; a cell holds one node.

append(holder) reproduces 0x5d54b50: allocate a node holding the
source value, hook it immediately before the sentinel (the back of
the list), increment the size, and return the new node (the
sentinel's prev slot after the hook).
erase(holder, slot) reproduces 0x5d54ba0: a null slot is a no-op;
otherwise decrement the size, unhook and free the node with the
sized delete size 0x18, zero the slot, and free the cell with the
sized delete size 8.
Returns (frees) where frees is a list of ("node", 0x18) /
("cell", 8) entries in binary order.
"""

NODE_SIZE = 0x18
CELL_SIZE = 8


class Node:
    """One list node: next/prev links plus one 8-byte value."""

    def __init__(self, value):
        self.next = None
        self.prev = None
        self.value = value
        self.freed = False


class Holder:
    """The holder's list: a sentinel node plus a size count."""

    def __init__(self, source_value):
        self.sentinel = Node(None)
        self.sentinel.next = self.sentinel
        self.sentinel.prev = self.sentinel
        self.size = 0
        self.source_value = source_value

    def values(self):
        """Values in list order (sentinel excluded)."""
        out = []
        cur = self.sentinel.next
        while cur is not self.sentinel:
            out.append(cur.value)
            cur = cur.next
        return out

    def check_links(self):
        """Doubly-linked consistency, sentinel included."""
        cur = self.sentinel
        seen = 0
        while True:
            assert cur.next.prev is cur, "next/prev link broken"
            assert cur.prev.next is cur, "prev/next link broken"
            cur = cur.next
            seen += 1
            if cur is self.sentinel:
                break
            assert seen <= self.size + 1, "list longer than size"
        assert seen == self.size + 1, "size disagrees with list length"


class Cell:
    """One 8-byte handle cell holding a node pointer."""

    def __init__(self, node):
        self.node = node
        self.freed = False


class Slot:
    """A handle slot: None or a Cell."""

    def __init__(self):
        self.cell = None


def append(holder):
    """Append the source value; return the new node."""
    node = Node(holder.source_value)
    tail = holder.sentinel.prev
    node.next = holder.sentinel
    node.prev = tail
    tail.next = node
    holder.sentinel.prev = node
    holder.size += 1
    # The routine returns [holder + 0x1268] after the hook, which is
    # the sentinel's prev slot: the new node.
    assert holder.sentinel.prev is node
    return node


def install_handle(slot, node):
    """Caller fragment (observed at 0x5d6b634): store the append
    return into a fresh cell and the cell into the slot, freeing the
    slot's previous cell with the sized delete size 8. Returns the
    list of frees for the replaced cell."""
    old = slot.cell
    slot.cell = Cell(node)
    if old is None:
        return []
    old.freed = True
    return [("cell", CELL_SIZE)]


def erase(holder, slot):
    """Erase through a handle slot; return the frees in binary order."""
    cell = slot.cell
    if cell is None:
        return []
    node = cell.node
    holder.size -= 1
    node.prev.next = node.next
    node.next.prev = node.prev
    node.freed = True
    frees = [("node", NODE_SIZE)]
    slot.cell = None
    cell.freed = True
    frees.append(("cell", CELL_SIZE))
    return frees
