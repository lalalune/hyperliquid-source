"""Tests for the node #115 list-copy-insert model
(tools/list_copy_insert_12320_115.py, RE-001 work item
RE-001-list-copy-insert-12320-115). Each check counts; the run
prints "<n> checks pass" on success.

Expectations are target-grounded, read from the whole-function
excerpt in the packet: an empty range writes nothing at all;
the copies are built in a private temp list (fresh 0x18-byte
node per source node, only the payload qword at +0x10 stored by
the body, hooks always at the temp header so the order is the
source order); one _M_transfer splice moves the whole temp
chain before the position node; the destination size at +0x10
grows by the copied count only after the transfer; the drain
loop then deletes whatever the transfer left in the temp list
-- nothing, for a faithful transfer. An allocation failure
mid-copy raw-deletes the temp chain and leaves the destination
byte-for-byte untouched.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from list_copy_insert_12320_115 import ListCopyInsert

CHECKS = [0]


def check(condition, label):
    assert condition, label
    CHECKS[0] += 1


def qword(mem, addr):
    value = 0
    for i in range(8):
        value |= mem.get(addr + i, 0) << (8 * i)
    return value


def store_qword(mem, addr, value):
    for i in range(8):
        mem[addr + i] = (value >> (8 * i)) & 0xFF


class Harness:
    """Abstract memory + allocator + the two PLT primitives,
    modelled faithfully: hook links a node before a position
    node; transfer splices [first, last) before a position and
    empties the source list it took the chain from."""

    def __init__(self):
        self.mem = {}
        self.next_addr = 0x100000
        self.frees = []          # (addr, size) in order
        self.hooks = []          # (node, position_node)
        self.transfers = []      # (position, first, last)
        self.log = []            # ordered event log
        self.machine = None
        self.fail_on_alloc = None   # 1-based alloc index to fail
        self.alloc_count = 0
        self.transfer_moves = True  # False: transfer is a no-op

    # -- list construction --------------------------------------
    def make_list(self, payloads, base=None):
        """Build a list object: header node + one node per
        payload, circular. Returns (obj, header, [nodes])."""
        obj = self.next_addr if base is None else base
        # The list object itself occupies 0x18 bytes (header
        # links + size); reserve it so the first node _fresh()
        # hands out does not alias the header.
        self.next_addr = max(self.next_addr, obj + 0x18)
        header = obj
        nodes = []
        prev = header
        for payload in payloads:
            node = self._fresh()
            store_qword(self.mem, node + 0x10, payload)
            store_qword(self.mem, prev + 0x00, node)
            store_qword(self.mem, node + 0x08, prev)
            prev = node
            nodes.append(node)
        store_qword(self.mem, header + 0x00, nodes[0] if nodes else header)
        store_qword(self.mem, header + 0x08, prev)
        if nodes:
            store_qword(self.mem, nodes[-1] + 0x00, header)
        store_qword(self.mem, obj + 0x10, len(payloads))
        return obj, header, nodes

    def _fresh(self):
        addr = self.next_addr
        self.next_addr += 0x18
        for i in range(0x18):
            self.mem[addr + i] = 0
        return addr

    def chain(self, header):
        out = []
        cur = qword(self.mem, header + 0x00)
        while cur != header:
            out.append(cur)
            cur = qword(self.mem, cur + 0x00)
        return out

    def payloads(self, header):
        return [qword(self.mem, n + 0x10) for n in self.chain(header)]

    # -- primitives handed to the model --------------------------
    def alloc(self, size):
        assert size == 0x18
        self.alloc_count += 1
        if self.fail_on_alloc == self.alloc_count:
            raise RuntimeError("bad_alloc (modelled)")
        addr = self.node_alloc()
        self.log.append(("alloc", addr))
        return addr

    def node_alloc(self):
        """Fresh-node source for the model's allocations; kept
        separate from _fresh so a test can poison exactly the
        records the routine allocates."""
        return self._fresh()

    def free(self, addr, size):
        self.frees.append((addr, size))
        self.log.append(("free", addr))

    def hook(self, node, position):
        # position is the model's ("temp", 0) token: the temp
        # header, a real node in mem for this harness. This is
        # _List_node_base::_M_hook verbatim: link the fresh node
        # in before the position node.
        self.hooks.append((node, position))
        self.log.append(("hook", node))
        self.machine.temp_link(node)
        pos = self.temp_header_addr
        store_qword(self.mem, node + 0x00, pos)
        store_qword(self.mem, node + 0x08, qword(self.mem, pos + 0x08))
        store_qword(self.mem, qword(self.mem, pos + 0x08) + 0x00, node)
        store_qword(self.mem, pos + 0x08, node)
        self.temp_nodes.append(node)

    def transfer(self, position, first, last):
        self.transfers.append((position, first, last))
        self.log.append(("transfer", position))
        if not self.transfer_moves:
            return
        header = self.temp_header_addr
        first_node = qword(self.mem, header + 0x00)
        # _List_node_base::_M_transfer verbatim, with
        # [first_node, header) spliced before `position`.
        if position != header:
            store_qword(self.mem,
                        qword(self.mem, header + 0x08) + 0x00, position)
            store_qword(self.mem,
                        qword(self.mem, first_node + 0x08) + 0x00, header)
            store_qword(self.mem,
                        qword(self.mem, position + 0x08) + 0x00, first_node)
            tmp = qword(self.mem, position + 0x08)
            store_qword(self.mem, position + 0x08,
                        qword(self.mem, header + 0x08))
            store_qword(self.mem, header + 0x08,
                        qword(self.mem, first_node + 0x08))
            store_qword(self.mem, first_node + 0x08, tmp)
        for node in list(self.temp_nodes):
            self.machine.temp_unlink(node)
        self.temp_nodes = []

    # -- run ------------------------------------------------------
    def run(self, dest, position, first, last):
        self.temp_nodes = []
        # The native temp header lives on the routine's stack;
        # here it is a real node in mem, self-linked at entry,
        # exactly as the body's prologue leaves it.
        self.temp_header_addr = self._fresh()
        store_qword(self.mem, self.temp_header_addr + 0x00,
                    self.temp_header_addr)
        store_qword(self.mem, self.temp_header_addr + 0x08,
                    self.temp_header_addr)
        self.machine = ListCopyInsert(
            self.mem, self.alloc, self.free, self.hook, self.transfer)
        try:
            self.machine.run(dest, position, first, last)
        finally:
            # The temp header lives on the routine's own stack
            # frame: when the frame is popped its bytes leave
            # the modelled memory, on the return path and on
            # the exception path alike.
            for i in range(0x18):
                self.mem.pop(self.temp_header_addr + i, None)
        return self.machine


def main():
    # -- Empty range: nothing is written, not even the size. ---
    h = Harness()
    dest, dhead, dnodes = h.make_list([0xAA])
    before = dict(h.mem)
    h.run(dest, dhead, 0x777000, 0x777000)
    check(h.mem == before, "empty range writes nothing at all")
    check(h.alloc_count == 0 and not h.frees and not h.transfers,
          "empty range: no alloc, no transfer, no free")
    check(qword(h.mem, dest + 0x10) == 1, "empty range: size unchanged")

    # -- One element into an empty destination -----------------
    h = Harness()
    dest, dhead, _ = h.make_list([])
    src, shead, snodes = h.make_list([0x1111])
    h.run(dest, dhead, snodes[0], shead)
    check(h.payloads(dhead) == [0x1111], "single copy lands")
    check(qword(h.mem, dest + 0x10) == 1, "size grows by one")
    check(len(h.transfers) == 1, "exactly one transfer call")
    check(h.transfers[0][0] == dhead,
          "transfer position is the destination header (tail append)")
    check(h.chain(dhead)[0] != snodes[0], "copy is a fresh node")
    check(h.frees == [], "faithful transfer: drain deletes nothing")
    check(qword(h.mem, snodes[0] + 0x10) == 0x1111
          and qword(h.mem, src + 0x10) == 1,
          "source node and source size untouched")

    # -- Order and tail position with pre-existing nodes -------
    h = Harness()
    dest, dhead, _ = h.make_list([0xD0, 0xD1])
    src, shead, snodes = h.make_list([0xA, 0xB, 0xC])
    src_before = {n: qword(h.mem, n + 0x10) for n in snodes}
    h.run(dest, dhead, snodes[0], shead)
    check(h.payloads(dhead) == [0xD0, 0xD1, 0xA, 0xB, 0xC],
          "copies appended after existing nodes, in source order")
    check(qword(h.mem, dest + 0x10) == 5, "size grows by copied count")
    check(all(qword(h.mem, n + 0x10) == p for n, p in src_before.items()),
          "every source payload unchanged")
    check([n for n, _ in h.hooks] == h.chain(dhead)[2:],
          "hook order equals final copy order (temp list preserves order)")
    events = [e[0] for e in h.log]
    check(events.index("transfer") > max(
        i for i, e in enumerate(events) if e == "alloc"),
        "transfer happens after the last allocation (bulk splice)")

    # -- Insert before a middle position ------------------------
    h = Harness()
    dest, dhead, dnodes = h.make_list([0xD0, 0xD1, 0xD2])
    src, shead, snodes = h.make_list([0xA, 0xB])
    h.run(dest, dnodes[1], snodes[0], shead)
    check(h.payloads(dhead) == [0xD0, 0xA, 0xB, 0xD1, 0xD2],
          "copies land before the given position node")
    check(h.transfers[0][0] == dnodes[1],
          "transfer receives the caller's position verbatim")
    check(qword(h.mem, dest + 0x10) == 5, "size still grows by two")

    # -- Partial range: [first, middle) -------------------------
    h = Harness()
    dest, dhead, _ = h.make_list([])
    src, shead, snodes = h.make_list([0xA, 0xB, 0xC, 0xD])
    h.run(dest, dhead, snodes[1], snodes[3])
    check(h.payloads(dhead) == [0xB, 0xC],
          "only the [first, last) range is copied")
    check(qword(h.mem, dest + 0x10) == 2, "size grows by range length")

    # -- The body's only own store to a copy is the payload -----
    h = Harness()
    dest, dhead, _ = h.make_list([])
    src, shead, snodes = h.make_list([0x99])
    # Poison the allocator's fresh records: the model itself
    # must not clear the link fields -- only hook may write them.
    orig_alloc = h.node_alloc
    def poisoned():
        addr = orig_alloc()
        for i in range(0x10):
            h.mem[addr + i] = 0xEE
        return addr
    h.node_alloc = poisoned
    machine = h.run(dest, dhead, snodes[0], shead)
    copied = h.chain(dhead)[0]
    check(qword(h.mem, copied + 0x10) == 0x99,
          "payload copied despite poisoned fresh record")

    # -- Drain loop is live when the transfer does not move ----
    h = Harness()
    dest, dhead, _ = h.make_list([0xD0])
    src, shead, snodes = h.make_list([0xA, 0xB])
    h.transfer_moves = False
    h.run(dest, dhead, snodes[0], shead)
    check(len(h.frees) == 2 and all(s == 0x18 for _, s in h.frees),
          "drain deletes both stranded temp nodes with size 0x18")
    check(h.payloads(dhead) == [0xD0],
          "no-op transfer: destination chain unchanged")
    check(qword(h.mem, dest + 0x10) == 3,
          "size add still runs (it follows the transfer call)")

    # -- Allocation failure: cleanup path ------------------------
    h = Harness()
    dest, dhead, _ = h.make_list([0xD0, 0xD1])
    src, shead, snodes = h.make_list([0xA, 0xB, 0xC])
    dest_before = {a: b for a, b in h.mem.items()
                   if a < 0x100000 + 0x1000}
    size_before = qword(h.mem, dest + 0x10)
    h.fail_on_alloc = 2     # second copy's operator new throws
    raised = False
    try:
        h.run(dest, dhead, snodes[0], shead)
    except RuntimeError:
        raised = True
    check(raised, "allocation failure propagates")
    check(len(h.frees) == 1 and h.frees[0][1] == 0x18,
          "cleanup deletes the one built temp node, size 0x18")
    check(h.transfers == [], "failure path: no transfer ran")
    check(qword(h.mem, dest + 0x10) == size_before,
          "failure path: destination size untouched")
    check(h.payloads(dhead) == [0xD0, 0xD1],
          "failure path: destination chain untouched")

    # Failure on the very first allocation: nothing to delete.
    h = Harness()
    dest, dhead, _ = h.make_list([])
    src, shead, snodes = h.make_list([0xA])
    h.fail_on_alloc = 1
    raised = False
    try:
        h.run(dest, dhead, snodes[0], shead)
    except RuntimeError:
        raised = True
    check(raised and h.frees == [],
          "first-allocation failure: cleanup deletes nothing")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
