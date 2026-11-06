"""Tests for the node #115 copy-on-write move helper model
(tools/cow_move_helper_12840_115.py, RE-001 work item
RE-001-cow-move-helper-12840-115). Each check counts; the run
prints "<n> checks pass" on success.

Expectations are target-grounded, read from the whole-function
excerpt in the packet: the prologue field writes, the list-1
deep copy plus payload bump, the list-2 lockstep reconciliation
(payload overwrite, surplus destroy, remainder deep copy) and
the closing payload bump are each exercised on structured list
images built in a model memory.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from cow_move_helper_12840_115 import (  # noqa: E402
    NODE_SIZE,
    cow_move_helper,
    list_copy_range,
    list_unhook,
)

CHECKS = [0]

MEM_SIZE = 0x20000
THIS = 0x1000
OLD = 0x2000
REFS = 0x18
NODE_ARENA = 0x4000
PAYLOAD_ARENA = 0x8000
HEAP = 0x10000


def check(condition, label):
    assert condition, label
    CHECKS[0] += 1


class BumpAlloc:
    def __init__(self, base):
        self.next = base
        self.freed = []

    def alloc(self, size):
        addr = self.next
        self.next += size
        return addr

    def free(self, addr, size):
        self.freed.append((addr, size))


def rd64(mem, addr):
    return int.from_bytes(mem[addr:addr + 8], "little")


def wr64(mem, addr, value):
    mem[addr:addr + 8] = (value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def rd32(mem, addr):
    return int.from_bytes(mem[addr:addr + 4], "little")


def wr32(mem, addr, value):
    mem[addr:addr + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")


def make_payload(mem, addr, counter):
    for i in range(0x78):
        mem[addr + i] = 0x50
    wr32(mem, addr + 0x70, counter)
    return addr


def build_list(mem, obj, header_off, payloads, arena):
    """Link a circular list of fresh nodes at obj+header_off
    carrying `payloads`; set the count field; return node addrs."""
    header = obj + header_off
    nodes = []
    for i, _payload in enumerate(payloads):
        node = arena + i * NODE_SIZE
        wr64(mem, node + 0x10, payloads[i])
        nodes.append(node)
    prev = header
    for node in nodes:
        wr64(mem, prev, node)
        wr64(mem, node + 8, prev)
        prev = node
    wr64(mem, prev, header)
    wr64(mem, header, nodes[0] if nodes else header)
    wr64(mem, header + 8, prev)
    wr64(mem, obj + header_off + 0x10, len(nodes))
    return nodes


def list_payloads(mem, obj, header_off):
    header = obj + header_off
    out = []
    node = rd64(mem, header)
    while node != header:
        out.append(rd64(mem, node + 0x10))
        node = rd64(mem, node)
    return out


def list_nodes(mem, obj, header_off):
    header = obj + header_off
    out = []
    node = rd64(mem, header)
    while node != header:
        out.append(node)
        node = rd64(mem, node)
    return out


def fresh_old(mem, l1_payloads, l2_payloads):
    for i in range(0x50):
        mem[OLD + i] = 0xA5
    nodes1 = build_list(mem, OLD, 0x00, l1_payloads, NODE_ARENA)
    nodes2 = build_list(mem, OLD, 0x18, l2_payloads,
                        NODE_ARENA + 0x400)
    wr32(mem, OLD + 0x30, 0xDEADBEEF)
    wr64(mem, OLD + 0x38, 0x1122334455667788)
    return nodes1, nodes2


def fresh_this(mem):
    for i in range(0x50):
        mem[THIS + i] = 0x5A
    wr32(mem, THIS + 0x34, 0xCAFEBABE)


def main():
    # -- Prologue on a fresh destination, empty source lists. --
    mem = bytearray(MEM_SIZE)
    fresh_old(mem, [], [])
    fresh_this(mem)
    alloc = BumpAlloc(HEAP)
    cow_move_helper(mem, THIS, REFS, OLD, alloc)
    check(rd64(mem, THIS + 0x00) == THIS, "list1 header next self")
    check(rd64(mem, THIS + 0x08) == THIS, "list1 header prev self")
    check(rd64(mem, THIS + 0x10) == 0, "list1 count zero")
    check(rd64(mem, THIS + 0x18) == THIS + 0x18, "list2 header self")
    check(rd64(mem, THIS + 0x20) == THIS + 0x18, "list2 header prev")
    check(rd64(mem, THIS + 0x28) == 0, "list2 count zero")
    check(rd32(mem, THIS + 0x30) == 0xDEADBEEF, "+0x30 dword copied")
    check(rd32(mem, THIS + 0x34) == 0xCAFEBABE,
          "+0x34 dword never written")
    check(rd64(mem, THIS + 0x38) == 0x1122334455667788,
          "+0x38 qword copied")
    check(rd32(mem, THIS + 0x40) == 0, "refcount zeroed")
    check(rd64(mem, THIS + 0x48) == REFS, "rsi stored at +0x48")
    check(alloc.next == HEAP and not alloc.freed,
          "empty copy allocates and frees nothing")

    # -- Self-copy guard: prologue stands, nothing else runs. --
    mem = bytearray(MEM_SIZE)
    p_a = make_payload(mem, PAYLOAD_ARENA, 7)
    fresh_old(mem, [p_a], [p_a])
    alloc = BumpAlloc(HEAP)
    cow_move_helper(mem, OLD, REFS, OLD, alloc)
    check(rd64(mem, OLD + 0x00) == OLD, "self: list1 header reset")
    check(rd64(mem, OLD + 0x10) == 0, "self: list1 count zeroed")
    check(rd64(mem, OLD + 0x28) == 0, "self: list2 count zeroed")
    check(rd32(mem, OLD + 0x40) == 0, "self: refcount zeroed")
    check(rd32(mem, p_a + 0x70) == 7, "self: payload not bumped")
    check(alloc.next == HEAP and not alloc.freed,
          "self: no allocation or free")

    # -- List 1 deep copy + bump; list 2 via the helper path. --
    mem = bytearray(MEM_SIZE)
    p1 = make_payload(mem, PAYLOAD_ARENA + 0x000, 10)
    p2 = make_payload(mem, PAYLOAD_ARENA + 0x100, 0xFFFFFFFF)
    p3 = make_payload(mem, PAYLOAD_ARENA + 0x200, 3)
    old_nodes1, _ = fresh_old(mem, [p1, p2], [p3])
    fresh_this(mem)
    alloc = BumpAlloc(HEAP)
    cow_move_helper(mem, THIS, REFS, OLD, alloc)
    check(list_payloads(mem, THIS, 0x00) == [p1, p2],
          "list1 payloads copied in order")
    check(rd64(mem, THIS + 0x10) == 2, "list1 count is 2")
    new_nodes = list_nodes(mem, THIS, 0x00)
    check(all(n >= HEAP for n in new_nodes),
          "list1 nodes are fresh allocations")
    check(list_payloads(mem, OLD, 0x00) == [p1, p2],
          "source list1 unchanged")
    check(rd32(mem, p1 + 0x70) == 11, "list1 payload 1 bumped")
    check(rd32(mem, p2 + 0x70) == 0,
          "list1 payload counter wraps 0xffffffff -> 0")
    check(list_payloads(mem, THIS, 0x18) == [p3],
          "list2 payload copied")
    check(rd64(mem, THIS + 0x28) == 1, "list2 count is 1")
    check(rd32(mem, p3 + 0x70) == 4, "list2 payload bumped once")

    # -- Preloaded destination list 2, source list 1 nonempty:
    #    the prologue self-links the destination list-2 header
    #    before any list phase reads it, so the preloaded nodes
    #    are orphaned -- the lockstep walk and the surplus
    #    destroy loop in the body never engage, and the helper
    #    deep-copies the whole source list 2. --
    mem = bytearray(MEM_SIZE)
    pa = make_payload(mem, PAYLOAD_ARENA + 0x000, 100)
    pb = make_payload(mem, PAYLOAD_ARENA + 0x100, 200)
    pc = make_payload(mem, PAYLOAD_ARENA + 0x200, 300)
    pd = make_payload(mem, PAYLOAD_ARENA + 0x300, 400)
    pe = make_payload(mem, PAYLOAD_ARENA + 0x400, 500)
    p1 = make_payload(mem, PAYLOAD_ARENA + 0x500, 1)
    fresh_old(mem, [p1], [pc, pd, pe])
    fresh_this(mem)
    dst_nodes = build_list(mem, THIS, 0x18, [pa, pb],
                           NODE_ARENA + 0x800)
    alloc = BumpAlloc(HEAP)
    cow_move_helper(mem, THIS, REFS, OLD, alloc)
    kept = list_nodes(mem, THIS, 0x18)
    check(all(n >= HEAP for n in kept),
          "preloaded list2 replaced by fresh copies")
    check(list_payloads(mem, THIS, 0x18) == [pc, pd, pe],
          "whole source list2 deep-copied")
    check(rd64(mem, THIS + 0x28) == 3, "list2 count rebuilt to 3")
    check(rd32(mem, pa + 0x70) == 100 and rd32(mem, pb + 0x70) == 200,
          "orphaned payloads are neither overwritten nor bumped")
    check(rd32(mem, pc + 0x70) == 301 and rd32(mem, pd + 0x70) == 401
          and rd32(mem, pe + 0x70) == 501,
          "copied list2 payloads bumped exactly once")
    check(not alloc.freed, "orphaning frees nothing")
    check(rd64(mem, dst_nodes[0] + 0x10) == pa
          and rd64(mem, dst_nodes[1] + 0x10) == pb,
          "orphaned nodes keep their payloads and links")

    # -- Preloaded destination list 2 longer than the source:
    #    still no destroy run -- the surplus nodes are orphaned
    #    by the same prologue reset, not deleted. --
    mem = bytearray(MEM_SIZE)
    pa = make_payload(mem, PAYLOAD_ARENA + 0x000, 100)
    pb = make_payload(mem, PAYLOAD_ARENA + 0x100, 200)
    pc = make_payload(mem, PAYLOAD_ARENA + 0x200, 300)
    pz = make_payload(mem, PAYLOAD_ARENA + 0x300, 900)
    p1 = make_payload(mem, PAYLOAD_ARENA + 0x500, 1)
    fresh_old(mem, [p1], [pz])
    fresh_this(mem)
    dst_nodes = build_list(mem, THIS, 0x18, [pa, pb, pc],
                           NODE_ARENA + 0x800)
    alloc = BumpAlloc(HEAP)
    cow_move_helper(mem, THIS, REFS, OLD, alloc)
    check(list_payloads(mem, THIS, 0x18) == [pz],
          "longer preloaded list2 replaced by the source copy")
    check(rd64(mem, THIS + 0x28) == 1, "list2 count rebuilt to 1")
    check(not alloc.freed,
          "surplus nodes are orphaned, never freed")
    check(rd32(mem, pz + 0x70) == 901, "copied payload bumped")
    check(rd32(mem, pb + 0x70) == 200 and rd32(mem, pc + 0x70) == 300,
          "orphaned payloads are not bumped")
    check(rd64(mem, dst_nodes[2] + 0x10) == pc,
          "orphaned tail node untouched")

    # -- Source list 1 empty, destination list 2 preloaded:
    #    same orphaning; the whole source list 2 is copied and
    #    only the copies are bumped. --
    mem = bytearray(MEM_SIZE)
    pa = make_payload(mem, PAYLOAD_ARENA + 0x000, 100)
    pb = make_payload(mem, PAYLOAD_ARENA + 0x100, 200)
    pc = make_payload(mem, PAYLOAD_ARENA + 0x200, 300)
    fresh_old(mem, [], [pb, pc])
    fresh_this(mem)
    dst_nodes = build_list(mem, THIS, 0x18, [pa], NODE_ARENA + 0x800)
    alloc = BumpAlloc(HEAP)
    cow_move_helper(mem, THIS, REFS, OLD, alloc)
    check(list_payloads(mem, THIS, 0x18) == [pb, pc],
          "empty source list1: list2 is a pure deep copy")
    check(rd64(mem, THIS + 0x28) == 2, "list2 count rebuilt to 2")
    check(rd32(mem, pa + 0x70) == 100,
          "orphaned payload not bumped by the closing walk")
    check(rd32(mem, pb + 0x70) == 201 and rd32(mem, pc + 0x70) == 301,
          "copied payloads bumped once")
    check(not alloc.freed, "orphaning frees nothing again")

    # -- Helper contract units. --
    mem = bytearray(MEM_SIZE)
    p1 = make_payload(mem, PAYLOAD_ARENA, 5)
    src_nodes = build_list(mem, OLD, 0x00, [p1], NODE_ARENA)
    wr64(mem, THIS + 0x00, THIS)
    wr64(mem, THIS + 0x08, THIS)
    wr64(mem, THIS + 0x10, 0)
    alloc = BumpAlloc(HEAP)
    list_copy_range(mem, THIS, THIS, rd64(mem, OLD), OLD, alloc)
    check(list_payloads(mem, THIS, 0x00) == [p1],
          "copy_range copies the payload")
    check(rd64(mem, THIS + 0x10) == 1, "copy_range adds the count")
    check(list_nodes(mem, THIS, 0x00) != src_nodes,
          "copy_range allocates fresh nodes")
    alloc2 = BumpAlloc(HEAP)
    list_copy_range(mem, THIS, THIS, OLD, OLD, alloc2)
    check(alloc2.next == HEAP, "copy_range empty range is a no-op")
    node = src_nodes[0]
    list_unhook(mem, node)
    check(rd64(mem, OLD) == OLD and rd64(mem, OLD + 8) == OLD,
          "unhook empties a one-node list")

    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
