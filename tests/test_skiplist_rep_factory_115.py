"""Tests for tools/skiplist_rep_factory_115.py.

Run (from the repository root):
    python3 tests/test_skiplist_rep_factory_115.py

Every expectation is pinned from the node #115 binary (digest
a6e2897c...b5301) via research/work-items/RE-001-skiplist-rep-
factory-115/; the packet's verify.py re-runs this file and
requires its summary line. No test uses pytest (not installed
on this VM); checks are counted by hand.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import skiplist_rep_factory_115 as m

CHECKS = 0


def check(condition, label):
    global CHECKS
    CHECKS += 1
    if not condition:
        raise AssertionError("check failed: %s" % label)


def test_huge_align():
    check(m.huge_align(0) == 0x1000, "align 0 -> 0x1000")
    check(m.huge_align(0x1000) == 0x1000, "align 0x1000 -> 0x1000")
    check(m.huge_align(0x1001) == 0x1010, "align 0x1001 -> 0x1010")
    check(m.huge_align(0x1010) == 0x1010, "align 0x1010 stays")
    check(m.huge_align(0x101F) == 0x1020, "align 0x101f -> 0x1020")
    check(m.huge_align(0x7FFFF000 + 0x1000) == 0x1000,
          "align huge -> 0x1000")
    check(m.huge_align(0x80000000) == 0x1000, "align 2GiB -> 0x1000")


def test_shard_bits_and_block_size():
    check(m.shard_bits(1) == 3, "shards hw=1 -> 3")
    check(m.shard_bits(8) == 3, "shards hw=8 -> 3")
    check(m.shard_bits(9) == 4, "shards hw=9 -> 4")
    check(m.shard_bits(16) == 4, "shards hw=16 -> 4")
    check(m.shard_bits(17) == 5, "shards hw=17 -> 5")
    check(m.shard_bits(64) == 6, "shards hw=64 -> 6")
    check(m.arena_block_size(0x80000) == 0x10000, "block 0x80000 -> /8")
    check(m.arena_block_size(0xFFFFF) == 0x1FFFF, "block just under cap")
    check(m.arena_block_size(0x100000) == 0x20000, "block at cap input")
    check(m.arena_block_size(0x800000) == 0x20000, "block above cap")


def test_arena_init():
    mem = m.Memory()
    arena = mem.alloc(0x9B0)
    owner18 = 0x12340
    out_arena, count, array = m.arena_init(
        mem, arena, owner18, arena + 0x80, 0x40, 16)
    check(out_arena == arena, "init returns the arena")
    check(mem.read_qword(arena) == m.CONCURRENT_ARENA_VTABLE,
          "arena vtable")
    check(mem.read_qword(arena + 0x40) == owner18 // 8,
          "block size = rsi/8")
    check(mem.read_u32(arena + 0x50) == 4, "shard bits for hw=16")
    check(count == 16, "16 shards for hw=16")
    check(mem.read_qword(arena + 0x48) == array, "shard array installed")
    for i in range(count):
        shard = array + i * 0x40
        check(mem.read_byte(shard + 0x28) == 0, "shard lock byte 0")
        check(mem.read_qword(shard + 0x30) == 0, "shard cursor 0")
        check(mem.read_qword(shard + 0x38) == 0, "shard end 0")
    # The +0x60 sub-object was initialised by arena_init.
    sub = arena + 0x60
    check(mem.read_qword(sub) == m.EMBEDDED_ARENA_VTABLE,
          "embedded Arena vtable")
    check(mem.read_qword(sub + 0x810) == m.huge_align(owner18),
          "aligned block size at +0x870")
    check(mem.read_qword(sub + 0x820) == 8, "pair A size 8")
    check(mem.read_qword(sub + 0x870) == 8, "pair B size 8")
    check(mem.read_qword(sub + 0x8D0) == 0x800, "stat +0x930 = 0x800")
    check(mem.read_qword(sub + 0x8E0) == 0x800, "stat +0x940 = 0x800")
    # Stat shadow copies the primaries; lock byte clear.
    check(mem.read_qword(arena + 0x958) == 0, "shadow +0x958 = 0")
    check(mem.read_qword(arena + 0x960) == 0x800, "shadow +0x960 = 0x800")
    check(mem.read_qword(arena + 0x968) == 0x800, "shadow +0x968 = 0x800")
    check(mem.read_byte(arena + 0x950) == 0, "lock byte clear")
    # The sub-init kept &owner+0x80 at arena+0x948.
    check(mem.read_qword(arena + 0x948) == arena + 0x80,
          "sub-init kept the header address")
    # arena_stat (slot 4) returns the aligned block size.
    check(m.arena_stat(mem, arena) == m.huge_align(owner18),
          "slot 4 returns aligned size")


def test_arena_subinit_rounding():
    mem = m.Memory()
    arena = mem.alloc(0x9B0)
    # rsi = 0x1000 -> aligned 0x1000; rcx = 0x100 divides it exactly.
    m.arena_subinit(mem, arena + 0x60, 0x1000, 0, 0x100)
    check(mem.read_qword(arena + 0x938) == 0x1000,
          "rounded size exact multiple stays")
    # rsi = 0x1001 -> aligned 0x1010; rcx = 0x1000 -> rounds to 0x2000.
    mem2 = m.Memory()
    arena2 = mem2.alloc(0x9B0)
    m.arena_subinit(mem2, arena2 + 0x60, 0x1001, 0, 0x1000)
    check(mem2.read_qword(arena2 + 0x938) == 0x2000,
          "rounded size rounds up to 0x2000")
    # rcx = 0 -> +0x938 stays 0 (the rounding branch is skipped).
    mem3 = m.Memory()
    arena3 = mem3.alloc(0x9B0)
    m.arena_subinit(mem3, arena3 + 0x60, 0x1010, 0, 0)
    check(mem3.read_qword(arena3 + 0x938) == 0, "rcx 0 -> +0x938 stays 0")
    # rcx >= aligned -> +0x938 stays rcx.
    mem4 = m.Memory()
    arena4 = mem4.alloc(0x9B0)
    m.arena_subinit(mem4, arena4 + 0x60, 0x1010, 0, 0x2000)
    check(mem4.read_qword(arena4 + 0x938) == 0x2000,
          "rcx >= aligned -> +0x938 stays rcx")


def test_block_pairs():
    mem = m.Memory()
    arena = mem.alloc(0x9B0)
    m.arena_subinit(mem, arena + 0x60, 0x8000, 0, 0x40)
    sub = arena + 0x60
    a = mem.read_qword(sub + 0x818)
    b = mem.read_qword(a + 24)
    check(mem.read_qword(sub + 0x828) == b, "pair A base slot")
    check(mem.read_qword(sub + 0x830) == b, "pair A base slot copy")
    check(mem.read_qword(sub + 0x838) == a + 24, "pair A link slot")
    check(mem.read_qword(sub + 0x840) == b + 0x200, "pair A end slot")
    check(mem.read_qword(sub + 0x848) == b, "pair A second base")
    check(mem.read_qword(sub + 0x858) == a + 24, "pair A second link")
    check(mem.read_qword(sub + 0x860) == b + 0x200, "pair A second end")
    c = mem.read_qword(sub + 0x868)
    d = mem.read_qword(c + 24)
    check(mem.read_qword(sub + 0x878) == d, "pair B base slot")
    check(mem.read_qword(sub + 0x888) == c + 24, "pair B link slot")
    check(mem.read_qword(sub + 0x890) == d + 0x200, "pair B end slot")
    check(mem.read_qword(sub + 0x898) == d, "pair B second base")
    check(mem.read_qword(sub + 0x8A8) == c + 24, "pair B second link")
    check(mem.read_qword(sub + 0x8B0) == d + 0x200, "pair B second end")
    check(mem.read_qword(sub + 0x8B8) == 0, "pair B tail zero")
    check(mem.read_qword(sub + 0x8C0) == sub + 0x810,
          "+0x920 points at the aligned-size slot")
    check(mem.read_qword(sub + 0x8C8) == sub + 0x10,
          "+0x928 points at arena+0x70")


def test_small_init():
    mem = m.Memory()
    addr = mem.alloc(0x18)
    m.small_init(mem, addr, 0xDEADBEEF)
    check(mem.read_qword(addr) == 0xDEADBEEF, "header ptr")
    check(mem.read_qword(addr + 0x08) == 0, "header +0x08 zero")
    check(mem.read_u16(addr + 0x10) == 0, "header +0x10 zero")


def test_factory_product():
    mem = m.Memory()
    owner = mem.alloc(0x2000)
    arena = owner + 0xA0
    factory = mem.alloc(0x28)
    m.build_holder(mem, factory, 0x1122334455667788)
    alloc = m.ArenaAllocator(mem)
    product = m.skiplist_rep_factory(mem, factory, owner, arena, 0x77,
                                     alloc)
    check(mem.read_qword(product) == m.SKIPLIST_REP_VTABLE,
          "product vtable")
    check(mem.read_qword(product + 0x08) == arena, "product +0x08 arena")
    check(mem.read_qword(product + 0x18) == arena, "product +0x18 arena")
    check(mem.read_qword(product + 0x10) == m.SKIPLIST_REP_QWORD10,
          "product +0x10 qword")
    check(mem.read_u16(product + 0x10) == 12, "product count 12")
    check(mem.read_u16(product + 0x12) == 4, "product +0x12 is 4")
    check(mem.read_u32(product + 0x14) == 0x20000000, "product +0x14")
    check(mem.read_qword(product + 0x20) == owner, "product +0x20 owner")
    check(mem.read_u32(product + 0x30) == 1, "product +0x30 is 1")
    check(mem.read_qword(product + 0x40) == owner, "product +0x40 owner")
    check(mem.read_qword(product + 0x48) == 0x77, "product +0x48 rcx")
    check(mem.read_qword(product + 0x50) == 0x1122334455667788,
          "product +0x50 factory a")
    check(len(alloc.calls) == 2, "two arena allocations")
    check(alloc.calls[0][1] == 0x60, "first alloc size 0x60")
    check(alloc.calls[1][1] == 0xE8, "second alloc size 0xE8")
    alloc1 = alloc.calls[0][3]
    alloc2 = alloc.calls[1][3]
    check(mem.read_qword(product + 0x28) == alloc1 + 0x58,
          "product +0x28 = alloc1+0x58")
    check(mem.read_qword(product + 0x38) == alloc2,
          "product +0x38 = alloc2")
    for i in range(12):
        check(mem.read_qword(alloc1 + i * 8) == 0,
              "alloc1 qword %d zeroed" % i)
    check(mem.read_u32(alloc2) == 0, "alloc2 +0x00 zero")
    check(mem.read_qword(alloc2 + 0x08) == alloc2 + 0x18,
          "alloc2 +0x08 = self+0x18")
    check(mem.read_qword(alloc2 + 0x10) == alloc2 + 0x80,
          "alloc2 +0x10 = self+0x80")


def test_owner_end_to_end():
    mem = m.Memory()
    owner = mem.alloc(0x2000)
    arena = owner + 0xA0
    factory = mem.alloc(0x28)
    m.build_holder(mem, factory, 0xAABBCCDDEEFF0011)
    alloc = m.ArenaAllocator(mem)
    # The real factory's slot 20 is the canonical forwarder.
    check(m.owner_dispatch(m.CANONICAL_SLOT20, factory) == "slot19",
          "canonical slot 20 -> slot 19")
    check(m.owner_dispatch(0x5F04D91, factory) == "slot20",
          "other slot 20 -> slot 20 itself")
    product_a, product_b, frees = m.owner_build_products(
        mem, factory, owner, arena, 0x55, 0x66, alloc)
    check(mem.read_qword(owner + 0xA50) == product_a,
          "product A at owner+0xa50")
    check(mem.read_qword(owner + 0xA58) == product_b,
          "product B at owner+0xa58")
    check(product_a != product_b, "two distinct products")
    # Product A keeps the real factory's `a`; product B keeps 0
    # (the transient holder was built with a = 0).
    check(mem.read_qword(product_a + 0x50) == 0xAABBCCDDEEFF0011,
          "product A keeps factory a")
    check(mem.read_qword(product_b + 0x50) == 0,
          "product B keeps transient holder a = 0")
    # Product A passes the virtual-call rcx; product B passes 0.
    check(mem.read_qword(product_a + 0x48) == 0x55,
          "product A keeps virtual rcx")
    check(mem.read_qword(product_b + 0x48) == 0,
          "product B rcx is 0")
    check(len(alloc.calls) == 4, "four allocations total")
    # The teardown freed the 23-byte heap key and the 0x30 buffer.
    check(len(frees) == 2, "two frees from the holder teardown")
    check(frees[0][1] == len(m.HOLDER_RECORD_KEY) + 1,
          "heap key freed with len+1")
    check(frees[1][1] == 0x30, "vector buffer freed (one record)")


def test_holder_teardown_vtable():
    mem = m.Memory()
    holder = mem.alloc(0x28)
    m.build_holder(mem, holder, 0)
    check(mem.read_qword(holder) == m.SKIPLIST_FACTORY_VTABLE,
          "holder vtable before teardown")
    m.destroy_holder(mem, holder)
    check(mem.read_qword(holder) == m.TEARDOWN_VTABLE,
          "holder vtable reset to Configurable")


def test_vtable_slot_counts():
    total = sum(len(s) for s in m.VTABLE_SLOTS.values())
    check(total == 23 + 23 + 5 + 5 + 14, "vtable slot total 70")
    check(m.VTABLE_SLOTS[m.SKIPLIST_FACTORY_VTABLE][0x98]
          == m.FACTORY_ADDR, "factory is SkipListFactory slot 19")
    check(m.VTABLE_SLOTS[m.SKIPLIST_FACTORY_VTABLE][0xA0]
          == m.CANONICAL_SLOT20, "slot 20 is the canonical forwarder")
    check(m.VTABLE_SLOTS[m.CONCURRENT_ARENA_VTABLE][0x18]
          == m.ARENA_SLOT3, "arena slot 3 is AllocateAligned")
    check(m.VTABLE_SLOTS[m.CONCURRENT_ARENA_VTABLE][0x10]
          == m.ARENA_SLOT2, "arena slot 2 is Allocate")
    check(m.VTABLE_SLOTS[m.SKIPLIST_REP_VTABLE][0x98] == 0x5F04D80,
          "SkipListRep slot 19 forwards to slot 18")
    check(m.VTABLE_SLOTS[m.EMBEDDED_ARENA_VTABLE][0x18]
          == m.ARENA_SLOW_PATH, "embedded Arena slot 3 is the slow path")


def main():
    test_huge_align()
    test_shard_bits_and_block_size()
    test_arena_init()
    test_arena_subinit_rounding()
    test_block_pairs()
    test_small_init()
    test_factory_product()
    test_owner_end_to_end()
    test_holder_teardown_vtable()
    test_vtable_slot_counts()
    print("all %d checks passed" % CHECKS)


if __name__ == "__main__":
    main()
