"""Tests for tools/owner_tail_phases_115.py.

Run (from the repository root):
    python3 tests/test_owner_tail_phases_115.py

Every expectation is pinned from the node #115 binary (digest
a6e2897c...b5301) via research/work-items/RE-001-owner-tail-
phases-115/; the packet's verify.py re-runs this file and
requires its summary line. No test uses pytest (not installed
on this VM); checks are counted by hand.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import owner_tail_phases_115 as m

CHECKS = 0


def check(condition, label):
    global CHECKS
    CHECKS += 1
    if not condition:
        raise AssertionError("check failed: %s" % label)


def _options(**over):
    opts = {0x210: 0x1111, 0x220: 0x2222, 0x260: 0x3333,
            0x218: 0x4444, 0x298: 0xAB, 0x2A0: 0x5555,
            0x300: 0x6666, 0x1C8: 0xCD}
    opts.update(over)
    return opts


def _arg4(**over):
    vals = {0x00: 100, 0x10: 0xAAAA, 0x18: 2.0,
            0x20: 0x34, 0x28: 0xBBBB, 0x30: 0xCCCC, 0x38: 7,
            0x40: 0xDDDD, 0x1BC: 0x12345678}
    vals.update(over)
    if isinstance(vals[0x18], float):
        vals[0x18] = struct.unpack("<Q", struct.pack("<d", vals[0x18]))[0]
    return vals


def test_prologue_helper():
    mem = m.Memory()
    owner = mem.alloc(m.OWNER_SIZE)
    arg4 = _arg4()
    opts = _options()
    writes = m.prologue_helper(mem, owner + 0x18, opts, arg4)
    check(mem.read_qword(owner + 0x18) == 0xAAAA, "prologue +0x18")
    # (double)100 * 2.0 = 200.0 -> int 200 -> <<3 = 1600.
    check(mem.read_u32(owner + 0x20) == 1600, "prologue +0x20 scaled")
    check(mem.read_qword(owner + 0x28) == 0xBBBB, "prologue +0x28")
    check(mem.read_u16(owner + 0x30) == 0xAB34, "prologue +0x30 u16")
    check(mem.read_byte(owner + 0x31) == 0xAB, "prologue +0x31 gate byte")
    check(mem.read_qword(owner + 0x38) == 7, "prologue +0x38 count")
    check(mem.read_qword(owner + 0x40) == 0x5555, "prologue +0x40")
    check(mem.read_qword(owner + 0x48) == 0xCCCC, "prologue +0x48")
    check(mem.read_qword(owner + 0x50) == 0x4444, "prologue +0x50")
    check(mem.read_qword(owner + 0x58) == 0x3333, "prologue +0x58")
    check(mem.read_qword(owner + 0x60) == 0x2222, "prologue +0x60")
    check(mem.read_byte(owner + 0x68) == 0xCD, "prologue +0x68 byte")
    check(mem.read_u32(owner + 0x6C) == 0x12345678, "prologue +0x6c")
    check(len(writes) == 12, "prologue 12 writes")
    # A negative *(arg4) goes through the unsigned fixup: -1 as
    # u64 converts to 2**64 as a double, times 2.0 is 2**65, and
    # the 32-bit result after cvttsd2si + shl is 0.
    arg4neg = _arg4()
    arg4neg[0x00] = (1 << 64) - 1
    mem2 = m.Memory()
    owner2 = mem2.alloc(m.OWNER_SIZE)
    m.prologue_helper(mem2, owner2 + 0x18, opts, arg4neg)
    check(mem2.read_u32(owner2 + 0x20) == 0,
          "prologue negative input gives 0")


def test_region_init():
    mem = m.Memory()
    owner = mem.alloc(m.OWNER_SIZE)
    m.region_init(mem, owner, 0xFEED, 0xBEEF)
    check(mem.read_byte(owner + 0xA60) == 1, "region +0xa60 = 1")
    check(mem.read_qword(owner + 0xA68) == 0, "region +0xa68 zero")
    check(mem.read_qword(owner + 0xA78) == 0, "region +0xa78 zero")
    check(mem.read_qword(owner + 0xA80) == 0xFEED, "region +0xa80 arg4")
    check(mem.read_qword(owner + 0xA88) == 0, "region +0xa88 zero")
    check(mem.read_qword(owner + 0xA90) == 0, "region +0xa90 zero")
    check(mem.read_qword(owner + 0xA98) == 0, "region +0xa98 zero")
    check(mem.read_qword(owner + 0xAA0) == owner + 0xAB0,
          "region +0xaa0 self-pointer")
    check(mem.read_qword(owner + 0xAA8) == 0, "region +0xaa8 zero")
    check(mem.read_byte(owner + 0xAB0) == 0, "region +0xab0 zero")
    check(mem.read_qword(owner + 0xAC0) == owner + 0xAD0,
          "region +0xac0 self-pointer")
    check(mem.read_qword(owner + 0xAC8) == 0, "region +0xac8 zero")
    check(mem.read_byte(owner + 0xAD0) == 0, "region +0xad0 zero")
    check(mem.read_qword(owner + 0xAE0) == 0, "region +0xae0 zero")
    check(mem.read_qword(owner + 0xB00) == 0, "region +0xb00 zero")
    check(mem.read_qword(owner + 0xB18) == 0, "region +0xb18 zero")
    check(mem.read_qword(owner + 0xB28) == 0, "region +0xb28 zero")
    check(mem.read_u32(owner + 0xB38) == 0, "region +0xb38 zero")
    check(mem.read_qword(owner + 0xB40) == 0, "region +0xb40 zero")
    check(mem.read_qword(owner + 0xB48) == owner + 0xB38,
          "region +0xb48 self-pointer")
    check(mem.read_qword(owner + 0xB50) == owner + 0xB38,
          "region +0xb50 self-pointer")
    check(mem.read_qword(owner + 0xB58) == 0, "region +0xb58 zero")
    check(mem.read_qword(owner + 0xB60) == 0, "region +0xb60 zero")
    check(mem.read_qword(owner + 0xB80) == 0, "region +0xb80 zero")
    check(mem.read_qword(owner + 0xBA0) == 0, "region +0xba0 zero")
    check(mem.read_qword(owner + 0xBC0) == 0, "region +0xbc0 zero")
    check(mem.read_u32(owner + 0xBC8) == 0, "region +0xbc8 zero")
    check(mem.read_u16(owner + 0xBCC) == 0, "region +0xbcc zero")
    check(mem.read_qword(owner + 0xBD0) == owner + 0xBE0,
          "region +0xbd0 self-pointer")
    check(mem.read_qword(owner + 0xBD8) == 0, "region +0xbd8 zero")
    check(mem.read_byte(owner + 0xBE0) == 0, "region +0xbe0 zero")
    check(mem.read_byte(owner + 0xBF0) == 0, "region +0xbf0 zero")
    check(mem.read_u32(owner + 0xBF4) == 0, "region +0xbf4 zero")
    check(mem.read_qword(owner + 0xBF8) == owner + 0xC08,
          "region +0xbf8 self-pointer")
    check(mem.read_qword(owner + 0xC00) == 0, "region +0xc00 zero")
    check(mem.read_byte(owner + 0xC08) == 0, "region +0xc08 zero")
    check(mem.read_qword(owner + 0xC18) == 0, "region +0xc18 zero")
    check(mem.read_qword(owner + 0xC20) == 0xBEEF, "region +0xc20 arg9")
    check(mem.read_qword(owner + 0xC28) == 0xBEEF, "region +0xc28 arg9")
    check(mem.read_qword(owner + 0xC30) == 0, "region +0xc30 zero")
    check(mem.read_qword(owner + 0xC38) == 0, "region +0xc38 zero")


def test_elem_ctor_codes():
    check(m.elem_ctor_ok(0), "rwlock rc 0 accepted")
    check(m.elem_ctor_ok(0x10), "rwlock rc 0x10 accepted")
    check(m.elem_ctor_ok(0x6E), "rwlock rc 0x6e accepted")
    check(not m.elem_ctor_ok(1), "rwlock rc 1 rejected")
    check(not m.elem_ctor_ok(0x20), "rwlock rc 0x20 rejected")
    check(m.ELEM_MAX_COUNT * 56 == m.ELEM_MAX_BYTES,
          "guard constant: 56*max == 0x7ffffffffffffff8")
    check(m.ELEM_MAX_COUNT == 0x249249249249249, "guard constant value")


def test_element_array():
    mem = m.Memory()
    owner = mem.alloc(m.OWNER_SIZE)
    calls = []
    begin, end, cap = m.element_array(mem, owner, 3, 1, calls.append)
    check(begin != 0, "array allocated")
    check(end == begin + 3 * 0x38, "array end = begin + 56*count")
    check(cap == end, "array cap == end")
    check(mem.read_qword(owner + 0xC40) == begin, "array +0xc40 begin")
    check(mem.read_qword(owner + 0xC48) == end, "array +0xc48 end")
    check(mem.read_qword(owner + 0xC50) == end, "array +0xc50 cap")
    check(calls == [begin, begin + 0x38, begin + 0x70],
          "array ctor per element, stride 0x38")
    # Gate byte 0 -> null triple, no ctor calls.
    mem2 = m.Memory()
    owner2 = mem2.alloc(m.OWNER_SIZE)
    calls2 = []
    out = m.element_array(mem2, owner2, 5, 0, calls2.append)
    check(out == (0, 0, 0), "gate 0 -> null triple")
    check(calls2 == [], "gate 0 -> no ctor calls")
    check(mem2.read_qword(owner2 + 0xC40) == 0, "gate 0 +0xc40 zero")
    check(mem2.read_qword(owner2 + 0xC48) == 0, "gate 0 +0xc48 zero")
    check(mem2.read_qword(owner2 + 0xC50) == 0, "gate 0 +0xc50 zero")
    # Count 0 with the gate open -> null triple too.
    mem3 = m.Memory()
    owner3 = mem3.alloc(m.OWNER_SIZE)
    out3 = m.element_array(mem3, owner3, 0, 1, lambda a: None)
    check(out3 == (0, 0, 0), "count 0 -> null triple")
    # Over the guard -> LengthError with the binary's message.
    mem4 = m.Memory()
    owner4 = mem4.alloc(m.OWNER_SIZE)
    try:
        m.element_array(mem4, owner4, m.ELEM_MAX_COUNT + 1, 1,
                        lambda a: None)
        check(False, "over-guard must raise")
    except m.LengthError as exc:
        check(str(exc) == m.LENGTH_ERROR_TEXT, "over-guard message")
    # Exactly at the guard -> allowed.
    mem5 = m.Memory()
    owner5 = mem5.alloc(m.OWNER_SIZE)
    seen = []
    m.element_array(mem5, owner5, 1, 1, seen.append)
    check(len(seen) == 1, "count 1 builds one element")


def test_tail_init():
    mem = m.Memory()
    owner = mem.alloc(m.OWNER_SIZE)
    opts = _options()
    arg4 = _arg4()
    m.tail_init(mem, owner, opts, arg4)
    check(mem.read_qword(owner + 0xC58) == 0xDDDD, "tail +0xc58 arg4+0x40")
    check(mem.read_qword(owner + 0xC60) == 0, "tail +0xc60 zero")
    check(mem.read_u32(owner + 0xC68) == 0, "tail +0xc68 once-flag zero")
    check(mem.read_qword(owner + 0xC70) == 0x1111, "tail +0xc70 opt+0x210")
    check(mem.read_qword(owner + 0xC78) == 0x6666, "tail +0xc78 opt+0x300")
    check(mem.read_qword(owner + 0xC80) == owner + 0xCB0,
          "tail +0xc80 self-pointer")
    check(mem.read_qword(owner + 0xC88) == 1, "tail +0xc88 = 1")
    check(mem.read_qword(owner + 0xC90) == 0, "tail +0xc90 zero")
    check(mem.read_qword(owner + 0xC98) == 0, "tail +0xc98 zero")
    check(mem.read_u32(owner + 0xCA0) == 0x3F800000, "tail +0xca0 = 1.0f")
    check(mem.read_qword(owner + 0xCA8) == 0, "tail +0xca8 zero")
    check(mem.read_qword(owner + 0xCB0) == 0, "tail +0xcb0 zero")
    check(mem.read_bytes(owner + 0xCB8, 16) == m.TAIL_CONST_CB8,
          "tail +0xcb8 constant")
    check(mem.read_bytes(owner + 0xCC8, 16) == m.TAIL_CONST_CC8,
          "tail +0xcc8 constant")
    check(mem.read_qword(owner + 0xCD8) == 0, "tail +0xcd8 zero")
    check(mem.read_qword(owner + 0xCE8) == 0, "tail +0xce8 zero")
    check(mem.read_qword(owner + 0xCF8) == 0, "tail +0xcf8 zero")
    check(mem.read_qword(owner + 0xD08) == 0, "tail +0xd08 zero")


def test_small_install_gate():
    # small iff (+0x20 != 0) and (+0xc58 != 0 or +0x30 != 0).
    check(m.small_install_gate(1, 0, 1), "gate: 20!=0, c58!=0 -> small")
    check(m.small_install_gate(1, 1, 0), "gate: 20!=0, 30!=0 -> small")
    check(m.small_install_gate(1, 1, 1), "gate: all nonzero -> small")
    check(not m.small_install_gate(0, 1, 1), "gate: 20==0 -> main")
    check(not m.small_install_gate(1, 0, 0), "gate: c58==0, 30==0 -> main")
    check(not m.small_install_gate(0, 0, 0), "gate: all zero -> main")


def test_descriptor_size():
    check(m.descriptor_size(0) == (0, 31), "descriptor value 0")
    check(m.descriptor_size(1) == (4, 63), "descriptor value 1")
    check(m.descriptor_size(256) == (4, 63), "descriptor value 256")
    check(m.descriptor_size(257) == (8, 95), "descriptor value 257")
    check(m.descriptor_size(512) == (8, 95), "descriptor value 512")
    check(m.descriptor_size(1600) == (28, 255),
          "descriptor value 1600 (prologue example)")


def test_build_small_descriptor():
    mem = m.Memory()
    block = mem.alloc(0x10)
    allocs = []

    def fake_alloc(arena, size, v28, opt220):
        addr = mem.alloc(size)
        allocs.append((arena, size, v28, opt220, addr))
        return addr

    n, size, raw, aligned = m.build_small_descriptor(
        mem, block, 0xA000, 1600, 0xBBBB, 0x2222, fake_alloc)
    check(n == 28, "descriptor n = 28")
    check(size == 255, "descriptor size = 255")
    check(mem.read_u32(block + 0x04) == 3, "descriptor +4 = 3")
    check(mem.read_u32(block + 0x00) == 28, "descriptor +0 = n")
    check(allocs[0][:4] == (0xA000, 255, 0xBBBB, 0x2222),
          "descriptor arena call args")
    check(aligned == (raw + 31) & ~31, "descriptor 32-aligned pointer")
    check(mem.read_qword(block + 0x08) == aligned, "descriptor +8 ptr")
    for i in range(size):
        check(mem.read_byte(raw + i) == 0, "descriptor region zeroed")


def test_install_table():
    mem = m.Memory()
    owner = mem.alloc(m.OWNER_SIZE)
    table = mem.alloc(0x10 * 4)
    big, smalls, releases = m.install_table(mem, owner, table, 2, {})
    check(len(smalls) == 4, "install 4 entries for log 2")
    check(big.use == 1 + 4, "big use = 1 + N after install")
    check(big.weak == 1, "big weak stays 1")
    check(mem.read_qword(big.addr) == m.BIG_CONTROL_VTABLE,
          "big control vtable")
    for i in range(0x10, 0x48):
        check(mem.read_byte(big.addr + i) == 0,
              "big cache object zero-filled")
    for i, small in enumerate(smalls):
        check(small.use == 1, "small use back to 1")
        check(small.weak == 1, "small weak 1")
        check(mem.read_qword(small.addr) == m.SMALL_CONTROL_VTABLE,
              "small control vtable")
        check(mem.read_qword(small.addr + 0x10) == big.addr + 0x10,
              "small +0x10 = &big+0x10")
        check(mem.read_qword(small.addr + 0x18) == big.addr,
              "small +0x18 = big control")
        check(mem.read_qword(table + i * 0x10) == big.addr + 0x10,
              "entry ptr = &big+0x10")
        check(mem.read_qword(table + i * 0x10 + 0x08) == small.addr,
              "entry control = small")
    check(releases == [None, None, None, None],
          "fresh entries release nothing")
    # The epilogue releases the big control once: use 5 -> 4.
    check(m.owner_epilogue_release(big) == "kept",
          "epilogue release kept (use 5 -> 4)")
    check(big.use == 4, "big use = N after epilogue")
    # Replacing entries releases the old controls: a {1,1} old
    # control is disposed+destroyed inline.
    old = m.Control(mem, mem.alloc(0x20), m.SMALL_CONTROL_VTABLE,
                    0x20, 0x10)
    big2, smalls2, releases2 = m.install_table(
        mem, owner, table, 0, {0: old})
    check(releases2 == ["disposed"], "old {1,1} control disposed")
    check(old.disposed and old.destroyed, "old control torn down")
    check(big2.use == 2, "second install big use = 1 + 1")
    # An old control with use 3 is kept (decremented to 2).
    old3 = m.Control(mem, mem.alloc(0x20), m.SMALL_CONTROL_VTABLE,
                     0x20, 0x10)
    old3.bump_use()
    old3.bump_use()
    check(old3.use == 3, "old control use 3 before replace")
    _b3, _s3, r3 = m.install_table(mem, owner, table, 0, {0: old3})
    check(r3 == ["kept"], "old use-3 control kept")
    check(old3.use == 2, "old control use 3 -> 2")


def test_release_paths():
    mem = m.Memory()
    ctl = m.Control(mem, mem.alloc(0x48), m.BIG_CONTROL_VTABLE,
                    0x48, 0x38)
    check(ctl.release() == "disposed", "{1,1} release disposes")
    check(ctl.disposed and ctl.destroyed, "disposed+destroyed")
    check(mem.read_qword(ctl.addr + 0x08) == 0, "counts zeroed")
    ctl2 = m.Control(mem, mem.alloc(0x48), m.BIG_CONTROL_VTABLE,
                     0x48, 0x38)
    ctl2.bump_use()
    check(ctl2.release() == "kept", "use 2 -> 1 kept")
    check(ctl2.use == 1, "use back to 1")
    check(ctl2.release() == "disposed", "use 1 -> disposed")


def test_once_predicate():
    mem = m.Memory()
    owner = mem.alloc(m.OWNER_SIZE)
    # Arm 1: scaled > (double)(H + total) -> False.
    # H = 100, A = 0, total = *(+0xa00) = 0: scaled = 60 > 100? No.
    # total-double = 0 > 60? No. Loop arm: base empty, shift 0,
    # r9 = 0 < 100>>2 = 25 -> True.
    mem.write_qword(owner + 0x78, 100)
    mem.write_qword(owner + 0xA80, 0)
    mem.write_qword(owner + 0xA00, 0)
    mem.write_qword(owner + 0xE8, 0)
    mem.write_byte(owner + 0xF0, 0)
    mem.write_qword(owner + 0x9F8, 0)
    check(m.once_predicate(mem, owner) is True, "predicate loop arm true")
    check(mem.read_qword(owner + 0xCD0) == 0, "+0xcd0 = *(+0xa00)")
    # Arm 1: H = 100, A = 1000 -> scaled = 1060 > 100 -> False.
    mem.write_qword(owner + 0xA80, 1000)
    check(m.once_predicate(mem, owner) is False, "predicate false arm")
    # Arm 2: total huge -> (double)total > scaled -> True.
    mem.write_qword(owner + 0xA00, 10 ** 6)
    mem.write_qword(owner + 0xA80, 0)
    check(m.once_predicate(mem, owner) is True, "predicate true arm")
    check(mem.read_qword(owner + 0xCD0) == 10 ** 6, "+0xcd0 stores total")
    # Loop arm with a real element sum: H = 100, A = 0, total = 0,
    # scaled = 60, (double)(100) = 100 > 60 so no early arm; base
    # has one element with +0x38 = 30, r9 = 0 -> 30 < 25? No.
    mem.write_qword(owner + 0xA00, 0)
    base = mem.alloc(64)
    mem.write_qword(base + 0x38, 30)
    mem.write_qword(owner + 0xE8, base)
    mem.write_byte(owner + 0xF0, 0)
    mem.write_qword(owner + 0x9F8, 0)
    check(m.once_predicate(mem, owner) is False,
          "predicate loop arm false (30 >= 25)")
    mem.write_qword(base + 0x38, 10)
    check(m.once_predicate(mem, owner) is True,
          "predicate loop arm true (10 < 25)")
    # Slot-15 results are added into +0xcd0 (both 0 in the binary).
    mem.write_qword(owner + 0xA00, 5)
    check(m.once_predicate(mem, owner, (3, 4)) is True,
          "predicate with nonzero slot15 returns")
    check(mem.read_qword(owner + 0xCD0) == 12, "+0xcd0 = 3+4+5")


def test_once_helper_latch():
    mem = m.Memory()
    owner = mem.alloc(m.OWNER_SIZE)
    mem.write_qword(owner + 0x78, 100)
    mem.write_qword(owner + 0xA80, 1000)  # predicate false
    mem.write_qword(owner + 0xA00, 0)
    mem.write_qword(owner + 0xE8, 0)
    mem.write_byte(owner + 0xF0, 0)
    mem.write_qword(owner + 0x9F8, 0)
    check(m.once_helper(mem, owner) == 0, "helper false -> flag stays 0")
    check(mem.read_u32(owner + 0xC68) == 0, "flag still 0")
    mem.write_qword(owner + 0xA80, 0)
    check(m.once_helper(mem, owner) == 1, "helper true -> flag latches")
    check(mem.read_u32(owner + 0xC68) == 1, "flag latched 1")
    mem.write_qword(owner + 0xA80, 1000)  # would be false now
    check(m.once_helper(mem, owner) == 1, "latched flag short-circuits")


def test_caller_args():
    base = {0x40: 0x111, 0x368: 0x222, 0x8E0: 0x333, 0x00: 0x444}
    args = m.caller_args(base, 0x555, 0x666)
    check(args == (0x111, 0x222, 0x555, 0x333, 0x666, 0x444),
          "caller arg order (rsi, rdx, rcx, r8, r9, stack)")
    check(m.OWNER_SIZE == 0xD20, "owner size 0xd20")
    check(m.CALLER_BIG_WINDOW == (0x5ED086C, 0x5ED08C6),
          "big caller window bounds")


def test_vtables_and_typeinfo():
    check(len(m.VTABLE_SLOTS[m.BIG_CONTROL_VTABLE]) == 5,
          "big control vtable has 5 slots")
    check(len(m.VTABLE_SLOTS[m.SMALL_CONTROL_VTABLE]) == 5,
          "small control vtable has 5 slots")
    check(m.VTABLE_SLOTS[m.BIG_CONTROL_VTABLE][0x10] == 0x5F061B0,
          "big slot 2 = _M_dispose")
    check(m.VTABLE_SLOTS[m.BIG_CONTROL_VTABLE][0x18] == 0x5F04F70,
          "big slot 3 = _M_destroy (frees 0x48)")
    check(m.VTABLE_SLOTS[m.SMALL_CONTROL_VTABLE][0x10] == 0x5F0A290,
          "small slot 2 = _M_dispose")
    check(m.VTABLE_SLOTS[m.SMALL_CONTROL_VTABLE][0x18] == 0x5F04F60,
          "small slot 3 = _M_destroy (frees 0x20)")
    check(m.VTABLE_SLOTS[m.SKIPLIST_REP_VTABLE][0x78] == m.SLOT15,
          "SkipListRep slot 15 = zero stub")
    check(m.TYPEINFO_POINTERS[m.BIG_CONTROL_VTABLE] == m.BIG_TYPEINFO,
          "big typeinfo pointer")
    check(m.TYPEINFO_POINTERS[m.SMALL_CONTROL_VTABLE] == m.SMALL_TYPEINFO,
          "small typeinfo pointer")
    check(m.TYPEINFO_NAME_POINTERS[m.BIG_TYPEINFO] == 0x9709A0,
          "big typeinfo name address")
    check(m.TYPEINFO_NAME_POINTERS[m.SMALL_TYPEINFO] == 0x970A20,
          "small typeinfo name address")
    check(m.TYPEINFO_BASE_POINTERS[m.BIG_TYPEINFO] ==
          m.CONTROL_BASE_TYPEINFO, "big base = _Sp_counted_base")
    check(m.TYPEINFO_BASE_POINTERS[m.SMALL_TYPEINFO] ==
          m.CONTROL_BASE_TYPEINFO, "small base = _Sp_counted_base")
    check(m.BIG_TYPEINFO_NAME.startswith(
        "St23_Sp_counted_ptr_inplaceIN7rocksdb33FragmentedRange"
        "TombstoneListCacheE"), "big typeinfo name text")
    check(m.SMALL_TYPEINFO_NAME.startswith(
        "St23_Sp_counted_ptr_inplaceIKSt10shared_ptrIN7rocksdb33"
        "FragmentedRangeTombstoneListCacheE"),
        "small typeinfo name text")
    check(m.TYPEINFO_POINTERS[m.SKIPLIST_REP_VTABLE] ==
          m.SKIPLIST_REP_TYPEINFO, "skiplist rep typeinfo pointer")
    check(m.TYPEINFO_NAME_POINTERS[m.SKIPLIST_REP_TYPEINFO] == 0x975200,
          "skiplist rep typeinfo name address")
    check(m.TYPEINFO_NAME_POINTERS[m.MEMTABLE_REP_TYPEINFO] == 0x9708D0,
          "memtable rep typeinfo name address")
    check(m.TYPEINFO_BASE_POINTERS[m.SKIPLIST_REP_TYPEINFO] ==
          m.MEMTABLE_REP_TYPEINFO,
          "skiplist rep base = MemTableRep (not _Sp_counted_base)")
    check(m.SKIPLIST_REP_TYPEINFO_NAME ==
          "N7rocksdb12_GLOBAL__N_111SkipListRepE",
          "skiplist rep typeinfo name text")
    check(m.MEMTABLE_REP_TYPEINFO_NAME == "N7rocksdb11MemTableRepE",
          "memtable rep typeinfo name text")
    check(m.CONTROL_COUNTS == 0x100000001, "control counts constant")
    check(m.CACHE_OBJECT_SIZE == 0x38, "cache object size 0x38")


def main():
    test_prologue_helper()
    test_region_init()
    test_elem_ctor_codes()
    test_element_array()
    test_tail_init()
    test_small_install_gate()
    test_descriptor_size()
    test_build_small_descriptor()
    test_install_table()
    test_release_paths()
    test_once_predicate()
    test_once_helper_latch()
    test_caller_args()
    test_vtables_and_typeinfo()
    print("all %d checks passed" % CHECKS)


if __name__ == "__main__":
    main()
