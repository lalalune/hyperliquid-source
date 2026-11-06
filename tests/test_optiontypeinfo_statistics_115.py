"""Tests for the node #115 AsCustomSharedPtr<Statistics> model.

Target-grounded expectations from research/work-items/
RE-001-optiontypeinfo-statistics-115: the builder's field layout,
the manager's op dispatch, the invoker's "id" fast path vs forward
path, and the counted release rule. Run: python3 tests/test_optiontypeinfo_statistics_115.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import optiontypeinfo_statistics_115 as m

CHECKS = []


def check(name, cond):
    CHECKS.append((name, bool(cond)))
    if not cond:
        print("FAILED:", name)


def test_builder_layout():
    rec = m.build_record(0, 3, 1)
    check("record size", len(rec) == 24)
    check("offset field", rec["+0x00"] == 0)
    check("reserved +0x08 zero", rec["+0x08"] == 0)
    check("reserved +0x10 zero", rec["+0x10"] == 0)
    check("manager hook", rec["+0x18"] == 0x606FA80)
    check("invoker hook", rec["+0x20"] == 0x60780A0)
    check("reserved +0x28 zero", rec["+0x28"] == 0)
    check("reserved +0xa0 zero", rec["+0xa0"] == 0)
    check("type is 22", rec["+0xa8"] == 22)
    check("verification field", rec["+0xac"] == 3)
    check("flags field", rec["+0xb0"] == 1)
    # The installing call site (0x6074d8f) uses offset 0,
    # verification 3, flags 1; a different caller would differ only
    # in those three fields.
    rec2 = m.build_record(0x40, 0, 2)
    check("offset varies", rec2["+0x00"] == 0x40)
    check("verification varies", rec2["+0xac"] == 0)
    check("flags vary", rec2["+0xb0"] == 2)
    check("hooks fixed", rec2["+0x18"] == 0x606FA80
          and rec2["+0x20"] == 0x60780A0 and rec2["+0xa8"] == 22)


def test_builder_manager_call_noop():
    code, writes = m.builder_manager_call()
    check("manager call returns 0", code == 0)
    check("manager call writes nothing", writes == [])


def test_manager_ops():
    value, code = m.manager(0)
    check("op0 returns typeinfo", value == 0x64D2D38 and code == 0)
    value, code = m.manager(1, functor_ptr=0xDEAD)
    check("op1 copies functor ptr", value == 0xDEAD and code == 0)
    for op in (2, 3, 4, 99):
        value, code = m.manager(op, functor_ptr=0xDEAD)
        check("op%d no-op" % op, value is None and code == 0)


def test_counted_release():
    disposed = []
    destroyed = []
    cb = m.CountedBase(use=1, weak=1,
                       dispose=lambda c: disposed.append(1),
                       destroy=lambda c: destroyed.append(1))
    check("packed last", cb.packed() == 0x100000001)
    check("fast release disposes", cb.release(True, lambda c: None) is True)
    check("fast release zeroes counts", cb.use == 0 and cb.weak == 0)
    check("fast release ran dispose", disposed == [1])
    check("fast release ran destroy", destroyed == [1])
    # Non-last: use 3 -> 2, no dispose.
    cb2 = m.CountedBase(use=3, weak=1)
    check("shared release keeps object", cb2.release(False, lambda c: None) is False)
    check("use decremented", cb2.use == 2 and cb2.weak == 1)
    # Old use 1 (weak 2): dispose helper runs, object not destroyed.
    ran = []
    cb3 = m.CountedBase(use=1, weak=2)
    check("last-use release disposes", cb3.release(True, lambda c: ran.append(1)) is True)
    check("dispose helper ran", ran == [1])
    check("not destroyed", cb3.destroyed is False)


def test_invoker_id_fast_path():
    calls = []

    def host(*a):
        calls.append(a)

    cb = m.CountedBase(use=1, weak=1)
    slot = m.SharedPtr(obj="StatisticsImpl", control=cb)
    dest = [slot]
    out = m.Status(code=9, subcode=9, state="x")
    got = m.invoker(out, None, b"id", b"", dest, host)
    check("id path returns out", got is out)
    check("id path does not call host", calls == [])
    check("id path empties status", out.is_empty())
    check("id path zeroes slot", slot.obj is None and slot.control is None)
    check("id path disposed control", cb.disposed and cb.destroyed)
    # Non-empty name with id-string "id": forwards, no release.
    slot2 = m.SharedPtr(obj="StatisticsImpl", control=m.CountedBase())
    dest2 = [slot2]
    out2 = m.Status()
    m.invoker(out2, "cfg", b"id", b"BasicStatistics", dest2, host)
    check("id+name forwards", len(calls) == 1)
    check("forwarded slot kept", slot2.obj == "StatisticsImpl")
    # Wrong id-string: forwards.
    m.invoker(m.Status(), "cfg", b"ix", b"", [m.SharedPtr()], host)
    check("non-id forwards", len(calls) == 2)
    # Name length 1 with id-string: forwards (length gate is == 2).
    m.invoker(m.Status(), "cfg", b"i", b"", [m.SharedPtr()], host)
    check("short id forwards", len(calls) == 3)


def test_invoker_forward_to_host():
    seen = []

    def host(out, cfg, name, slot):
        seen.append((cfg, name))
        slot.obj = "created"
        slot.control = m.CountedBase()
        out.code, out.subcode, out.state = 0, 0, None

    slot = m.SharedPtr()
    dest = [slot]
    out = m.Status(code=5)
    got = m.invoker(out, "cfg", b"zz", b"BasicStatistics", dest, host)
    check("forward returns out", got is out)
    check("forward passes cfg", seen == [("cfg", b"BasicStatistics")])
    check("forward installs object", slot.obj == "created")
    check("forward empties status", out.is_empty())


def test_create_host_contract():
    out = m.Status(code=7)
    slot = m.SharedPtr()
    branch = m.create_host_contract(out, None, b"", slot)
    check("empty name is default branch", branch == "default")
    check("default installs StatisticsImpl", slot.obj == "StatisticsImpl")
    check("default empties status", out.is_empty())
    out2 = m.Status()
    slot2 = m.SharedPtr()
    branch2 = m.create_host_contract(out2, None, b"BasicStatistics", slot2)
    check("BasicStatistics is default branch", branch2 == "default")
    check("BasicStatistics installs", slot2.obj == "StatisticsImpl")
    out3 = m.Status()
    branch3 = m.create_host_contract(out3, None, b"SomethingElse", m.SharedPtr())
    check("other name is parse path", branch3 == "parse_path")


def main():
    test_builder_layout()
    test_builder_manager_call_noop()
    test_manager_ops()
    test_counted_release()
    test_invoker_id_fast_path()
    test_invoker_forward_to_host()
    test_create_host_contract()
    failed = [n for n, ok in CHECKS if not ok]
    print("%d tests passed, %d failed" % (len(CHECKS) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
