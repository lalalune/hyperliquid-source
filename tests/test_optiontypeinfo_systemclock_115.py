"""Tests for the node #115 AsCustomSharedPtr<SystemClock> model.

Target-grounded expectations from research/work-items/
RE-001-optiontypeinfo-systemclock-115: the builder's field layout
and copy-helper install, the manager's op dispatch, the invoker's
"id" fast path vs forward path, the Status move-assignment, the
create host's adopt vs default dispatch, the accessor's combined
allocation, and the default initializer's registry insert.
Run: python3 tests/test_optiontypeinfo_systemclock_115.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import optiontypeinfo_systemclock_115 as m

CHECKS = []


def check(name, cond):
    CHECKS.append((name, bool(cond)))
    if not cond:
        print("FAILED:", name)


def _record_with_members(offset=0, verification=1, flags=0x2000):
    rec = m.build_record(offset, verification, flags)
    rec["+0x08"] = {"functor": None, "manager": m.MANAGER,
                    "invoker": m.INVOKER}
    for member in ("+0x28", "+0x48", "+0x68", "+0x88"):
        rec[member] = {"functor": None, "manager": None, "invoker": None}
    return rec


def test_builder_layout():
    rec = m.build_record(0, 1, 0x2000)
    check("record size", len(rec) == 24)
    check("offset field", rec["+0x00"] == 0)
    check("reserved +0x08 zero", rec["+0x08"] == 0)
    check("reserved +0x10 zero", rec["+0x10"] == 0)
    check("manager hook", rec["+0x18"] == 0x5FCC660)
    check("invoker hook", rec["+0x20"] == 0x5FD4C30)
    check("reserved +0x28 zero", rec["+0x28"] == 0)
    check("reserved +0xa0 zero", rec["+0xa0"] == 0)
    check("type is 22", rec["+0xa8"] == 22)
    check("verification field", rec["+0xac"] == 1)
    check("flags field", rec["+0xb0"] == 0x2000)
    # The +0x04 padding dword is never written by the builder or
    # the copy helper, so it is absent from the model.
    check("padding +0x04 unwritten", "+0x04" not in rec)
    # The installing call site (0x5fd1a14) uses offset 0,
    # verification 1, flags 0x2000; a different caller would differ
    # only in those three fields.
    rec2 = m.build_record(0x40, 0, 2)
    check("offset varies", rec2["+0x00"] == 0x40)
    check("verification varies", rec2["+0xac"] == 0)
    check("flags vary", rec2["+0xb0"] == 2)
    check("hooks fixed", rec2["+0x18"] == 0x5FCC660
          and rec2["+0x20"] == 0x5FD4C30 and rec2["+0xa8"] == 22)


def test_builder_temp_cleanup_noop():
    code, writes = m.builder_temp_cleanup()
    check("temp cleanup returns 0", code == 0)
    check("temp cleanup writes nothing", writes == [])


def test_manager_ops():
    value, code = m.manager(0)
    check("op0 returns typeinfo", value == 0x64CDA00 and code == 0)
    value, code = m.manager(1, functor_ptr=0xDEAD)
    check("op1 copies functor ptr", value == 0xDEAD and code == 0)
    for op in (2, 3, 4, 99):
        value, code = m.manager(op, functor_ptr=0xDEAD)
        check("op%d no-op" % op, value is None and code == 0)


def test_copy_record():
    src = _record_with_members(0, 1, 0x2000)
    out = {}
    got = m.copy_record(out, src)
    check("copy returns out", got is out)
    check("copy offset", out["+0x00"] == 0)
    check("copy installs manager", out["+0x08"]["manager"] == 0x5FCC660)
    check("copy installs invoker", out["+0x08"]["invoker"] == 0x5FD4C30)
    check("copy leaves member 1 empty", out["+0x28"]["manager"] is None)
    check("copy leaves member 4 empty", out["+0x88"]["invoker"] is None)
    check("copy type", out["+0xa8"] == 22)
    check("copy verification", out["+0xac"] == 1)
    check("copy flags", out["+0xb0"] == 0x2000)
    check("copy never writes padding", "+0x04" not in out)


def test_status_move():
    dst = m.Status(code=1, subcode=2, state="old")
    src = m.Status(code=3, subcode=4, state="new")
    got = m.status_move(dst, src)
    check("move returns dst", got is dst)
    check("move copies code", dst.code == 3)
    check("move copies subcode", dst.subcode == 4)
    check("move moves state", dst.state == "new")
    check("move zeroes src subcode", src.subcode == 0)
    check("move nulls src state", src.state is None)
    check("move keeps src code byte", src.code == 3)
    # Self-move is a no-op.
    self_status = m.Status(code=5, subcode=6, state="keep")
    m.status_move(self_status, self_status)
    check("self-move is no-op",
          self_status.code == 5 and self_status.subcode == 6
          and self_status.state == "keep")


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
    slot = m.SharedPtr(obj="PosixClock", control=cb)
    dest = [slot]
    out = m.Status(code=9, subcode=9, state="x")
    got = m.invoker(out, None, b"id", b"", dest, host)
    check("id path returns out", got is out)
    check("id path does not call host", calls == [])
    check("id path empties status", out.is_empty())
    check("id path zeroes slot", slot.obj is None and slot.control is None)
    check("id path disposed control", cb.disposed and cb.destroyed)
    # Non-empty name with id-string "id": forwards, no release.
    slot2 = m.SharedPtr(obj="PosixClock", control=m.CountedBase())
    dest2 = [slot2]
    out2 = m.Status()
    m.invoker(out2, "cfg", b"id", b"SystemClock", dest2, host)
    check("id+name forwards", len(calls) == 1)
    check("forwarded slot kept", slot2.obj == "PosixClock")
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
    got = m.invoker(out, "cfg", b"zz", b"SystemClock", dest, host)
    check("forward returns out", got is out)
    check("forward passes cfg", seen == [("cfg", b"SystemClock")])
    check("forward installs object", slot.obj == "created")
    check("forward empties status", out.is_empty())


def _make_current(name_70=b"SystemClock", name_90=None, predicate=None,
                  slot_90_default=True):
    clock = m.Clock(name_70=name_70, name_90=name_90,
                    predicate_80=predicate,
                    slot_90_is_default=slot_90_default)
    control = m.CountedBase(use=1, weak=1)
    return m.SharedPtr(obj=clock, control=control)


def _noop_translator(status=m.Status(), name=b"", error=None):
    def tr(cfg, nm):
        return status, name, error
    return tr


def _noop_factory(status=m.Status()):
    def fac(field, name, slot):
        return status
    return fac


def _noop_second(status=m.Status()):
    def sec(intermediate, cfg, obj, cur):
        return status
    return sec


def test_host_adopts_by_slot_0x70_name():
    current = _make_current()
    dest = m.SharedPtr(obj="old", control=m.CountedBase())
    out = m.Status(code=7)
    got = m.create_host(out, {"byte_1": False}, b"SystemClock", dest,
                        current, _noop_translator(), _noop_factory(),
                        _noop_second())
    check("adopt returns out", got is out)
    check("adopt empties status", out.is_empty())
    check("adopt installs current", dest.obj is current.obj)
    check("adopt installs control", dest.control is current.control)


def test_host_adopts_by_slot_0x90_name():
    current = _make_current(name_70=b"Other", name_90=b"SystemClock",
                            slot_90_default=False)
    dest = m.SharedPtr()
    out = m.Status()
    m.create_host(out, {"byte_1": False}, b"SystemClock", dest, current,
                  _noop_translator(), _noop_factory(), _noop_second())
    check("slot-0x90 adopt installs", dest.obj is current.obj)
    check("slot-0x90 adopt empties status", out.is_empty())


def test_host_predicate_false_goes_default():
    current = _make_current(predicate=lambda nm: False)
    dest = m.SharedPtr()
    out = m.Status()
    trans_status = m.Status(code=3, subcode=1, state="t")
    m.create_host(out, {"byte_1": False}, b"SystemClock", dest, current,
                  _noop_translator(status=trans_status),
                  _noop_factory(), _noop_second())
    check("predicate false moves translator status", out.code == 3)
    check("predicate false keeps slot empty", dest.obj is None)


def test_host_default_translator_error():
    current = _make_current(name_70=b"Other")
    dest = m.SharedPtr()
    out = m.Status()
    trans_status = m.Status(code=5, subcode=0, state="bad")
    m.create_host(out, {"byte_1": False}, b"Unknown", dest, current,
                  _noop_translator(status=trans_status),
                  _noop_factory(), _noop_second())
    check("translator error moves status", out.code == 5)
    check("translator error moves state", out.state == "bad")


def test_host_default_factory_success():
    current = _make_current(name_70=b"Other")
    dest = m.SharedPtr()
    out = m.Status(code=9)
    calls = []

    def factory(field, name, slot):
        calls.append(name)
        slot.obj = "created-clock"
        slot.control = m.CountedBase()
        return m.Status()

    def second(intermediate, cfg, obj, cur):
        return m.Status()

    m.create_host(out, {"byte_1": False}, b"Emulated", dest, current,
                  _noop_translator(name=b"Emulated"), factory, second)
    check("factory called with translated name", calls == [b"Emulated"])
    check("factory installs clock", dest.obj == "created-clock")
    check("factory path empties status", out.is_empty())


def test_host_factory_not_supported_resets():
    current = _make_current(name_70=b"Other")
    dest = m.SharedPtr()
    out = m.Status(code=9)

    def factory(field, name, slot):
        return m.Status(code=3)

    m.create_host(out, {"byte_1": True}, b"Emulated", dest, current,
                  _noop_translator(name=b"Emulated"), factory,
                  _noop_second())
    check("not-supported with byte_1 empties status", out.is_empty())


def test_host_default_no_name_no_error_releases():
    current = _make_current(name_70=b"Other")
    old_cb = m.CountedBase(use=1, weak=1)
    dest = m.SharedPtr(obj="old", control=old_cb)
    out = m.Status(code=9)
    m.create_host(out, {"byte_1": False}, b"Unknown", dest, current,
                  _noop_translator(), _noop_factory(), _noop_second())
    check("no-name no-error releases slot", dest.obj is None)
    check("no-name no-error disposes old", old_cb.disposed)
    check("no-name no-error empties status", out.is_empty())


def test_host_error_path_builds_status():
    current = _make_current(name_70=b"Other")
    dest = m.SharedPtr()
    out = m.Status()

    def builder(code, message, name):
        return m.Status(code=code, state=message + name)

    m.create_host(out, {"byte_1": False}, b"Unknown", dest, current,
                  _noop_translator(error=b"Unknown"),
                  _noop_factory(), _noop_second(),
                  error_status_builder=builder)
    check("error path code 3", out.code == 3)
    check("error path message",
          out.state == b"Cannot reset object Unknown")


def test_default_predicate():
    clock = m.Clock(name_70=b"SystemClock", name_90=b"Alt",
                    slot_90_is_default=False)
    check("default predicate empty is false",
          m.default_slot_0x80_predicate(clock, b"") is False)
    check("default predicate matches slot-0x70",
          m.default_slot_0x80_predicate(clock, b"SystemClock") is True)
    check("default predicate matches slot-0x90",
          m.default_slot_0x80_predicate(clock, b"Alt") is True)
    check("default predicate rejects other",
          m.default_slot_0x80_predicate(clock, b"Nope") is False)
    check("default slot-0x90 is empty", m.default_slot_0x90_name() == b"")
    check("sentinel constants",
          m.SENTINEL_SLOT_0X80 == 0x5D2E770
          and m.SENTINEL_SLOT_0X90 == 0x5D2CA10)


def test_accessor_slow_path():
    acc = m.ClockAccessor()
    control, slot = acc.current()
    check("accessor guard set", acc.guard is True)
    check("accessor returns control", acc.static_control is control)
    check("accessor packed counts", control.packed() == 0x100000001)
    check("accessor clock is PosixClock",
          slot.obj.name_70 == b"SystemClock")
    control2, slot2 = acc.current()
    check("accessor fast path returns same control", control2 is control)
    check("accessor fast path returns same slot object",
          slot2.obj is slot.obj)


def test_default_init_registers():
    registry = {}
    name = m.default_init(registry)
    check("default init returns name", name == b"SystemClock")
    check("default init registers SystemClock", b"SystemClock" in registry)
    check("registered clock name_70",
          registry[b"SystemClock"].name_70 == b"SystemClock")


def main():
    test_builder_layout()
    test_builder_temp_cleanup_noop()
    test_manager_ops()
    test_copy_record()
    test_status_move()
    test_counted_release()
    test_invoker_id_fast_path()
    test_invoker_forward_to_host()
    test_host_adopts_by_slot_0x70_name()
    test_host_adopts_by_slot_0x90_name()
    test_host_predicate_false_goes_default()
    test_host_default_translator_error()
    test_host_default_factory_success()
    test_host_factory_not_supported_resets()
    test_host_default_no_name_no_error_releases()
    test_host_error_path_builds_status()
    test_default_predicate()
    test_accessor_slow_path()
    test_default_init_registers()
    failed = [n for n, ok in CHECKS if not ok]
    print("%d tests passed, %d failed" % (len(CHECKS) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
