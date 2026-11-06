"""Tests for the node #115 AsCustomSharedPtr<SliceTransform> model.

Target-grounded expectations from research/work-items/
RE-001-optiontypeinfo-slicetransform-115: the builder's field layout
and its six-destroy cleanup (which differs from the SystemClock
sibling), the manager's op dispatch, the invoker's "id" fast path vs
forward path, the create host's translator/find/create dispatch with
its three code-4 error arms, the registry find's type-node match,
entry scan, parent recursion and miss, and the once initializer's
registration.
Run: python3 tests/test_optiontypeinfo_slicetransform_115.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import optiontypeinfo_slicetransform_115 as m

CHECKS = []


def check(name, cond):
    CHECKS.append((name, bool(cond)))
    if not cond:
        print("FAILED:", name)


def _record_with_members(offset=0x40, verification=2, flags=0x1100):
    rec = m.build_record(offset, verification, flags)
    rec["+0x08"] = {"functor": None, "manager": m.MANAGER,
                    "invoker": m.INVOKER}
    for member in ("+0x28", "+0x48", "+0x68", "+0x88"):
        rec[member] = {"functor": None, "manager": None, "invoker": None}
    return rec


def test_builder_layout():
    rec = m.build_record(0x40, 2, 0x1100)
    check("record size", len(rec) == 24)
    check("offset field", rec["+0x00"] == 0x40)
    check("reserved +0x08 zero", rec["+0x08"] == 0)
    check("reserved +0x10 zero", rec["+0x10"] == 0)
    check("manager hook", rec["+0x18"] == 0x607D190)
    check("invoker hook", rec["+0x20"] == 0x60809E0)
    check("reserved +0x28 zero", rec["+0x28"] == 0)
    check("reserved +0xa0 zero", rec["+0xa0"] == 0)
    check("type is 22", rec["+0xa8"] == 22)
    check("verification field", rec["+0xac"] == 2)
    check("flags field", rec["+0xb0"] == 0x1100)
    # The +0x04 padding dword is never written by the builder or
    # the copy helper, so it is absent from the model.
    check("padding +0x04 unwritten", "+0x04" not in rec)
    # The second installing call site (0x6090205) uses offset 0xc0,
    # verification 2, flags 0; only those three fields differ.
    rec2 = m.build_record(0xC0, 2, 0)
    check("offset varies", rec2["+0x00"] == 0xC0)
    check("verification varies", rec2["+0xac"] == 2)
    check("flags vary", rec2["+0xb0"] == 0)
    check("hooks fixed", rec2["+0x18"] == 0x607D190
          and rec2["+0x20"] == 0x60809E0 and rec2["+0xa8"] == 22)


def test_builder_temp_cleanup_noop():
    code, writes = m.builder_temp_cleanup()
    check("temp cleanup returns 0", code == 0)
    check("temp cleanup writes nothing", writes == [])
    # The six destroys are no-ops: the lambda's manager op 3 and
    # the zero members. The record destructor runs only on the
    # landing pad, never on the normal path.
    check("cleanup is not the record dtor",
          m.RECORD_DTOR == 0x5D3F950 and m.builder_temp_cleanup() == (0, []))


def test_manager_ops():
    value, code = m.manager(0)
    check("op0 returns typeinfo", value == 0x64D3018 and code == 0)
    value, code = m.manager(1, functor_ptr=0xDEAD)
    check("op1 copies functor ptr", value == 0xDEAD and code == 0)
    for op in (2, 3, 4, 99):
        value, code = m.manager(op, functor_ptr=0xDEAD)
        check("op%d no-op" % op, value is None and code == 0)


def test_copy_record():
    src = _record_with_members()
    out = {}
    got = m.copy_record(out, src)
    check("copy returns out", got is out)
    check("copy offset", out["+0x00"] == 0x40)
    check("copy installs manager", out["+0x08"]["manager"] == 0x607D190)
    check("copy installs invoker", out["+0x08"]["invoker"] == 0x60809E0)
    check("copy leaves member 1 empty", out["+0x28"]["manager"] is None)
    check("copy leaves member 4 empty", out["+0x88"]["invoker"] is None)
    check("copy type", out["+0xa8"] == 22)
    check("copy verification", out["+0xac"] == 2)
    check("copy flags", out["+0xb0"] == 0x1100)
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
    slot = m.SharedPtr(obj="old-transform", control=cb)
    dest = [slot]
    out = m.Status(code=9, subcode=9, state="x")
    got = m.invoker(out, None, b"id", b"", dest, host)
    check("id path returns out", got is out)
    check("id path does not call host", calls == [])
    check("id path empties status", out.is_empty())
    check("id path zeroes slot", slot.obj is None and slot.control is None)
    check("id path disposed control", cb.disposed and cb.destroyed)
    # Non-empty name with id-string "id": forwards, no release.
    slot2 = m.SharedPtr(obj="old-transform", control=m.CountedBase())
    dest2 = [slot2]
    out2 = m.Status()
    m.invoker(out2, "cfg", b"id", b"prefix_extractor", dest2, host)
    check("id+name forwards", len(calls) == 1)
    check("forwarded slot kept", slot2.obj == "old-transform")
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
    got = m.invoker(out, "cfg", b"zz", b"prefix_extractor", dest, host)
    check("forward returns out", got is out)
    check("forward passes cfg", seen == [("cfg", b"prefix_extractor")])
    check("forward installs object", slot.obj == "created")
    check("forward empties status", out.is_empty())


def _noop_translator(status=None, name=b""):
    def tr(cfg, nm, dest_obj):
        return (status if status is not None else m.Status(), name)
    return tr


def _noop_second(status=None):
    def sec(intermediate, cfg, obj, cur):
        return status if status is not None else m.Status()
    return sec


def _registry_with(factory, predicate=lambda key: True):
    return m.Registry(buckets=[(b"SliceTransform", [(predicate, factory)])])


def _factory_success(obj_value="created-transform"):
    def fac(name, obj_slot, detail):
        obj_slot["obj"] = obj_value
        return True
    return fac


def test_host_translator_error():
    dest = m.SharedPtr()
    out = m.Status(code=7)
    trans_status = m.Status(code=5, subcode=0, state="bad")
    m.create_host(out, {"byte_1": False}, b"prefix_extractor", dest,
                  _noop_translator(status=trans_status), m.Registry(),
                  _noop_second())
    check("translator error moves status", out.code == 5)
    check("translator error moves state", out.state == "bad")
    check("translator error keeps slot empty", dest.obj is None)


def test_host_empty_translated_name_releases():
    old_cb = m.CountedBase(use=1, weak=1)
    dest = m.SharedPtr(obj="old", control=old_cb)
    out = m.Status(code=9)
    m.create_host(out, {"byte_1": False}, b"prefix_extractor", dest,
                  _noop_translator(name=b""), m.Registry(), _noop_second())
    check("empty name releases slot", dest.obj is None)
    check("empty name disposes old", old_cb.disposed)
    check("empty name empties status", out.is_empty())


def test_host_find_miss_code_3():
    dest = m.SharedPtr()
    out = m.Status()
    m.create_host(out, {"byte_1": False}, b"prefix_extractor", dest,
                  _noop_translator(name=b"prefix_extractor"),
                  m.Registry(), _noop_second())
    check("find miss code 3", out.code == 3)
    check("find miss message",
          out.state == b"Could not load SliceTransform prefix_extractor")


def test_host_factory_success_installs():
    dest = m.SharedPtr(obj="old", control=m.CountedBase())
    out = m.Status(code=9)
    m.create_host(out, {"byte_1": False}, b"prefix_extractor", dest,
                  _noop_translator(name=b"prefix_extractor"),
                  _registry_with(_factory_success()), _noop_second())
    check("factory installs object", dest.obj == "created-transform")
    check("factory installs control", dest.control is not None)
    check("factory control packed", dest.control.packed() == 0x100000001)
    check("factory control table", dest.control.table == 0x64D7888)
    check("factory path empties status", out.is_empty())


def test_host_factory_null_with_detail_code_4():
    def fac(name, obj_slot, detail):
        detail["text"] = b"factory said no"
        return False

    dest = m.SharedPtr()
    out = m.Status()
    m.create_host(out, {"byte_1": False}, b"prefix_extractor", dest,
                  _noop_translator(name=b"prefix_extractor"),
                  _registry_with(fac), _noop_second())
    check("null factory with detail code 4", out.code == 4)
    check("null factory detail message",
          out.state == b"factory said no prefix_extractor")


def test_host_factory_null_no_detail_code_4():
    def fac(name, obj_slot, detail):
        return False

    dest = m.SharedPtr()
    out = m.Status()
    m.create_host(out, {"byte_1": False}, b"prefix_extractor", dest,
                  _noop_translator(name=b"prefix_extractor"),
                  _registry_with(fac), _noop_second())
    check("null factory no detail code 4", out.code == 4)
    check("null factory no detail message",
          out.state == b"Could not load SliceTransform prefix_extractor")


def test_host_factory_unguarded_code_4():
    def fac(name, obj_slot, detail):
        # Returns non-null but leaves the object slot empty.
        return True

    dest = m.SharedPtr()
    out = m.Status()
    m.create_host(out, {"byte_1": False}, b"prefix_extractor", dest,
                  _noop_translator(name=b"prefix_extractor"),
                  _registry_with(fac), _noop_second())
    check("unguarded factory code 4", out.code == 4)
    check("unguarded factory message",
          out.state == b"Cannot make a shared SliceTransform "
                      b"from unguarded one  prefix_extractor")


def test_host_not_supported_resets():
    dest = m.SharedPtr()
    out = m.Status(code=9)

    def fac(name, obj_slot, detail):
        return False

    m.create_host(out, {"byte_1": True}, b"prefix_extractor", dest,
                  _noop_translator(name=b"prefix_extractor"),
                  m.Registry(), _noop_second())
    check("not-supported with byte_1 empties status", out.is_empty())


def test_host_second_translator_on_success():
    dest = m.SharedPtr()
    out = m.Status(code=9)
    seen = []

    def second(intermediate, cfg, obj, cur):
        seen.append(obj)
        return m.Status(code=0, subcode=0, state=None)

    m.create_host(out, {"byte_1": False}, b"prefix_extractor", dest,
                  _noop_translator(name=b"prefix_extractor"),
                  _registry_with(_factory_success()), second)
    check("second translator sees installed object",
          seen == ["created-transform"])
    check("success path empties status", out.is_empty())


def test_find_type_match_and_predicate_scan():
    calls = []

    def fac_a(name, obj_slot, detail):
        calls.append("a")
        return True

    def fac_b(name, obj_slot, detail):
        calls.append("b")
        return True

    entries = [(lambda key: False, fac_a), (lambda key: True, fac_b)]
    registry = m.Registry(buckets=[(b"SliceTransform", entries)])
    got = m.find_registry(registry, b"prefix_extractor")
    check("find returns second matching entry", got is fac_b)
    check("find skipped non-matching entry", calls == [])


def test_find_type_mismatch_misses():
    registry = m.Registry(buckets=[(b"OtherType", [(lambda k: True, 1)])])
    check("find misses other type", m.find_registry(registry, b"x") is None)


def test_find_parent_recursion():
    parent = m.Registry(buckets=[(b"SliceTransform",
                                  [(lambda k: True, "parent-factory")])])
    child = m.Registry(buckets=[(b"OtherType", [])], parent=parent)
    check("find recurses to parent",
          m.find_registry(child, b"prefix_extractor") == "parent-factory")


def test_find_miss_returns_none():
    registry = m.Registry(buckets=[(b"SliceTransform",
                                    [(lambda k: False, "never")])])
    check("find misses when predicate false",
          m.find_registry(registry, b"prefix_extractor") is None)
    check("find misses empty registry",
          m.find_registry(m.Registry(), b"prefix_extractor") is None)


def test_default_init_registers():
    registry = m.Registry()
    name = m.default_init(registry)
    check("default init returns name", name == b"SliceTransform")
    got = m.find_registry(registry, b"prefix_extractor")
    check("default init registers factory", got is not None)
    obj_slot = {"obj": None}
    detail = {"text": None}
    check("default factory creates", got(b"prefix_extractor", obj_slot, detail) is True)
    check("default factory object",
          obj_slot["obj"] == "default-slice-transform")


def main():
    test_builder_layout()
    test_builder_temp_cleanup_noop()
    test_manager_ops()
    test_copy_record()
    test_status_move()
    test_counted_release()
    test_invoker_id_fast_path()
    test_invoker_forward_to_host()
    test_host_translator_error()
    test_host_empty_translated_name_releases()
    test_host_find_miss_code_3()
    test_host_factory_success_installs()
    test_host_factory_null_with_detail_code_4()
    test_host_factory_null_no_detail_code_4()
    test_host_factory_unguarded_code_4()
    test_host_not_supported_resets()
    test_host_second_translator_on_success()
    test_find_type_match_and_predicate_scan()
    test_find_type_mismatch_misses()
    test_find_parent_recursion()
    test_find_miss_returns_none()
    test_default_init_registers()
    failed = [n for n, ok in CHECKS if not ok]
    print("%d tests passed, %d failed" % (len(CHECKS) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
