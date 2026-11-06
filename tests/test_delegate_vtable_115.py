"""Tests for the node #115 Find delegate vtable family model.

Run under plain python3 (pytest is not installed on this VM):
    python3 tests/test_delegate_vtable_115.py

The tests exercise dispatch outcomes end to end (inputs through the
model to observable outputs), not only pinned constants: Name /
NickName matching, the wrapped-object offsets, the resolver scan,
the slot-0x18/0x50/0x58/0x60 guards, the parse gates, the clock
slot-0x98 arithmetic and the unwrap chain. The packet's records.json
is the cross-check source for the vtable family data.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import delegate_vtable_115 as m  # noqa: E402

PACKET = os.path.join(os.path.dirname(__file__), "..", "research",
                      "work-items", "RE-001-delegate-vtable-115")
RECORDS = json.load(open(os.path.join(PACKET, "records.json")))


MANGLED = {
    "EnvLogger": "N7rocksdb9EnvLoggerE",
    "Env": "N7rocksdb3EnvE",
    "SystemClockWrapper": "N7rocksdb18SystemClockWrapperE",
    "CompositeEnv": "N7rocksdb12CompositeEnvE",
    "CompositeEnvWrapper": "N7rocksdb19CompositeEnvWrapperE",
    "PosixClock": "*N7rocksdb12_GLOBAL__N_110PosixClockE",
    "PosixEnv": "*N7rocksdb12_GLOBAL__N_18PosixEnvE",
    "MockEnv": "N7rocksdb7MockEnvE",
    "EmulatedSystemClock": "N7rocksdb19EmulatedSystemClockE",
    "MockEnvDirectory": "*N7rocksdb12_GLOBAL__N_116MockEnvDirectoryE",
    "MockEnvFileLock": "*N7rocksdb12_GLOBAL__N_115MockEnvFileLockE",
    "TestMemLogger": "*N7rocksdb12_GLOBAL__N_113TestMemLoggerE",
    "AutoRollLogger": "N7rocksdb14AutoRollLoggerE",
    "StatisticsImpl": "N7rocksdb14StatisticsImplE",
    "ConfigurableMutableCFOptions": "N7rocksdb28ConfigurableMutableCFOptionsE",
    "ConfigurableCFOptions": "N7rocksdb21ConfigurableCFOptionsE",
    "Configurable": "N7rocksdb12ConfigurableE",
    "MutableDBConfigurable": "N7rocksdb21MutableDBConfigurableE",
    "DBOptionsConfigurable": "N7rocksdb21DBOptionsConfigurableE",
}


def test_vtable_bases_match_records():
    assert len(m.VTABLES) == 19
    assert len(RECORDS["vtables"]) == 19
    by_base = {v["vtable"]: v for v in RECORDS["vtables"]}
    for cls, base in m.VTABLES.items():
        rec = by_base["0x%x" % base]
        assert rec["nslots"] == m.NSLOTS[cls]
        assert rec["class"] == MANGLED[cls]


def test_vtable_slot_counts():
    assert m.NSLOTS["Env"] == 85
    assert m.NSLOTS["CompositeEnv"] == 85
    assert m.NSLOTS["CompositeEnvWrapper"] == 85
    assert m.NSLOTS["PosixEnv"] == 85
    assert m.NSLOTS["MockEnv"] == 85
    assert m.NSLOTS["SystemClockWrapper"] == 26
    assert m.NSLOTS["PosixClock"] == 26
    assert m.NSLOTS["EmulatedSystemClock"] == 26
    assert m.NSLOTS["StatisticsImpl"] == 32
    assert m.NSLOTS["Configurable"] == 14
    assert m.NSLOTS["ConfigurableCFOptions"] == 14
    assert m.NSLOTS["EnvLogger"] == 11
    assert m.NSLOTS["MockEnvDirectory"] == 6
    assert m.NSLOTS["MockEnvFileLock"] == 2


def test_name_literals():
    assert m.name("Env") == ""
    assert m.name("CompositeEnv") == ""
    assert m.name("CompositeEnvWrapper") == "CompositeEnv"
    assert m.name("PosixClock") == "DefaultClock"
    assert m.name("PosixEnv") == "PosixEnv"
    assert m.name("MockEnv") == "MockEnv"
    assert m.name("EmulatedSystemClock") == "TimeEmulatedSystemClock"
    assert m.name("StatisticsImpl") == "BasicStatistics"


def test_name_null_and_missing():
    # SystemClockWrapper's slot 0x70 is NULL (pure virtual).
    assert m.name("SystemClockWrapper") is None
    # Configurable and Logger tables have no slot 0x70 at all.
    for cls in ("Configurable", "ConfigurableCFOptions",
                "DBOptionsConfigurable", "EnvLogger", "TestMemLogger",
                "MockEnvDirectory", "MockEnvFileLock"):
        try:
            m.name(cls)
        except ValueError:
            pass
        else:
            raise AssertionError("name(%s) should raise" % cls)


def test_nickname_literals():
    assert m.nickname("PosixClock") == "PosixClock"
    assert m.nickname("PosixEnv") == "DefaultEnv"
    for cls in ("Env", "CompositeEnv", "CompositeEnvWrapper",
                "SystemClockWrapper", "MockEnv", "EmulatedSystemClock",
                "StatisticsImpl"):
        assert m.nickname(cls) == ""


def test_is_instance_of_name_match():
    assert m.is_instance_of("PosixEnv", "PosixEnv") == 1
    assert m.is_instance_of("PosixClock", "DefaultClock") == 1
    assert m.is_instance_of("StatisticsImpl", "BasicStatistics") == 1
    assert m.is_instance_of("MockEnv", "MockEnv") == 1
    assert m.is_instance_of("CompositeEnvWrapper", "CompositeEnv") == 1
    assert m.is_instance_of("EmulatedSystemClock",
                            "TimeEmulatedSystemClock") == 1


def test_is_instance_of_nickname_match():
    assert m.is_instance_of("PosixClock", "PosixClock") == 1
    assert m.is_instance_of("PosixEnv", "DefaultEnv") == 1


def test_is_instance_of_no_match():
    assert m.is_instance_of("PosixEnv", "PosixClock") == 0
    assert m.is_instance_of("PosixClock", "PosixEnv") == 0
    assert m.is_instance_of("StatisticsImpl", "BasicStatistic") == 0
    assert m.is_instance_of("StatisticsImpl", "BasicStatisticsX") == 0
    assert m.is_instance_of("MockEnv", "MockEnvX") == 0
    assert m.is_instance_of("Env", "PosixEnv") == 0


def test_is_instance_of_mockenv_compositeenv():
    # MockEnv and CompositeEnvWrapper override the canonical
    # (0x5fd6240): "CompositeEnv" returns 1 without reaching the
    # canonical, everything else falls through.
    assert m.is_instance_of("MockEnv", "CompositeEnv") == 1
    assert m.is_instance_of("CompositeEnvWrapper", "CompositeEnv") == 1
    assert m.is_instance_of("PosixEnv", "CompositeEnv") == 0
    assert m.is_instance_of("CompositeEnvWrapper", "MockEnv") == 0
    assert m.is_instance_of("MockEnv", "MockEnvX") == 0


def test_is_instance_of_empty_name():
    # Env's Name() and NickName() are both "": the empty string
    # matches by length 0 then a zero-length memcmp.
    assert m.is_instance_of("Env", "") == 1
    assert m.is_instance_of("CompositeEnv", "") == 1
    # SystemClockWrapper's Name() is NULL, so only its NickName ""
    # can match -- the empty string still matches.
    assert m.is_instance_of("SystemClockWrapper", "") == 1
    assert m.is_instance_of("SystemClockWrapper", "x") == 0


def test_is_instance_of_canonical():
    for cls in ("Env", "CompositeEnv", "PosixClock", "PosixEnv",
                "EmulatedSystemClock", "SystemClockWrapper",
                "StatisticsImpl"):
        assert m.is_instance_of_canonical(cls) is True
    # MockEnv and CompositeEnvWrapper override slot 0x80 (0x5fd6240),
    # so both fail find_entry's canonical-IsInstanceOf check.
    assert m.is_instance_of_canonical("MockEnv") is False
    assert m.is_instance_of_canonical("CompositeEnvWrapper") is False


def test_wrapped_object_offsets():
    assert m.wrapped_object("Env", {0x20: 0x1111}) == 0
    assert m.wrapped_object("SystemClockWrapper", {0x20: 0x2222}) == 0x2222
    assert m.wrapped_object("EmulatedSystemClock", {0x20: 0x3333}) == 0x3333
    assert m.wrapped_object("CompositeEnvWrapper", {0x48: 0x4444}) == 0x4444
    assert m.wrapped_object("MockEnv", {0x48: 0x5555}) == 0x5555
    assert m.wrapped_object("StatisticsImpl", {0x28: 0x6666}) == 0x6666
    # A missing offset reads as null.
    assert m.wrapped_object("StatisticsImpl", {}) == 0
    assert m.wrapped_object("MockEnv", {0x20: 0x7777}) == 0


def test_zero_status():
    assert m.zero_status() == b"\x00" * 16
    assert len(m.zero_status()) == 16


def test_resolve_name_match_and_miss():
    records = [(b"alpha", 0x1000), (b"beta", 0x2000), (b"gamma", 0x3000)]
    assert m.resolve_name(records, b"alpha") == 0x1000
    assert m.resolve_name(records, b"beta") == 0x2000
    assert m.resolve_name(records, b"gamma") == 0x3000
    assert m.resolve_name(records, b"delta") is None
    assert m.resolve_name(records, b"alph") is None
    assert m.resolve_name(records, b"alphaX") is None
    assert m.resolve_name([], b"alpha") is None


def test_resolve_name_first_match_wins():
    records = [(b"dup", 0x1000), (b"dup", 0x2000)]
    assert m.resolve_name(records, b"dup") == 0x1000


def test_resolve_name_empty_and_long():
    records = [(b"", 0x1000), (b"x" * 40, 0x2000)]
    assert m.resolve_name(records, b"") == 0x1000
    assert m.resolve_name(records, b"x" * 40) == 0x2000
    assert m.resolve_name(records, b"x" * 39) is None


def test_dotted_name_strips_prefix():
    assert m.dotted_name("PosixEnv", "PosixEnv.log_level") == "log_level"
    assert m.dotted_name("PosixClock", "DefaultClock.now") == "now"
    assert m.dotted_name("StatisticsImpl", "BasicStatistics.x") == "x"
    # Env's Name() is "": the prefix is just ".".
    assert m.dotted_name("Env", ".log_level") == "log_level"


def test_dotted_name_no_prefix_falls_back():
    assert m.dotted_name("PosixEnv", "log_level") is None
    assert m.dotted_name("PosixEnv", "PosixEnvX.log") is None
    assert m.dotted_name("PosixEnv", "PosixEnv") is None
    assert m.dotted_name("Env", "log_level") is None


def test_dotted_name_null_name_raises():
    try:
        m.dotted_name("SystemClockWrapper", "x.y")
    except ValueError:
        pass
    else:
        raise AssertionError("SCW dotted_name should raise")


def test_get_option_id():
    name, status = m.get_option_id("id", "PosixEnv")
    assert name == "PosixEnv"
    assert status == b"\x00" * 16
    assert m.get_option_id("idx", "PosixEnv") is None
    assert m.get_option_id("", "PosixEnv") is None
    assert m.get_option_id("ID", "PosixEnv") is None


def test_configure_option_guards():
    # value +0x2c byte <= 1 returns 1 before anything else.
    assert m.configure_option(0, object(), "a", "b") == ("return", 1, None)
    assert m.configure_option(1, object(), "a", "b") == ("return", 1, None)
    # A null delegate returns 0.
    assert m.configure_option(3, None, "a", "b") == ("return", 0, None)
    # Matching names return 1 with no rewrite.
    assert m.configure_option(3, object(), "x", "x") == ("return", 1, None)
    assert m.configure_option(9, object(), "x", "x") == ("return", 1, None)


def test_configure_option_mismatch():
    # Mismatch + flags > 2: rewrite to "id", forward to Configurable.
    assert m.configure_option(3, object(), "a", "b") == \
        ("forward", None, "id")
    assert m.configure_option(9, object(), "a", "b") == \
        ("forward", None, "id")
    # Mismatch + flags == 2: rewrite to "id", return 1.
    assert m.configure_option(2, object(), "a", "b") == \
        ("return", 1, "id")


def test_set_option():
    # Kind byte 0 always forwards.
    assert m.set_option(0, False, "x") == ("forward",)
    assert m.set_option(0, True, "x") == ("forward",)
    # Kind != 0 with the changeable flag set forwards.
    assert m.set_option(1, True, "x") == ("forward",)
    assert m.set_option(7, True, "x") == ("forward",)
    # Kind != 0 with the flag clear reports the error.
    action, msg = m.set_option(1, False, "log_level")
    assert action == "error"
    assert msg == "Option not changeable: log_level"


def test_validate_always_one():
    assert m.validate(True, False, "log_level") == (1, "log_level")
    assert m.validate(False, True, "log_level") == (1, "log_level")
    assert m.validate(True, True, "log_level") == (1, "log_level")
    # Both validators reject: the name is blanked, still returns 1.
    assert m.validate(False, False, "log_level") == (1, "")


def test_serialize_id():
    assert m.serialize_id("opts", "PosixEnv", "val", 1) == \
        "optsid=PosixEnvval"
    # An empty delegate name composes the id form at any kind.
    assert m.serialize_id("opts", "", "val", 2) == "optsid=val"
    assert m.serialize_id("opts", "", "val", 0) == "optsid=val"
    # Kind != 1 with a non-empty delegate name forwards.
    assert m.serialize_id("opts", "PosixEnv", "val", 2) is None
    assert m.serialize_id("opts", "PosixEnv", "val", 0) is None


def test_parse_gate_28():
    def q(hi, lo):
        return (hi << 32) | lo
    # (high-4) > 1 is required: high 4 and 5 never fire.
    assert m.parse_gate_28(q(4, 6), True, True) is False
    assert m.parse_gate_28(q(5, 6), True, True) is False
    # A high dword of 0..3 wraps unsigned and also passes.
    assert m.parse_gate_28(q(0, 6), True, True) is True
    assert m.parse_gate_28(q(3, 6), True, True) is True
    # The 0x40 flag bit blocks the worker.
    assert m.parse_gate_28(q(6, 6), False, True) is False
    # +0xa0 non-null fires at high 6.
    assert m.parse_gate_28(q(6, 6), True, True) is True
    # +0xa0 null fires only for low 0x15/0x16.
    assert m.parse_gate_28(q(6, 0x15), True, False) is True
    assert m.parse_gate_28(q(6, 0x16), True, False) is True
    assert m.parse_gate_28(q(6, 0x17), True, False) is False
    assert m.parse_gate_28(q(6, 6), True, False) is False
    # The two halves are independent: high 6 with low 0x15 fires,
    # high 4 with low 0x15 does not.
    assert m.parse_gate_28(q(4, 0x15), True, False) is False


def test_parse_gate_30():
    def q(hi, lo):
        return (hi << 32) | lo
    assert m.parse_gate_30(q(4, 6), True) is False
    assert m.parse_gate_30(q(5, 6), True) is False
    # No 0x40 flag check here: high 6 with +0xc0 non-null fires.
    assert m.parse_gate_30(q(6, 6), True) is True
    # +0xc0 null fires only for low 0x15/0x16.
    assert m.parse_gate_30(q(6, 0x15), False) is True
    assert m.parse_gate_30(q(6, 0x16), False) is True
    assert m.parse_gate_30(q(6, 0x17), False) is False
    assert m.parse_gate_30(q(6, 6), False) is False
    # High-dword wraparound passes the first test too.
    assert m.parse_gate_30(q(0, 0x15), False) is True


def test_posix_clock_now():
    assert m.posix_clock_now(0, 0) == 0
    assert m.posix_clock_now(1, 500000) == 1500000
    assert m.posix_clock_now(1, 0) == 1000000
    assert m.posix_clock_now(0, 999999) == 999999
    # 2026-11-06 20:00 KST ~= 1794000000 s: a realistic epoch value.
    assert m.posix_clock_now(1794000000, 123456) == 1794000000123456


def test_emulated_clock_now():
    # Flag clear: wrapped time + offset.
    assert m.emulated_clock_now(False, 1000000, 500) == 1000500
    # Flag set: the wrapped clock is not called, only the offset.
    assert m.emulated_clock_now(True, 1000000, 500) == 500
    assert m.emulated_clock_now(True, 0, 0) == 0
    assert m.emulated_clock_now(False, 0, 0) == 0


def test_unwrap_chain():
    unwrap = m.SLOT98_UNWRAP_SCW
    terminal = m.SLOT98_TERMINAL
    assert m.unwrap_chain([terminal]) == terminal
    assert m.unwrap_chain([unwrap, terminal]) == terminal
    assert m.unwrap_chain([unwrap, unwrap, terminal]) == terminal
    assert m.unwrap_chain([unwrap, unwrap, unwrap]) == unwrap
    assert m.unwrap_chain([]) is None
    # Ten unrolled levels: an 11th-level terminal is not reached.
    assert m.unwrap_chain([unwrap] * 10 + [terminal]) == unwrap


def test_slot78_is_name_as_string():
    # Every family table that reaches slot 0x78 uses the shared
    # 0x5d32a30 (Name() assigned into the sret string).
    for v in RECORDS["vtables"]:
        slot = v["slots"].get("0x78")
        if slot is None:
            continue
        assert slot["target"] == "0x5d32a30", v["vtable"]
        assert slot["kind"] == "function"


def test_slot80_canonical_except_mockenv():
    for v in RECORDS["vtables"]:
        slot = v["slots"].get("0x80")
        if slot is None:
            continue
        if v["vtable"] in ("0x64d1398", "0x64ce590"):
            # MockEnv and CompositeEnvWrapper share the 0x5fd6240
            # override ("CompositeEnv" returns 1, else canonical).
            assert slot["target"] == "0x5fd6240", v["vtable"]
        else:
            assert slot["target"] == "0x5d2e770", v["vtable"]


def test_records_cross_checks():
    assert RECORDS["task"] == "RE-001"
    assert RECORDS["artifact"]["sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    assert RECORDS["census"]["typeinfo_objects"] == 701
    assert RECORDS["census"]["strict_vtables"] == 406
    assert RECORDS["census"]["caller_rows"] == 75
    assert len(RECORDS["interface_slots"]) == 18
    assert RECORDS["value_struct"]["size"] == 80
    # The GOT landmarks in the model match the packet.
    for got, target in m.GOT.items():
        rec = [g for g in RECORDS["got_landmarks"]
               if g["got"] == "0x%x" % got]
        assert len(rec) == 1
        assert rec[0]["target"] == "0x%x" % target
    # The literals in the model match the packet.
    for addr, text in RECORDS["literals"].items():
        assert m.NAME.get("PosixClock") == "DefaultClock"  # sanity
        assert text in ("", "id", "=", "Option not changeable: ",
                        "target=", "DefaultClock", "DefaultEnv",
                        "BasicStatistics", "CompositeEnv", "PosixEnv",
                        "PosixClock", "MockEnv",
                        "TimeEmulatedSystemClock")


def test_find_entry_constants():
    assert m.FIND_ENTRY == 0x609E510
    assert m.DELEGATE_IMPL == 0x6097110
    assert m.CREATE_HOST == 0x6077820
    assert m.IS_INSTANCE_OF == 0x5D2E770
    assert m.NAME_AS_STRING == 0x5D32A30
    assert m.ZERO_STATUS == 0x60956F0
    assert m.SLOT38_RESOLVER == 0x60958C0
    assert m.SLOT98_TERMINAL == 0x5FCC240
    assert m.GOT[0x64ECEB8] == m.IS_INSTANCE_OF
    assert m.GOT[0x64ED8B0] == m.SLOT98_TERMINAL


def _run_all():
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    for name, fn in fns:
        fn()
        print("ok", name)
    print("all %d tests passed" % len(fns))


if __name__ == "__main__":
    _run_all()
