"""Tests for the node #115 SystemClockWrapper vtable model (RE-001).

Every test is grounded in the evidence packet
research/work-items/RE-001-systemclock-wrapper-vtable-115/: the
vtable slot maps, the chain-walk rule, the single-level forwarding,
the GetOption "id" fast path, AreEquivalent, the lazy default in
PrepareOptions, GetId/Name and the emulated offsets/counters.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import systemclock_wrapper_vtable_115 as m


def test_wrapper_slot_map():
    assert len(m.WRAPPER_SLOTS) == 26
    assert m.slot_address(m.WRAPPER_SLOTS, 0) is None
    assert m.slot_address(m.WRAPPER_SLOTS, 1) is None
    assert m.slot_address(m.WRAPPER_SLOTS, 14) is None
    assert m.slot_address(m.WRAPPER_SLOTS, 2) == 0x609D760
    assert m.slot_address(m.WRAPPER_SLOTS, 3) == 0x609DC40
    assert m.slot_address(m.WRAPPER_SLOTS, 4) == 0x5D32560
    assert m.slot_address(m.WRAPPER_SLOTS, 5) == 0x5FCF590
    assert m.slot_address(m.WRAPPER_SLOTS, 6) == 0x6096790
    assert m.slot_address(m.WRAPPER_SLOTS, 7) == 0x5D2E090
    assert m.slot_address(m.WRAPPER_SLOTS, 8) == 0x60956F0
    assert m.slot_address(m.WRAPPER_SLOTS, 9) == 0x609D0E0
    assert m.slot_address(m.WRAPPER_SLOTS, 10) == 0x60986B0
    assert m.slot_address(m.WRAPPER_SLOTS, 11) == 0x6095710
    assert m.slot_address(m.WRAPPER_SLOTS, 12) == 0x5FCDAE0
    assert m.slot_address(m.WRAPPER_SLOTS, 13) == 0x609D980
    assert m.slot_address(m.WRAPPER_SLOTS, 15) == 0x5D32A30
    assert m.slot_address(m.WRAPPER_SLOTS, 16) == 0x5D2E770
    assert m.slot_address(m.WRAPPER_SLOTS, 17) == 0x5FCC3F0
    assert m.slot_address(m.WRAPPER_SLOTS, 18) == 0x5D2CA10
    assert m.slot_address(m.WRAPPER_SLOTS, 19) == 0x5D4D490
    assert m.slot_address(m.WRAPPER_SLOTS, 20) == 0x5FCC340
    assert m.slot_address(m.WRAPPER_SLOTS, 21) == 0x5FCC360
    assert m.slot_address(m.WRAPPER_SLOTS, 22) == 0x5FCC380
    assert m.slot_address(m.WRAPPER_SLOTS, 23) == 0x5DD41A0
    assert m.slot_address(m.WRAPPER_SLOTS, 24) == 0x5D4B100
    assert m.slot_address(m.WRAPPER_SLOTS, 25) == 0x5FCC3A0


def test_emulated_overrides_share_wrapper_slots():
    for slot in (2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 17, 18, 25):
        assert m.EMULATED_OVERRIDES.get(slot) is None
    assert m.EMULATED_OVERRIDES[14][0] == 0x60257A0
    assert m.EMULATED_OVERRIDES[19][0] == 0x60259E0
    assert m.EMULATED_OVERRIDES[20][0] == 0x60259A0
    assert m.EMULATED_OVERRIDES[21][0] == 0x6025A30
    assert m.EMULATED_OVERRIDES[22][0] == 0x6025A10
    assert m.EMULATED_OVERRIDES[23][0] == 0x6025B40
    assert m.EMULATED_OVERRIDES[24][0] == 0x6025EB0
    emu = m.EmulatedSystemClock(target=m.PosixClock())
    for slot in (2, 3, 5, 12, 15, 17, 25):
        assert emu.slot_ptr(slot) == m.WRAPPER_SLOTS[slot][0]
    assert emu.slot_ptr(14) == 0x60257A0
    assert emu.slot_ptr(19) == 0x60259E0


def test_posix_slots():
    assert m.POSIX_SLOTS[14][0] == 0x5FE0FE0
    assert m.POSIX_SLOTS[17][0] == 0x5D2CA00
    assert m.POSIX_SLOTS[18][0] == 0x5FE0FF0
    assert m.POSIX_SLOTS[19][0] == 0x5FE1540
    assert m.POSIX_SLOTS[20][0] == 0x5FE14F0
    assert m.POSIX_SLOTS[21][0] == 0x5FE1480
    assert m.POSIX_SLOTS[22][0] == 0x5FE1430
    assert m.POSIX_SLOTS[23][0] == 0x5FE1420
    assert m.POSIX_SLOTS[24][0] == 0x5FE2230
    assert m.POSIX_SLOTS[25][0] == 0x5FE1340
    posix = m.PosixClock()
    assert posix.call_slot(14) == "DefaultClock"
    assert posix.call_slot(18) == "PosixClock"
    assert posix.call_slot(17) is None
    assert posix.call_slot(15) == "DefaultClock"


def test_chain_walk_lands_on_leaf():
    leaf = m.PosixClock(now_micros=4242)
    wrap = m.SystemClockWrapper(target=leaf)
    assert wrap.call_slot(19) == 4242
    assert wrap.call_slot(24) == 4242


def test_chain_walk_skips_wrapper_levels():
    leaf = m.PosixClock(now_micros=777)
    mid = m.SystemClockWrapper(target=leaf)
    outer = m.SystemClockWrapper(target=mid)
    assert outer.call_slot(19) == 777
    assert outer.call_slot(24) == 777


def test_chain_walk_first_differing_level_wins():
    leaf = m.PosixClock(now_micros=100, now_nanos=100_000)
    emu = m.EmulatedSystemClock(target=leaf)
    emu.frozen = True
    emu.emulated_offset = 55
    outer = m.SystemClockWrapper(target=emu)
    # The emulated level differs from the canonical, so the walk
    # stops there and never reaches the leaf.
    assert outer.call_slot(19) == 55
    assert outer.call_slot(20) == 55_000


def test_chain_walk_ninth_level():
    leaf = m.PosixClock(now_micros=9)
    chain = leaf
    for _ in range(8):
        chain = m.SystemClockWrapper(target=chain)
    assert chain.call_slot(19) == 9


def test_chain_walk_off_the_end_raises():
    wrap = m.SystemClockWrapper(target=None)
    try:
        wrap.call_slot(19)
    except ValueError as exc:
        assert "chain-walk" in str(exc)
    else:
        raise AssertionError("expected the off-the-end chain to raise")


def test_forwarding_is_single_level():
    leaf = m.PosixClock(now_micros=5, now_nanos=5_000)
    mid = m.SystemClockWrapper(target=leaf)
    outer = m.SystemClockWrapper(target=mid)
    # Each forwarding slot tail-jumps one level; nesting forwards
    # level by level until the leaf.
    assert outer.call_slot(20) == 5_000
    assert outer.call_slot(21) == 5
    assert outer.call_slot(22) == 5_000


def test_sleep_walks_the_chain():
    leaf = m.PosixClock(now_micros=1000)
    wrap = m.SystemClockWrapper(target=leaf)
    wrap.call_slot(23, 250)
    assert leaf.slept_micros == 250
    assert wrap.call_slot(19) == 1250


def test_get_option_id_fast_path():
    emu = m.EmulatedSystemClock(target=m.PosixClock())
    value, status = emu.call_slot(2, "id")
    assert status.ok
    assert value == "TimeEmulatedSystemClock"
    value, status = emu.call_slot(2, "name")
    assert not status.ok
    assert value is None


def test_are_equivalent_branches():
    a = m.EmulatedSystemClock(target=m.PosixClock())
    b = m.EmulatedSystemClock(target=m.PosixClock())
    # flag <= 1 returns 1 without comparing ids.
    a.config_flag = 1
    assert a.call_slot(3, b)[0] == 1
    # this == other returns 1.
    a.config_flag = 5
    assert a.call_slot(3, a)[0] == 1
    # a null other returns 0.
    assert a.call_slot(3, None)[0] == 0
    # different ids return 0 and write "id".
    c = m.PosixClock()
    assert a.call_slot(3, c) == (0, "id")
    # equal ids with flag <= 2 return 1.
    a.config_flag = 2
    assert a.call_slot(3, b)[0] == 1
    # equal ids with flag > 2 use the deeper check.
    a.config_flag = 3
    a.deeper_check = lambda self, other: 0
    assert a.call_slot(3, b)[0] == 0


def test_prepare_options_installs_default():
    wrap = m.SystemClockWrapper(target=None)
    status = wrap.call_slot(5, {})
    assert status.ok
    assert isinstance(wrap.target, m.PosixClock)
    assert wrap.target.call_slot(14) == "DefaultClock"
    # A second call keeps the installed clock.
    keep = wrap.target
    wrap.call_slot(5, {})
    assert wrap.target is keep


def test_get_id_names():
    assert m.PosixClock().call_slot(15) == "DefaultClock"
    emu = m.EmulatedSystemClock(target=m.PosixClock())
    assert emu.call_slot(15) == "TimeEmulatedSystemClock"
    # A bare wrapper has a null Name slot, so it has no id of its own.
    assert m.SystemClockWrapper(target=None).call_slot(15) == ""
    # With a wrapped clock installed, the id comes from the target.
    wrap = m.SystemClockWrapper(target=m.PosixClock())
    assert wrap.call_slot(15) == "DefaultClock"


def test_slot_17_and_18():
    leaf = m.PosixClock()
    wrap = m.SystemClockWrapper(target=leaf)
    assert wrap.call_slot(17) is leaf
    assert wrap.call_slot(18) == ""


def test_emulated_offsets_and_counters():
    leaf = m.PosixClock(now_micros=1000, now_nanos=1_000_000)
    emu = m.EmulatedSystemClock(target=leaf)
    emu.emulated_offset = 40
    assert emu.call_slot(19) == 1040
    assert emu.call_slot(20) == 1_040_000
    emu.frozen = True
    assert emu.call_slot(19) == 40
    assert emu.call_slot(20) == 40_000
    emu.frozen = False
    assert emu.call_slot(21) == 1000
    assert emu.call_slot(22) == 1_000_000
    assert emu.cpu_count == 2
    emu.call_slot(23, 7)
    assert emu.sleep_count == 1
    assert emu.emulated_offset == 47
    assert leaf.slept_micros == 7


def test_time_to_string_forwards():
    leaf = m.PosixClock()
    wrap = m.SystemClockWrapper(target=leaf)
    assert wrap.call_slot(25, None) == "PosixClock time"


def test_serialize_options():
    wrap = m.SystemClockWrapper(target=None)
    status, out = wrap.call_slot(12, {}, "cfg")
    assert status.ok and out == "cfg"
    wrap = m.SystemClockWrapper(target=m.PosixClock())
    status, out = wrap.call_slot(12, {}, "cfg")
    assert status.ok and out == "cfg"
    # A wrapped clock that is not the default clock contributes its id.
    outer = m.SystemClockWrapper(target=m.EmulatedSystemClock(target=None))
    status, out = outer.call_slot(12, {}, "cfg")
    assert status.ok
    assert out == "cfg/TimeEmulatedSystemClock"


def test_chain_canonicals():
    assert m.CHAIN_CANONICAL[19] == (0x64ECF80, 0x5D4D490)
    assert m.CHAIN_CANONICAL[23] == (0x64ED5F8, 0x5DD41A0)
    assert m.CHAIN_CANONICAL[24] == (0x64ED3E8, 0x5D4B100)
