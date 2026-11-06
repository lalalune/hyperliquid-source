"""Tests for tools/flag_drain_wait_51ab0_115.py.

Each test drives the drain-and-wait model end to end and checks the
observable operation sequence, not only constants. Run directly:
every test_* function is invoked by the packet checker (pytest is
not installed on this VM).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from flag_drain_wait_51ab0_115 import (  # noqa: E402
    ADDRESS, CONDVAR_OFFSET, FLAG_DRAIN, FLAG_WAIT, LOCK_SLOT,
    MUTEX_OFFSET, SIZE_BYTES, TEARDOWN_ARG, WATCHED_OFFSET,
    DrainWait, Holder,
)


def test_both_flags_clear_returns_with_entry_noop_only():
    routine = DrainWait()
    assert routine.run(Holder()) is None
    assert routine.trace == [("entry_noop", LOCK_SLOT)]


def test_drain_once_then_returns():
    holder = Holder(flag_drain=True)

    def teardown():
        holder.flag_drain = False

    routine = DrainWait(on_teardown=teardown)
    assert routine.run(holder) is None
    assert routine.trace == [("entry_noop", LOCK_SLOT),
                            ("unlock", LOCK_SLOT),
                            ("teardown", TEARDOWN_ARG),
                            ("lock", LOCK_SLOT)]


def test_drain_repeats_until_flag_clears():
    holder = Holder(flag_drain=True)
    calls = []

    def teardown():
        calls.append(1)
        if len(calls) == 3:
            holder.flag_drain = False

    routine = DrainWait(on_teardown=teardown)
    assert routine.run(holder) is None
    assert routine.trace.count(("teardown", TEARDOWN_ARG)) == 3
    assert routine.trace.count(("unlock", LOCK_SLOT)) == 3
    assert routine.trace.count(("lock", LOCK_SLOT)) == 3


def test_unlock_precedes_teardown_precedes_relock():
    holder = Holder(flag_drain=True)

    def teardown():
        holder.flag_drain = False

    routine = DrainWait(on_teardown=teardown)
    routine.run(holder)
    trace = routine.trace
    assert trace.index(("unlock", LOCK_SLOT)) < \
        trace.index(("teardown", TEARDOWN_ARG)) < \
        trace.index(("lock", LOCK_SLOT))


def test_drain_then_wait_when_wait_flag_set_by_teardown():
    holder = Holder(flag_drain=True)

    def teardown():
        holder.flag_drain = False
        holder.flag_wait = True
        holder.watched = object()

    def wait():
        holder.watched = None

    routine = DrainWait(on_teardown=teardown, on_wait=wait)
    assert routine.run(holder) is None
    trace = routine.trace
    assert ("teardown", TEARDOWN_ARG) in trace
    assert ("mutex_lock", MUTEX_OFFSET, 0) in trace
    assert trace.count(("condvar_wait", CONDVAR_OFFSET)) == 1
    assert ("mutex_unlock", MUTEX_OFFSET) in trace
    assert trace.index(("mutex_lock", MUTEX_OFFSET, 0)) < \
        trace.index(("condvar_wait", CONDVAR_OFFSET)) < \
        trace.index(("mutex_unlock", MUTEX_OFFSET))


def test_wait_skipped_when_watched_already_null():
    routine = DrainWait()
    assert routine.run(Holder(flag_wait=True, watched=None)) is None
    assert routine.trace == [("entry_noop", LOCK_SLOT)]


def test_wait_loops_until_watched_clears():
    holder = Holder(flag_wait=True, watched=object())
    waits = []

    def wait():
        waits.append(1)
        if len(waits) == 3:
            holder.watched = None

    routine = DrainWait(on_wait=wait)
    assert routine.run(holder) is None
    assert len(waits) == 3
    assert routine.trace.count(("condvar_wait", CONDVAR_OFFSET)) == 3
    assert routine.trace[-1] == ("mutex_unlock", MUTEX_OFFSET)


def test_mutex_lock_failure_raises_without_wait_or_unlock():
    routine = DrainWait(on_mutex_lock=lambda: 16)
    try:
        routine.run(Holder(flag_wait=True, watched=object()))
    except SystemError as exc:
        assert exc.args == (16,)
    else:
        raise AssertionError("expected SystemError")
    assert ("condvar_wait", CONDVAR_OFFSET) not in routine.trace
    assert ("mutex_unlock", MUTEX_OFFSET) not in routine.trace
    assert routine.trace[-1] == ("throw_system_error", 16)


def test_wait_flag_ignored_while_drain_flag_set():
    # The wait path is only tested after the drain flag reads zero:
    # a drain that never sets the wait flag returns without waiting.
    holder = Holder(flag_drain=True, flag_wait=True)

    def teardown():
        holder.flag_drain = False
        holder.flag_wait = False

    routine = DrainWait(on_teardown=teardown)
    assert routine.run(holder) is None
    assert ("condvar_wait", CONDVAR_OFFSET) not in routine.trace


def test_offsets_match_the_pinned_layout():
    assert ADDRESS == 0x5D51AB0
    assert SIZE_BYTES == 357
    assert LOCK_SLOT == 0x700
    assert FLAG_DRAIN == 0x489
    assert FLAG_WAIT == 0x48A
    assert TEARDOWN_ARG == 0xD40
    assert CONDVAR_OFFSET == 0x14B0
    assert MUTEX_OFFSET == 0x14E0
    assert WATCHED_OFFSET == 0x1508


def test_normal_returns_are_void():
    assert DrainWait().run(Holder()) is None
    holder = Holder(flag_wait=True, watched=object())
    assert DrainWait(on_wait=lambda: setattr(holder, "watched", None)) \
        .run(holder) is None
