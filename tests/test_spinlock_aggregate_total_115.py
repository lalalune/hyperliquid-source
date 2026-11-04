"""Tests for the node #115 spinlock-guarded aggregate total (0x5f0e2d0).

RE-001 work item; packet research/work-items/RE-001-spinlock-aggregate-115/.
Runs under pytest when installed, and under plain python3 via the
__main__ runner below (pytest is not installed on the analysis VM).

Host field keys mirror the window's this-relative offsets:
f0_shift (byte at +0xf0), f928/f938/f940/f948/f950/f960/f9d0/f9e0,
c88/c98. entry_fields are the table entries' +0x38 fields in order.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from spinlock_aggregate_total_115 import (  # noqa: E402
    FakeLock, aggregate_total, spin_acquire)


def base_host(**over):
    host = {"f0_shift": 0, "f928": 0, "f938": 0, "f940": 0,
            "f948": 0, "f950": 0, "f960": 0, "f9d0": 0, "f9e0": 0,
            "c88": 0, "c98": 0}
    host.update(over)
    return host


def test_immediate_acquire():
    lock = FakeLock(0)
    pauses, yields = spin_acquire(lock)
    assert (pauses, yields) == (0, 0)
    assert lock.byte == 1


def test_contended_acquire_no_yield():
    # Lock held for the first 3 checks, then released by the holder.
    seen = {"n": 0}

    class Scripted(FakeLock):
        def read(self):
            seen["n"] += 1
            # Keep the byte in sync: the holder releases the lock
            # after the third check, so the cmpxchg then succeeds.
            self.byte = 1 if seen["n"] <= 3 else 0
            return self.byte

    lock = Scripted(1)
    pauses, yields = spin_acquire(lock)
    assert pauses == 3
    assert yields == 0
    assert lock.byte == 1


def test_contended_acquire_yields_after_101_pauses():
    # Held for the first 150 checks: pauses 1..150, yields on pauses
    # whose entry counter already exceeds 100, i.e. pauses 102..150.
    seen = {"n": 0}

    class Scripted(FakeLock):
        def read(self):
            seen["n"] += 1
            self.byte = 1 if seen["n"] <= 150 else 0
            return self.byte

    lock = Scripted(1)
    pauses, yields = spin_acquire(lock)
    assert pauses == 150
    assert yields == 49
    assert lock.byte == 1


def test_cmpxchg_race_retries():
    # Check sees 0, but a contender grabs the byte before cmpxchg;
    # the next check sees it held, then the holder releases it.
    calls = {"n": 0}

    class Racy(FakeLock):
        def read(self):
            calls["n"] += 1
            return 0 if calls["n"] == 1 else self.byte

        def cmpxchg(self, expected, new):
            if calls["n"] == 1:
                self.byte = 1  # contender wins the race
                return False, 1
            return super().cmpxchg(expected, new)

    lock = Racy(0)
    # Holder releases after the race pause: script via read count.
    orig_read = lock.read

    def read2():
        v = orig_read()
        if calls["n"] >= 3:
            lock.byte = 0
        return v if calls["n"] < 3 else 0

    lock.read = read2
    pauses, yields = spin_acquire(lock)
    assert pauses >= 1
    assert yields == 0
    assert lock.byte == 1


def test_capacity_and_sum():
    # shift 2 -> 4 entries; sum of +0x38 fields.
    out = aggregate_total(base_host(f0_shift=2), [10, 20, 30, 40],
                          lambda: 0, lambda: 0)
    # value0 = 0 + 0 - 100 = 2**64-100; it passes (2**64-100 < 2**64-1),
    # the zero queries pass, and the minimum bufsize 56 passes
    # (56 < 99), so the total is 2**64-100+56 = 2**64-44.
    assert out["value0"] == (1 << 64) - 100
    assert out["result"] == (1 << 64) - 44
    assert out["stored_cd0"] == (1 << 64) - 44


def test_capacity_shift_zero_single_entry():
    # Shift 0 -> capacity 1: a single entry suffices, and a table
    # shorter than capacity is rejected (see also the sum test).
    out = aggregate_total(base_host(f0_shift=0), [0],
                          lambda: 0, lambda: 0)
    assert out["value0"] == 0
    assert out["result"] == 56  # bufsize 8*(0+0+7) only
    try:
        aggregate_total(base_host(f0_shift=1), [0],
                        lambda: 0, lambda: 0)
    except ValueError:
        pass
    else:
        raise AssertionError("short table accepted")


def test_value0_formula_hand_computed():
    # f960-f940 = 0x18 -> /8 = 3 -> -1 = 2 -> <<6 = 128
    # (f948-f950)/8 = -2, (f938-f928)/8 = -4 -> rax = 122
    # (f9e0-f9d0) = 0x100 -> value0 = 256 + 122*8 - 32 = 1200
    host = base_host(f940=0x1000, f960=0x1018, f948=0x2000,
                     f950=0x2010, f938=0x3000, f928=0x3020,
                     f9d0=0x3F00, f9e0=0x4000)
    out = aggregate_total(host, [32], lambda: 0, lambda: 0)
    assert out["value0"] == 1200
    # Plus the minimum bufsize 56 (zero queries): total 1256.
    assert out["result"] == 1256
    assert out["stored_cd0"] == 1256


def test_value0_null_end_quirk():
    # f960 == 0: the adc adds the carry, so rax = 0, not -1.
    host = base_host(f940=0, f960=0)
    out = aggregate_total(host, [0], lambda: 0, lambda: 0)
    assert out["value0"] == 0
    assert out["result"] == 56  # bufsize only


def test_bufsize_formula():
    # 8 * (c88 + 4*c98 + 7) = 8 * (3 + 20 + 7) = 240
    out = aggregate_total(base_host(c88=3, c98=5), [0],
                          lambda: 0, lambda: 0)
    assert out["bufsize"] == 240


def test_overflow_fails_and_stores_nothing():
    # value0 = 2**64-2, then q1 = 1: 1 < ~(2**64-2) = 1 is false.
    out = aggregate_total(base_host(), [2], lambda: 1, lambda: 0)
    assert out["value0"] == (1 << 64) - 2
    assert out["result"] == -1
    assert out["stored_cd0"] is None
    assert out["cleanup_skipped"] is True


def test_overflow_boundary_passes():
    # value0 = 2**64-100: ~running is 99 at the bufsize step, so the
    # minimum bufsize 56 passes and the total is 2**64-44.
    out = aggregate_total(base_host(), [100], lambda: 0, lambda: 0)
    assert out["value0"] == (1 << 64) - 100
    assert out["result"] == (1 << 64) - 44
    assert out["stored_cd0"] == (1 << 64) - 44


def test_first_value_at_ceiling_fails():
    # v = 2**64-1 is not < ~0 = 2**64-1.
    out = aggregate_total(base_host(), [1], lambda: 0, lambda: 0)
    assert out["value0"] == (1 << 64) - 1
    assert out["result"] == -1
    assert out["stored_cd0"] is None


def test_end_to_end_with_queries():
    # value0 = 1200 (as in the hand-computed test), q1 = 5, q2 = 7,
    # bufsize = 8*(0+0+7) = 56 -> total 1268.
    host = base_host(f940=0x1000, f960=0x1018, f948=0x2000,
                     f950=0x2010, f938=0x3000, f928=0x3020,
                     f9d0=0x3F00, f9e0=0x4000)
    out = aggregate_total(host, [32], lambda: 5, lambda: 7)
    assert out["value0"] == 1200
    assert out["q_a50"] == 5
    assert out["q_a58"] == 7
    assert out["bufsize"] == 56
    assert out["result"] == 1268
    assert out["stored_cd0"] == 1268
    assert out["cleanup"] is None


def test_cleanup_triple_zero_is_noop():
    out = aggregate_total(base_host(), [0], lambda: 0, lambda: 0,
                          triple=(0, 0, 0))
    assert out["cleanup"] is None


def test_cleanup_triple_nonzero_deletes():
    out = aggregate_total(base_host(), [0], lambda: 0, lambda: 0,
                          triple=(0x5000, 0x4000, 0x5200))
    assert out["cleanup"] == ("delete", 0x5000, 0x200)
    assert out["triple_stored"] == 0x5000


def test_packet_records_window():
    here = os.path.dirname(os.path.abspath(__file__))
    packet = os.path.join(here, "..", "research", "work-items",
                          "RE-001-spinlock-aggregate-115", "records.json")
    records = json.load(open(packet))
    assert records["window"]["start"] == "0x5f0e2d0"
    assert records["window"]["end"] == "0x5f0e51b"
    assert records["window"]["artifact_sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")


def _run_all():
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    for name, fn in fns:
        fn()
        print("ok", name)
    print("all %d tests passed" % len(fns))


if __name__ == "__main__":
    _run_all()
