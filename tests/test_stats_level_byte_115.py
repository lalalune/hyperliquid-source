"""Tests for the node #115 StatisticsImpl stats_level_ model (RE-001).

Every expectation is grounded in the pinned binary evidence
(research/work-items/RE-001-stats-level-byte-115/): the ctor write,
the four gate compares, the timed-lock helpers and the factories.
Run directly (pytest is not installed on this VM):
    python3 tests/test_stats_level_byte_115.py
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import stats_level_byte_115 as m


class TestStatsLevelEnum(unittest.TestCase):
    def test_values(self):
        self.assertEqual(
            [m.K_DISABLE_ALL, m.K_EXCEPT_HISTOGRAM_OR_TIMERS,
             m.K_EXCEPT_TIMERS, m.K_EXCEPT_DETAILED_TIMERS,
             m.K_EXCEPT_TIME_FOR_MUTEX, m.K_ALL],
            [0, 1, 2, 3, 4, 5])

    def test_names(self):
        self.assertEqual(m.level_name(3), "kExceptDetailedTimers")
        self.assertEqual(m.level_name(5), "kAll")
        self.assertEqual(m.level_name(0), "kDisableAll")

    def test_default_is_not_max(self):
        # The correction to #3572/#3396: the ctor writes 3, the header
        # default, not the maximum (kAll is 5).
        self.assertEqual(m.LEVEL_DEFAULT, 3)
        self.assertEqual(m.LEVEL_MAX, 5)
        self.assertLess(m.LEVEL_DEFAULT, m.LEVEL_MAX)

    def test_ctor_write_site(self):
        self.assertEqual(m.CTOR_WRITE_SITE, 0x6071A32)
        self.assertEqual(m.CTOR_WRITE_VALUE, 3)
        self.assertEqual(m.CTOR_FDE, (0x6071A00, 0x6071B60))
        self.assertEqual(m.LEVEL_OFFSET, 0x20)
        self.assertEqual(m.STATISTICS_VTABLE, 0x64D2D88)


class TestGates(unittest.TestCase):
    def test_record_tick_gate(self):
        # 0x606fba0: level != 0 and id <= 0xb1.
        self.assertFalse(m.record_tick_allowed(0, 0))
        self.assertTrue(m.record_tick_allowed(1, 0))
        self.assertTrue(m.record_tick_allowed(1, 0xB1))
        self.assertFalse(m.record_tick_allowed(1, 0xB2))
        self.assertTrue(m.record_tick_allowed(5, 0xB1))

    def test_record_hist_gate(self):
        # 0x606fef0 / 0x606ffd0: level > 1.
        self.assertFalse(m.record_hist_allowed(0))
        self.assertFalse(m.record_hist_allowed(1))
        self.assertTrue(m.record_hist_allowed(2))
        self.assertTrue(m.record_hist_allowed(5))

    def test_forwarder_gate(self):
        # 0x5d48960: level > 2, then tail-jump to slot 0xd8.
        self.assertFalse(m.forwarder_allowed(2))
        self.assertTrue(m.forwarder_allowed(3))
        self.assertTrue(m.forwarder_allowed(5))

    def test_timed_lock_gate(self):
        # 0x606ca40/0x606ccb0/0x606cf20: stats+clock non-null, level > 4,
        # code == 52 (DB_MUTEX_WAIT_MICROS).
        self.assertTrue(m.timed_lock_allowed(True, True, 5, 52))
        self.assertFalse(m.timed_lock_allowed(True, True, 4, 52))
        self.assertFalse(m.timed_lock_allowed(True, True, 5, 51))
        self.assertFalse(m.timed_lock_allowed(False, True, 5, 52))
        self.assertFalse(m.timed_lock_allowed(True, False, 5, 52))
        self.assertEqual(m.DB_MUTEX_WAIT_MICROS, 52)
        self.assertEqual(m.GATE_TIMED_CODE, 0x34)


class TestStatistics(unittest.TestCase):
    def test_factory_defaults(self):
        s = m.build_statistics()
        self.assertEqual(s.level, 3)
        self.assertIsNone(s.delegate)
        self.assertEqual(s.ticks, {})
        self.assertEqual(s.hists, {})

    def test_set_get_level_roundtrip(self):
        s = m.build_statistics()
        for level in range(6):
            s.set_stats_level(level)
            self.assertEqual(s.get_stats_level(), level)
        with self.assertRaises(ValueError):
            s.set_stats_level(6)
        with self.assertRaises(ValueError):
            s.set_stats_level(-1)

    def test_tick_end_to_end(self):
        s = m.build_statistics()  # level 3
        self.assertTrue(s.record_tick(10, 7))
        self.assertEqual(s.ticks[10], 7)
        s.set_stats_level(0)
        self.assertFalse(s.record_tick(10, 7))
        self.assertEqual(s.ticks[10], 7)
        self.assertFalse(s.record_tick(0xB2, 1))  # id bound
        s.set_stats_level(1)
        self.assertTrue(s.record_tick(0xB1, 1))

    def test_hist_end_to_end(self):
        s = m.build_statistics()
        self.assertTrue(s.record_hist(2, 1.5))
        self.assertEqual(s.hists[2], [1.5])
        s.set_stats_level(1)
        self.assertFalse(s.record_hist(2, 1.5))
        self.assertEqual(s.hists[2], [1.5])
        # The forwarder needs level > 2.
        self.assertFalse(s.record_in_histogram(2, 2.5))
        s.set_stats_level(3)
        self.assertTrue(s.record_in_histogram(2, 2.5))
        self.assertEqual(s.hists[2], [1.5, 2.5])

    def test_delegate_forward(self):
        inner = m.build_statistics()
        outer = m.build_statistics(delegate=inner)
        self.assertTrue(outer.record_tick(5, 3))
        self.assertEqual(inner.ticks[5], 3)
        # The delegate forward for histograms is id-gated at 0x33.
        self.assertTrue(outer.record_hist(0x33, 9.0))
        self.assertEqual(inner.hists[0x33], [9.0])
        self.assertTrue(outer.record_hist(0x34, 9.0))
        self.assertNotIn(0x34, inner.hists)


class TestTimedHelpers(unittest.TestCase):
    def _setup(self, level=5, code=52):
        s = m.build_statistics()
        s.set_stats_level(level)
        clock = m.FakeClock()
        return s, clock

    def test_mutex_lock_timed(self):
        s, clock = self._setup()
        mu = m.InstrumentedMutex(stats=s, clock=clock, code=52)
        kind, elapsed = mu.lock(wait_micros=250)
        self.assertEqual((kind, elapsed), ("timed", 250))
        self.assertEqual(s.ticks[52], 250)
        self.assertTrue(mu.locked)
        mu.unlock()
        self.assertFalse(mu.locked)

    def test_mutex_lock_plain_paths(self):
        # Level 4: plain (no timing, no tick).
        s, clock = self._setup(level=4)
        mu = m.InstrumentedMutex(stats=s, clock=clock, code=52)
        self.assertEqual(mu.lock(), ("plain", 0))
        self.assertNotIn(52, s.ticks)
        # Wrong code: plain even at kAll.
        s2, clock2 = self._setup()
        mu2 = m.InstrumentedMutex(stats=s2, clock=clock2, code=51)
        self.assertEqual(mu2.lock(wait_micros=100), ("plain", 0))
        self.assertNotIn(51, s2.ticks)
        # No stats: plain.
        mu3 = m.InstrumentedMutex(stats=None, clock=clock2, code=52)
        self.assertEqual(mu3.lock(wait_micros=100), ("plain", 0))
        # No clock: plain.
        mu4 = m.InstrumentedMutex(stats=s2, clock=None, code=52)
        self.assertEqual(mu4.lock(wait_micros=100), ("plain", 0))

    def test_condvar_wait(self):
        s, clock = self._setup()
        cv = m.InstrumentedCondVar(stats=s, clock=clock, code=52)
        self.assertEqual(cv.wait(wait_micros=80), ("timed", 80))
        self.assertEqual(s.ticks[52], 80)
        s.set_stats_level(4)
        self.assertEqual(cv.wait(wait_micros=80), ("plain", 0))
        self.assertEqual(s.ticks[52], 80)

    def test_condvar_timedwait(self):
        s, clock = self._setup()
        cv = m.InstrumentedCondVar(stats=s, clock=clock, code=52)
        self.assertEqual(cv.timed_wait(1_500_000, wait_micros=40),
                         ("timed", 40))
        self.assertEqual(s.ticks[52], 40)

    def test_split_microseconds(self):
        self.assertEqual(m.split_microseconds(0), (0, 0))
        self.assertEqual(m.split_microseconds(999999), (0, 999999))
        self.assertEqual(m.split_microseconds(1000000), (1, 0))
        self.assertEqual(m.split_microseconds(1500000), (1, 500000))
        self.assertEqual(m.split_microseconds(123456789),
                         (123, 456789))

    def test_split_magic_matches_plain(self):
        rng = random.Random(20261107)
        for _ in range(200):
            v = rng.randrange(0, 10 ** 12)
            self.assertEqual(m.split_microseconds_magic(v),
                             m.split_microseconds(v))

    def test_tls_once(self):
        once = m.TlsOnce()
        self.assertTrue(once.ensure())
        self.assertFalse(once.ensure())
        self.assertFalse(once.ensure())
        self.assertEqual(once.calls, 3)
        self.assertTrue(once.initialized)


class TestCensusConstants(unittest.TestCase):
    def test_census(self):
        self.assertEqual(m.MARKED_FDES, 62)
        self.assertEqual(m.LEVEL_WRITES, 1)
        self.assertEqual(m.LEVEL_READS, 9)
        self.assertEqual(m.MOVB_STORES_BINARY_WIDE, 16889)
        self.assertEqual(m.MOVZBL_LOADS_BINARY_WIDE, 11335)
        self.assertEqual(m.TIMER_CALLS["mutex-lock"], 244)
        self.assertEqual(m.TIMER_CALLS["condvar-wait"], 27)
        self.assertEqual(m.TIMER_CALLS["condvar-timedwait"], 3)
        self.assertEqual(m.TIMER_CALLS["tls-init"], 500)
        self.assertEqual(sum(m.TIMER_CALLS.values()), 779)
        self.assertEqual(m.HIST_ID_MAX, 0x33)


if __name__ == "__main__":
    unittest.main(verbosity=2)
