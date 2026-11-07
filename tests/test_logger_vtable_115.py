"""Tests for tools/logger_vtable_115.py (RE-001, node #115).

Each test drives a model rule end-to-end (inputs through the model to
an observable output), grounded in the evidence packet
research/work-items/RE-001-logger-vtable-full-map-115/:
  - the vtable slot maps (vtables.tsv / records.json),
  - the level gates (slot 5 reads the own +0x11; slot 8 returns the
    wrapped logger's level when present),
  - the Logv write path (timestamp format, trailing newline, dirty
    flag, cached-size refresh threshold 0x4c4b3f),
  - the rollover triggers (size >= +0xd8, time check),
  - the writer error contract and the CloseImpl error message,
  - the object sizes (EnvLogger 0x140 in a 0x150 control block;
    AutoRollLogger 0x290).
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import logger_vtable_115 as m


class TestSlotMaps(unittest.TestCase):
    def test_both_vtables_have_11_slots(self):
        self.assertEqual(len(m.ENVLOGGER_SLOTS), 11)
        self.assertEqual(len(m.AUTOROLL_SLOTS), 11)
        for slots in (m.ENVLOGGER_SLOTS, m.AUTOROLL_SLOTS):
            self.assertEqual(sorted(slots), list(range(11)))

    def test_shared_slots(self):
        # Close (2) and the leveled Logv (5) are the same function in
        # both vtables.
        for slot in m.SHARED_SLOTS:
            self.assertEqual(m.slot_fn(m.ENVLOGGER_VTABLE, slot),
                             m.slot_fn(m.AUTOROLL_VTABLE, slot))
        self.assertEqual(m.slot_fn(m.ENVLOGGER_VTABLE, 2), 0x5FCC410)
        self.assertEqual(m.slot_fn(m.ENVLOGGER_VTABLE, 5), 0x5FCD400)

    def test_overridden_slots_differ(self):
        # Every slot except 2 and 5 has a distinct AutoRollLogger body.
        for slot in range(11):
            if slot in m.SHARED_SLOTS:
                continue
            self.assertNotEqual(
                m.slot_fn(m.ENVLOGGER_VTABLE, slot),
                m.slot_fn(m.AUTOROLL_VTABLE, slot),
                f"slot {slot} should be overridden")

    def test_slot_names(self):
        self.assertEqual(m.slot_name(m.ENVLOGGER_VTABLE, 4),
                         "Logv(const char*, va_list)")
        self.assertEqual(m.slot_name(m.ENVLOGGER_VTABLE, 6),
                         "GetLogFileSize() const")
        self.assertEqual(m.slot_name(m.AUTOROLL_VTABLE, 4),
                         "Logv(const char*, va_list)")
        self.assertEqual(m.slot_name(m.AUTOROLL_VTABLE, 10), "CloseImpl()")
        # Slots 11+ are unpinned.
        self.assertIsNone(m.slot_name(m.ENVLOGGER_VTABLE, 11))
        self.assertIsNone(m.slot_fn(m.AUTOROLL_VTABLE, 12))
        self.assertIsNone(m.slot_name(0xDEADBEEF, 0))

    def test_vtable_addresses(self):
        self.assertEqual(m.ENVLOGGER_VTABLE, 0x64CDA68)
        self.assertEqual(m.AUTOROLL_VTABLE, 0x64D1F00)


class TestLevelGates(unittest.TestCase):
    def test_gate_drops_below_level(self):
        # log_level_ = ERROR (3, the factory default): DEBUG/INFO/WARN
        # are dropped, ERROR/FATAL/HEADER are written.
        for level in (m.DEBUG_LEVEL, m.INFO_LEVEL, m.WARN_LEVEL):
            self.assertFalse(m.level_gate(m.ERROR_LEVEL, level))
        for level in (m.ERROR_LEVEL, m.FATAL_LEVEL, m.HEADER_LEVEL):
            self.assertTrue(m.level_gate(m.ERROR_LEVEL, level))

    def test_gate_at_info_writes_all_but_debug(self):
        self.assertFalse(m.level_gate(m.INFO_LEVEL, m.DEBUG_LEVEL))
        for level in (m.INFO_LEVEL, m.WARN_LEVEL, m.ERROR_LEVEL,
                      m.FATAL_LEVEL, m.HEADER_LEVEL):
            self.assertTrue(m.level_gate(m.INFO_LEVEL, level))

    def test_logheader_forwards_at_info(self):
        # LogHeader forwards with level 1; it is written iff
        # 1 >= log_level_.
        self.assertTrue(m.level_gate(m.INFO_LEVEL, 1))
        self.assertFalse(m.level_gate(m.WARN_LEVEL, 1))

    def test_autoroll_get_level_prefers_wrapped(self):
        # Slot 8 returns the wrapped logger's level when present,
        # else the own +0x11.
        self.assertEqual(m.autoroll_get_log_level(2, 3), 2)
        self.assertEqual(m.autoroll_get_log_level(None, 3), 3)

    def test_autoroll_get_level_desync(self):
        # The #4315 discrepancy, resolved: slot 8 reports the wrapped
        # level while the shared slot-5 gate reads the own +0x11, so
        # the two can disagree -- the gate drops a level-2 message
        # even though slot 8 reports level 2.
        own, wrapped = 3, 2
        self.assertFalse(m.level_gate(own, 2))
        self.assertEqual(m.autoroll_get_log_level(wrapped, own), 2)

    def test_autoroll_set_level_updates_both(self):
        self.assertTrue(m.autoroll_set_log_level(True))
        self.assertFalse(m.autoroll_set_log_level(False))


class TestLogvWritePath(unittest.TestCase):
    def test_timestamp_prefix(self):
        line = m.timestamp_prefix(2026, 11, 8, 4, 5, 45, 123456, 789)
        self.assertEqual(line, "2026/11/08-04:05:45.123456 789 ")
        # The format pads each field: single-digit values are
        # zero-padded, the thread id is not.
        self.assertEqual(
            m.timestamp_prefix(2026, 1, 2, 3, 4, 5, 6, 7),
            "2026/01/02-03:04:05.000006 7 ")

    def test_ensure_trailing_newline(self):
        self.assertEqual(m.ensure_trailing_newline("abc\n"), "abc\n")
        self.assertEqual(m.ensure_trailing_newline("abc"), "abc\n")
        self.assertEqual(m.ensure_trailing_newline(""), "\n")

    def test_size_refresh_threshold(self):
        # Exactly at the threshold: no refresh (the binary uses >).
        self.assertFalse(m.size_refresh_needed(0x4C4B3F, 0))
        self.assertTrue(m.size_refresh_needed(0x4C4B40, 0))
        # Growth below the threshold does not refresh.
        self.assertFalse(m.size_refresh_needed(1000, 0))
        # A refresh resets the baseline, so the next small growth does
        # not refresh again.
        self.assertFalse(m.size_refresh_needed(0x4C4B40 + 100,
                                               0x4C4B40))

    def test_perf_timing_active(self):
        for level in (0, 1, 2):
            self.assertFalse(m.perf_timing_active(level))
        for level in (3, 4):
            self.assertTrue(m.perf_timing_active(level))

    def test_buffer_growth_doubles(self):
        self.assertEqual(m.buffer_growth(8, 8), 8)
        self.assertEqual(m.buffer_growth(8, 9), 16)
        self.assertEqual(m.buffer_growth(8, 100), 128)
        self.assertEqual(m.buffer_growth(1, 1), 1)


class TestRollover(unittest.TestCase):
    def test_size_gate(self):
        self.assertTrue(m.roll_needed(1000, 1000, False))
        self.assertTrue(m.roll_needed(1001, 1000, False))
        self.assertFalse(m.roll_needed(999, 1000, False))

    def test_no_size_roll_when_zero(self):
        # log_max_size == 0 means no size roll, whatever the size.
        self.assertFalse(m.roll_needed(10 ** 9, 0, False))

    def test_time_gate(self):
        self.assertTrue(m.roll_needed(0, 0, True))
        self.assertFalse(m.roll_needed(0, 0, False))

    def test_either_gate_rolls(self):
        self.assertTrue(m.roll_needed(5, 1000, True))
        self.assertTrue(m.roll_needed(2000, 1000, False))


class TestWriterAndClose(unittest.TestCase):
    def test_writer_previous_error(self):
        code, msg = m.writer_append(True)
        self.assertEqual(code, m.K_IO_ERROR)
        self.assertEqual(msg, "Writer has previous error.")
        self.assertEqual(m.writer_append(False), (0, ""))

    def test_close_error_message(self):
        self.assertEqual(
            m.close_error_message("disk full"),
            "Close of log file failed with error:disk full")

    def test_close_idempotent(self):
        # Already closed: CloseImpl is not called again.
        called, closed = m.close_impl(True)
        self.assertFalse(called)
        self.assertTrue(closed)
        # Open: CloseImpl runs and closed_ becomes set.
        called, closed = m.close_impl(False)
        self.assertTrue(called)
        self.assertTrue(closed)

    def test_autoroll_close_impl(self):
        self.assertEqual(m.autoroll_close_impl(False), "OK")
        self.assertEqual(m.autoroll_close_impl(True),
                         "delegated to wrapped Close")

    def test_autoroll_get_file_size(self):
        self.assertEqual(m.autoroll_get_log_file_size(False, 123), 0)
        self.assertEqual(m.autoroll_get_log_file_size(True, 123), 123)


class TestLayouts(unittest.TestCase):
    def test_object_sizes(self):
        self.assertEqual(m.ENVLOGGER_SIZE, 0x140)
        self.assertEqual(m.ENVLOGGER_CONTROL_BLOCK_SIZE, 0x150)
        self.assertEqual(m.AUTOROLL_SIZE, 0x290)
        # EnvLogger sits at control+0x10 inside its control block.
        self.assertEqual(m.ENVLOGGER_CONTROL_BLOCK_SIZE
                         - m.ENVLOGGER_SIZE, 0x10)

    def test_envlogger_offsets(self):
        self.assertEqual(m.ENVLOGGER_OFF["closed_"], 0x10)
        self.assertEqual(m.ENVLOGGER_OFF["log_level_"], 0x11)
        self.assertEqual(m.ENVLOGGER_OFF["cached_size"], 0x98)
        self.assertEqual(m.ENVLOGGER_OFF["mutex"], 0x108)
        self.assertEqual(m.ENVLOGGER_OFF["last_size"], 0x130)
        self.assertEqual(m.ENVLOGGER_OFF["dirty"], 0x138)

    def test_autoroll_offsets(self):
        self.assertEqual(m.AUTOROLL_OFF["logger_"], 0xB8)
        self.assertEqual(m.AUTOROLL_OFF["log_max_size"], 0xD8)
        self.assertEqual(m.AUTOROLL_OFF["time_to_roll"], 0xE0)
        self.assertEqual(m.AUTOROLL_OFF["headers"], 0xF0)
        self.assertEqual(m.AUTOROLL_OFF["header_count"], 0x100)
        self.assertEqual(m.AUTOROLL_OFF["mutex"], 0x268)

    def test_constants(self):
        self.assertEqual(m.SIZE_REFRESH_THRESHOLD, 0x4C4B3F)
        self.assertEqual(m.K_IO_ERROR, 5)
        self.assertEqual(m.TIMESTAMP_FORMAT,
                         "%04d/%02d/%02d-%02d:%02d:%02d.%06d %llu ")
        self.assertEqual(m.ARTIFACT_SHA256,
                         "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")


if __name__ == "__main__":
    unittest.main()
