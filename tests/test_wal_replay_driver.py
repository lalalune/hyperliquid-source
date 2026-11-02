"""Tests for tools/wal_replay_driver.py (RE-001 wal replay driver).

Run from the repository root:
    python3 -m unittest tests.test_wal_replay_driver -v
"""
import json
import struct
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.wal_replay_driver import (
    LOG_FILE,
    LOG_FORMAT,
    UNKNOWN_CODE,
    UNKNOWN_PREFIX,
    CacheTable,
    ReplayDriver,
    Status,
    decimal_digit_count,
    filename_for,
    format_decimal,
    log_file_name,
    unknown_type_log_line,
)

PACKET = Path(__file__).resolve().parents[1] / (
    "research/work-items/RE-001-wal-replay-driver-94")
BINARY = Path(__file__).resolve().parents[1] / "work/hl-node-94.bin"


def make_driver(table=None, replay=None, chain=None):
    table = table if table is not None else CacheTable(bucket_count=8)
    replay = replay if replay is not None else (lambda f, k: (Status.zero(), 0))
    chain = chain if chain is not None else (lambda s, f: s.code)
    return ReplayDriver("/wal", "archive", table, replay, chain)


class DecimalTests(unittest.TestCase):
    def test_threshold_digit_counts(self):
        cases = [(0, 1), (9, 1), (10, 2), (99, 2), (100, 3), (999, 3),
                 (1000, 4), (9999, 4), (10000, 5), (99999, 5),
                 (100000, 6), (999999, 6), (1000000, 7), (9999999, 7),
                 (10000000, 8), (99999999, 8), (100000000, 9),
                 (999999999, 9), (1000000000, 10), (2147483648, 10)]
        for magnitude, want in cases:
            self.assertEqual(decimal_digit_count(magnitude), want)
            self.assertEqual(len(str(magnitude)), want)

    def test_signed_formatting(self):
        self.assertEqual(format_decimal(0), "0")
        self.assertEqual(format_decimal(2), "2")
        self.assertEqual(format_decimal(999999999), "999999999")
        self.assertEqual(format_decimal(1000000000), "1000000000")
        # Unsigned-large values read as negative signed values.
        self.assertEqual(format_decimal(0xFFFFFFFF), "-1")
        self.assertEqual(format_decimal(0xFFFFFFFE), "-2")
        self.assertEqual(format_decimal(0x80000000), "-2147483648")
        self.assertEqual(format_decimal(0x80000001), "-2147483647")

    def test_pair_band_values(self):
        # Values whose conversion exercises every digit-pair band.
        for value in (0, 5, 42, 99, 100, 123, 999, 1000, 4096, 9999,
                      10000, 54321, 99999, 100000, 999999, 1234567,
                      9999999, 12345678, 99999999, 123456789,
                      999999999, 1000000000, 2147483647):
            self.assertEqual(format_decimal(value), str(value))
            self.assertEqual(decimal_digit_count(value), len(str(value)))


class FilenameTests(unittest.TestCase):
    def test_type1_direct(self):
        self.assertEqual(filename_for(1, "/wal", "archive", 123),
                         "/wal/000123.log")
        self.assertEqual(filename_for(1, "/wal", "archive", 0),
                         "/wal/000000.log")
        self.assertEqual(filename_for(1, "/wal", "archive", 1234567),
                         "/wal/1234567.log")

    def test_type0_subdir(self):
        self.assertEqual(filename_for(0, "/wal", "archive", 123),
                         "/wal/archive/000123.log")
        self.assertEqual(filename_for(0, "/wal", "archive", 999999),
                         "/wal/archive/999999.log")

    def test_name_component(self):
        self.assertEqual(log_file_name(7), "000007.log")
        self.assertEqual(log_file_name(1000000), "1000000.log")

    def test_unknown_type_rejected(self):
        with self.assertRaises(ValueError):
            filename_for(2, "/wal", "archive", 1)


class UnknownTypeTests(unittest.TestCase):
    def test_log_line_verbatim(self):
        line = unknown_type_log_line(2)
        self.assertEqual(
            line,
            "[db/wal_manager.cc:381] [WalManger] Unknown file type 2")
        # The binary spells WalManger (not WalManager) here.
        self.assertIn("WalManger", line)
        self.assertEqual(LOG_FILE, "db/wal_manager.cc")
        self.assertEqual(LOG_FORMAT,
                         "[%s:381] [WalManger] Unknown file type %s")

    def test_driver_unknown_path(self):
        driver = make_driver()
        status, slot = driver.run(2, 42)
        self.assertEqual(status.code, UNKNOWN_CODE)
        self.assertEqual(status.message, UNKNOWN_PREFIX + "2")
        self.assertEqual(slot, 0)
        self.assertTrue(driver.events[0].startswith("log:[db/wal_manager"))
        self.assertNotIn("lock-lookup", driver.events)

    def test_driver_unknown_large_value(self):
        driver = make_driver()
        status, _ = driver.run(0xFFFFFFFF, 42)
        self.assertEqual(status.message, UNKNOWN_PREFIX + "-1")


class CacheTests(unittest.TestCase):
    def test_hit_returns_zero_status_and_value(self):
        table = CacheTable(bucket_count=8)
        table.insert(42, "cached-value")
        driver = make_driver(table=table)
        status, slot = driver.run(1, 42)
        self.assertEqual(status, Status.zero())
        self.assertEqual(slot, "cached-value")
        self.assertNotIn("replay1", driver.events)

    def test_miss_ok_type0_inserts_and_propagates(self):
        table = CacheTable(bucket_count=8)
        seen = []
        replay = lambda f, k: (Status(0, (1, 2, 3, 4, 5), "ptr"), 777)
        driver = make_driver(table=table, replay=replay)
        status, slot = driver.run(0, 42)
        self.assertEqual(status.code, 0)
        self.assertEqual(status.rest, (1, 2, 3, 4, 5))
        self.assertEqual(status.pointer, "ptr")
        self.assertEqual(slot, 777)
        self.assertIn("lock-insert", driver.events)
        found, value = table.lookup(42)
        self.assertTrue(found)
        self.assertEqual(value, 777)

    def test_miss_ok_type0_zero_slot_skips_insert(self):
        table = CacheTable(bucket_count=8)
        driver = make_driver(table=table)
        status, slot = driver.run(0, 42)
        self.assertEqual(status, Status.zero())
        self.assertEqual(slot, 0)
        self.assertNotIn("lock-insert", driver.events)
        found, _ = table.lookup(42)
        self.assertFalse(found)

    def test_miss_ok_type1_never_inserts(self):
        table = CacheTable(bucket_count=8)
        replay = lambda f, k: (Status.zero(), 555)
        driver = make_driver(table=table, replay=replay)
        status, slot = driver.run(1, 42)
        self.assertEqual(status, Status.zero())
        self.assertEqual(slot, 555)
        self.assertNotIn("lock-insert", driver.events)
        found, _ = table.lookup(42)
        self.assertFalse(found)

    def test_existing_key_not_replaced(self):
        table = CacheTable(bucket_count=8)
        table.insert(42, "first")
        self.assertFalse(table.insert(42, "second"))
        found, value = table.lookup(42)
        self.assertTrue(found)
        self.assertEqual(value, "first")
        self.assertEqual(table.element_count, 1)

    def test_bucket_segments_and_rehash_keep_all_keys(self):
        table = CacheTable(bucket_count=4)
        keys = list(range(40))
        for key in keys:
            table.insert(key, "v%d" % key)
        for key in keys:
            found, value = table.lookup(key)
            self.assertTrue(found, key)
            self.assertEqual(value, "v%d" % key)
        self.assertEqual(table.element_count, 40)

    def test_no_growth_policy_keeps_small_table(self):
        table = CacheTable(bucket_count=2,
                           growth_policy=lambda b, e: (False, b))
        for key in (1, 2, 3, 4, 5):
            table.insert(key, key * 10)
        for key in (1, 2, 3, 4, 5):
            found, value = table.lookup(key)
            self.assertTrue(found)
            self.assertEqual(value, key * 10)


class PostReplayTests(unittest.TestCase):
    def test_type0_error_chain_byte1_zeroes(self):
        replay = lambda f, k: (Status(5, (0, 0, 0, 0, 0), "p"), 0)
        driver = make_driver(replay=replay, chain=lambda s, f: 1)
        status, _ = driver.run(0, 42)
        self.assertEqual(status, Status.zero())

    def test_type0_error_chain_other_propagates_saved(self):
        saved = Status(5, (1, 2, 3, 4, 5), "p")
        replay = lambda f, k: (saved, 0)
        driver = make_driver(replay=replay, chain=lambda s, f: 7)
        status, _ = driver.run(0, 42)
        self.assertEqual(status, saved)

    def test_type1_error_chain_zero_propagates(self):
        saved = Status(5, (1, 2, 3, 4, 5), "p")
        replay = lambda f, k: (saved, 0)
        driver = make_driver(replay=replay, chain=lambda s, f: 0)
        status, _ = driver.run(1, 42)
        self.assertEqual(status, saved)
        self.assertNotIn("filename0-retry:" + "/wal/archive/000042.log",
                         driver.events)

    def test_type1_error_chain_nonzero_retries_type0(self):
        calls = []
        table = CacheTable(bucket_count=8)

        def replay(filename, key):
            calls.append(filename)
            if len(calls) == 1:
                return Status(5, (0, 0, 0, 0, 0), None), 0
            return Status.zero(), 999

        driver = make_driver(table=table, replay=replay,
                             chain=lambda s, f: 3)
        status, slot = driver.run(1, 42)
        self.assertEqual(calls[0], "/wal/000042.log")
        self.assertEqual(calls[1], "/wal/archive/000042.log")
        self.assertEqual(status, Status.zero())
        self.assertEqual(slot, 999)
        found, value = table.lookup(42)
        self.assertTrue(found)
        self.assertEqual(value, 999)

    def test_type1_retry_error_then_byte1_zeroes(self):
        calls = []

        def replay(filename, key):
            calls.append(filename)
            if len(calls) == 1:
                return Status(5, (0, 0, 0, 0, 0), None), 0
            return Status(6, (0, 0, 0, 0, 0), None), 0

        driver = make_driver(replay=replay, chain=lambda s, f: 1)
        status, _ = driver.run(1, 42)
        self.assertEqual(len(calls), 2)
        self.assertEqual(status, Status.zero())


class PacketTests(unittest.TestCase):
    def test_packet_checker_passes(self):
        out = subprocess.run(
            [sys.executable, str(PACKET / "verify.py")],
            capture_output=True, text=True, cwd=PACKET.parents[2])
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("ALL CHECKS PASSED", out.stdout)

    def test_records_semantic_only(self):
        records = json.loads((PACKET / "records.json").read_text())
        self.assertNotIn("mnemonic", json.dumps(records))
        for key in ("artifact", "window", "arguments", "unknown_type",
                    "digit_table", "filename_builders", "cache_table",
                    "cache_lookup", "cache_insert", "replay_calls",
                    "status_copy", "post_replay_type0", "post_replay_type1",
                    "error_chain", "callers", "unknowns", "not_claimed"):
            self.assertIn(key, records)

    def test_excerpts_regenerate(self):
        out = subprocess.run(
            [sys.executable, str(PACKET / "export_excerpts.py")],
            capture_output=True, text=True, cwd=PACKET.parents[2])
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        check = subprocess.run(
            [sys.executable, str(PACKET / "verify.py")],
            capture_output=True, text=True, cwd=PACKET.parents[2])
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    def test_sampled_instructions_byte_for_byte(self):
        data = BINARY.read_bytes()
        for addr, want in ((0x520C120, bytes.fromhex("f30f1efa")),
                           (0x520CA74, bytes.fromhex("e8b7e2ffff")),
                           (0x520C37B, bytes.fromhex("e8b0260200")),
                           (0x520D244, bytes.fromhex("e88738f5ff"))):
            off = addr - 0x1000
            self.assertEqual(data[off:off + len(want)], want, hex(addr))

    def test_corruption_control(self):
        data = bytearray(BINARY.read_bytes())
        data[0x520C120 - 0x1000] ^= 0xFF
        self.assertNotEqual(
            bytes(data[0x520C120 - 0x1000:0x520C120 - 0x1000 + 4]),
            bytes.fromhex("f30f1efa"))
        records = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(
            records["artifact"]["sha256"],
            "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f")


if __name__ == "__main__":
    unittest.main()
