"""Tests for the node #115 rocksdb::WritableFileWriter::WriteBufferedWithChecksum model.

Replays all 2,400 cases in cases.tsv through the tool, then checks
the model's key behaviours directly: the seen-error gate, the
zero-size call (NO short-circuit -- one zero-length Append carrying
the buffered checksum), the rate-limiter DRAIN loop (grants are
consumed, then exactly ONE Append; the IO_TOTAL skip), the
single-Append failure return (seen_error_ set after the
notifications, no flushed_size_ advance), the checksum HANDOFF (the
entry buffered_data_crc32c_checksum_, never a fresh crc32c::Value),
the listener events (finish type 1, failure type 8 with trailing
(left, old_size)), the timer guards (nanos armed iff perf_level > 2,
CPU iff > 3, with the stop-order asymmetry), the IOStats bytes
counter and its flag, the four TEST_SYNC_POINT sites, the caller
census (Flush + Append x2), the CRC32C chain (Value + Mask +
Combine), the DecideRateLimiterPriority matrix, the IOOptions
defaults, the writer layout bindings, the FDE body hashes, and the
live engine check (a real file written by the model matches the
model's file image).
"""

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import writable_file_writer_writebufferedwithchecksum115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-rocksdb-writable-file-writer-writebufferedwithchecksum-115")


def _read_cases():
    rows = []
    with open(PACKET / "cases.tsv") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    return rows


def _writer(over=None, file_over=None, script=None):
    return m.make_writer(over, file_over, script)


def _wbc(state, data, size, priority=m.IO_TOTAL):
    return m.write_buffered_with_checksum(state, data, size, priority)


def _events(state):
    return state.events + state.file.events


def _ops(state):
    return [e["op"] for e in _events(state)]


class ReplayTests(unittest.TestCase):
    def test_case_count(self):
        rows = _read_cases()
        self.assertEqual(len(rows), 2400)
        groups = {}
        for r in rows:
            groups[r["group"]] = groups.get(r["group"], 0) + 1
        self.assertEqual(groups, {"gate": 600, "grant_loop": 600,
                                  "checksum": 600, "bindings": 600})

    def test_all_cases_replay(self):
        self.assertTrue(m.verify_cases(PACKET / "cases.tsv"))

    def test_case_ids_unique(self):
        rows = _read_cases()
        ids = [r["case_id"] for r in rows]
        self.assertEqual(len(ids), len(set(ids)))

    def test_grant_loop_rows_cover_failures(self):
        rows = _read_cases()
        grows = [json.loads(r["expected_json"])
                 for r in rows if r["group"] == "grant_loop"]
        failed = [e for e in grows if e.get("seen_error")]
        multi = [e for e in grows if len(e.get("wbc_grants", [])) >= 2]
        # Both the single-Append failure arm and multi-grant drains
        # are exercised: failed rows advance nothing.
        self.assertGreater(len(failed), 50)
        self.assertGreater(len(multi), 100)
        for e in failed:
            # The scripted failure is ERR_IO (code 5) or
            # ERR_CORRUPTION (code 2) on the single Append.
            self.assertIn(e["return_status"]["code"], (2, 5))


class GateTests(unittest.TestCase):
    def test_seen_error_returns_prev_error_and_writes_nothing(self):
        state = _writer({"seen_error": True, "cursize": 5,
                         "buf_hex": b"hello".hex()})
        s = _wbc(state, b"hello world", 11)
        self.assertFalse(s.is_ok())
        self.assertEqual(s.code, 5)
        self.assertEqual(s.summary()["state"], 1)
        self.assertEqual(len(state.file.image), 0)
        self.assertEqual(state.wbc_append_calls, 0)
        # The gate reads seen_error_ first: nothing else changes.
        self.assertEqual(state.buf.cursize, 5)
        self.assertEqual(state.flushed_size, 0)

    def test_zero_size_runs_one_zero_length_append(self):
        state = _writer({"cursize": 100, "buf_hex": bytes(100).hex(),
                         "buffered_data_crc32c_checksum": 0xDEADBEEF,
                         "perform_data_verification": True})
        s = _wbc(state, b"", 0)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.buf.cursize, 0)
        self.assertEqual(state.buffered_data_crc32c_checksum, 0)
        # NO zero-size short-circuit (unlike WriteBuffered): one
        # zero-length Append carrying the buffered checksum.
        self.assertEqual(state.wbc_append_calls, 1)
        self.assertEqual(len(state.file.image), 0)
        appends = [e for e in state.file.events
                   if e["op"] == "file_append"]
        self.assertEqual(len(appends), 1)
        self.assertEqual(appends[0]["checksum"], 0xDEADBEEF)

    def test_single_append_no_limiter(self):
        state = _writer()
        s = _wbc(state, b"0123456789", 10)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.wbc_grants, [])
        self.assertEqual(state.wbc_append_calls, 1)
        self.assertEqual(state.wbc_get_file_size_calls, 1)
        self.assertEqual(state.flushed_size, 10)
        self.assertEqual(bytes(state.file.image), b"0123456789")
        self.assertEqual(state.buf.cursize, 0)

    def test_io_total_priority_skips_limiter(self):
        limiter = m.FakeRateLimiter([1])
        state = _writer({"rate_limiter_grants": [1]})
        state.rate_limiter = limiter
        s = _wbc(state, b"0123456789", 10, m.IO_TOTAL)
        self.assertTrue(s.is_ok())
        self.assertEqual(limiter.calls, [])
        self.assertEqual(state.wbc_grants, [])
        self.assertEqual(state.wbc_append_calls, 1)

    def test_non_total_priority_consults_limiter(self):
        state = _writer({"rate_limiter_grants": [4]})
        s = _wbc(state, b"0123456789", 10, m.IO_LOW)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.wbc_grants, [4, 6])
        self.assertEqual(state.wbc_append_calls, 1)
        self.assertEqual(state.flushed_size, 10)


class DrainTests(unittest.TestCase):
    def test_drain_loop_consumes_full_size_then_one_append(self):
        state = _writer({"rate_limiter_grants": [100, 1000, 4096]})
        data = bytes(range(256)) * 19 + bytes(range(136))
        assert len(data) == 5000
        s = _wbc(state, data, 5000, m.IO_LOW)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.wbc_grants, [100, 1000, 3900])
        self.assertEqual(state.wbc_append_calls, 1)
        self.assertEqual(state.flushed_size, 5000)
        self.assertEqual(bytes(state.file.image), data)

    def test_grant_exhaustion_falls_back_to_remaining(self):
        state = _writer({"rate_limiter_grants": [4]})
        s = _wbc(state, b"0123456789", 10, m.IO_LOW)
        self.assertTrue(s.is_ok())
        # The limiter's scripted grants run out after one call;
        # the tail grant takes granted = remaining.
        self.assertEqual(state.wbc_grants, [4, 6])
        self.assertEqual(state.wbc_append_calls, 1)
        self.assertEqual(state.flushed_size, 10)

    def test_append_failure_advances_nothing(self):
        state = _writer({"rate_limiter_grants": [100, 100]})
        state.script = {"append_statuses": [dict(m.ERR_IO)]}
        data = bytes([0xAB]) * 200
        s = _wbc(state, data, 200, m.IO_LOW)
        self.assertFalse(s.is_ok())
        self.assertEqual(s.code, 5)
        self.assertTrue(state.seen_error)
        self.assertEqual(state.wbc_grants, [100, 100])
        self.assertEqual(state.wbc_append_calls, 1)
        self.assertEqual(state.flushed_size, 0)
        self.assertEqual(len(state.file.image), 0)
        self.assertEqual(state.buf.cursize, 0)
        self.assertEqual(state.buffered_data_crc32c_checksum, 0)

    def test_get_file_size_called_once_and_discarded(self):
        state = _writer({"rate_limiter_grants": [5, 5]})
        s = _wbc(state, b"0123456789", 10, m.IO_LOW)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.wbc_get_file_size_calls, 1)
        gets = [e for e in state.file.events
                if e["op"] == "get_file_size"]
        self.assertEqual(len(gets), 1)
        # The return is discarded: the file length is not used
        # anywhere in the outcome (flushed_size_ tracks size).
        self.assertEqual(state.flushed_size, 10)


class ChecksumTests(unittest.TestCase):
    def test_checksum_is_always_the_buffered_handoff(self):
        # Verification off: the checksum arm is still taken.
        state = _writer({"perform_data_verification": False,
                         "buffered_data_crc32c_checksum": 0x12345678})
        s = _wbc(state, b"hello world", 11)
        self.assertTrue(s.is_ok())
        appends = [e for e in state.file.events
                   if e["op"] == "file_append"]
        self.assertEqual(appends[0]["checksum"], 0x12345678)
        # Verification on: same handoff, not a fresh Value.
        state = _writer({"perform_data_verification": True,
                         "buffered_data_crc32c_checksum": 0x12345678})
        s = _wbc(state, b"hello world", 11)
        self.assertTrue(s.is_ok())
        appends = [e for e in state.file.events
                   if e["op"] == "file_append"]
        self.assertEqual(appends[0]["checksum"], 0x12345678)
        self.assertNotEqual(appends[0]["checksum"],
                           m.crc32c_value(b"hello world"))

    def test_handoff_not_fresh_value_over_grants(self):
        state = _writer({"perform_data_verification": True,
                         "buffered_data_crc32c_checksum": 0x12345678,
                         "rate_limiter_grants": [5, 6]})
        s = _wbc(state, b"hello world", 11, m.IO_LOW)
        self.assertTrue(s.is_ok())
        appends = [e for e in state.file.events
                   if e["op"] == "file_append"]
        # One Append, one handoff: the entry buffered value.
        self.assertEqual(len(appends), 1)
        self.assertEqual(appends[0]["checksum"], 0x12345678)

    def test_failure_resets_checksum(self):
        state = _writer({"perform_data_verification": True,
                         "buffered_data_crc32c_checksum": 0x12345678})
        state.script = {"append_statuses": [dict(m.ERR_IO)]}
        s = _wbc(state, b"hello", 5)
        self.assertFalse(s.is_ok())
        self.assertEqual(state.buffered_data_crc32c_checksum, 0)
        self.assertEqual(state.buf.cursize, 0)


class ListenerTests(unittest.TestCase):
    def test_no_listeners_no_notify_events(self):
        state = _writer({"listeners": [], "perf_level": 5,
                         "clock_pairs": m._clock_pairs()})
        s = _wbc(state, b"0123456789", 10)
        self.assertTrue(s.is_ok())
        self.assertEqual([e for e in _events(state)
                          if e["op"].startswith("notify_")], [])

    def test_finish_event_type_1(self):
        pairs = [(1000000 + 1000 * j, 500000 + 700 * j)
                 for j in range(8)]
        state = _writer({"listeners": ["L1"], "perf_level": 5,
                         "clock_pairs": pairs,
                         "next_write_offset": 4096})
        s = _wbc(state, b"0123456789", 10)
        self.assertTrue(s.is_ok())
        finishes = [e for e in state.events
                    if e["op"] == "notify_finish"]
        self.assertEqual(len(finishes), 1)
        self.assertEqual(finishes[0]["type"], 1)
        self.assertEqual(finishes[0]["offset"], 4096)
        self.assertEqual(finishes[0]["nbytes"], 10)
        self.assertEqual(finishes[0]["elapsed_nanos"], 2100)

    def test_failure_event_type_8_with_trailing_u64s(self):
        state = _writer({"listeners": ["L1", "L2"],
                         "next_write_offset": 777,
                         "rate_limiter_grants": [4]})
        state.script = {"append_statuses": [dict(m.ERR_IO)]}
        s = _wbc(state, b"0123456789", 10, m.IO_LOW)
        self.assertFalse(s.is_ok())
        failures = [e for e in state.events
                    if e["op"] == "notify_failure"]
        self.assertEqual(len(failures), 2)  # one per listener
        self.assertEqual(failures[0]["type"], 8)
        # PINNED DIFFERENCE from WriteBuffered: (left, old_size),
        # not (granted, next_write_offset_).
        self.assertEqual(failures[0]["left"], 10)
        self.assertEqual(failures[0]["old_size"], 777)


class GuardTests(unittest.TestCase):
    def test_perf_0_no_guard_counters(self):
        state = _writer({"perf_level": 0,
                         "clock_pairs": m._clock_pairs()})
        s = _wbc(state, b"0123456789", 10)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.write_buffered_with_checksum_nanos, 0)
        self.assertEqual(state.write_buffered_with_checksum_cpu_nanos, 0)

    def test_perf_3_nanos_only(self):
        state = _writer({"perf_level": 3,
                         "clock_pairs": m._clock_pairs()})
        s = _wbc(state, b"0123456789", 10)
        self.assertTrue(s.is_ok())
        self.assertGreater(state.write_buffered_with_checksum_nanos, 0)
        self.assertEqual(state.write_buffered_with_checksum_cpu_nanos, 0)

    def test_perf_5_both_guards(self):
        state = _writer({"perf_level": 5,
                         "clock_pairs": m._clock_pairs()})
        s = _wbc(state, b"0123456789", 10)
        self.assertTrue(s.is_ok())
        self.assertGreater(state.write_buffered_with_checksum_nanos, 0)
        self.assertGreater(state.write_buffered_with_checksum_cpu_nanos, 0)

    def test_iostats_bytes_flag_skips_add(self):
        state = _writer({"iostats_bytes_flag": True})
        s = _wbc(state, b"0123456789", 10)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.iostats_bytes_written, 0)
        state = _writer({"iostats_bytes_flag": False})
        s = _wbc(state, b"0123456789", 10)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.iostats_bytes_written, 10)

    def test_sync_points_four_per_call(self):
        state = _writer({"sync_point_enabled": True,
                         "rate_limiter_grants": [5, 5]})
        s = _wbc(state, b"0123456789", 10, m.IO_LOW)
        self.assertTrue(s.is_ok())
        syncs = [e for e in state.events if e["op"] == "sync_point"]
        self.assertEqual(len(syncs), 4)  # 4 per call, not per chunk
        self.assertEqual([e["site"] for e in syncs],
                         ["0x604f1e9", "0x604f315",
                          "0x604f5f9", "0x604f621"])


class CensusTests(unittest.TestCase):
    def test_caller_census_three_calls(self):
        pkt = json.load(open(PACKET / "census.json"))
        self.assertEqual(pkt["validated_sites"], 7)
        self.assertEqual(pkt["targets"]["0x604f080"]["calls"], 3)
        self.assertEqual(pkt["targets"]["0x604f080"]["jumps"], 0)
        self.assertEqual(pkt["targets"]["0x604f080"]["lea_refs"], 0)
        rows = [l.split("\t") for l in
                open(PACKET / "callers.tsv").read().splitlines()[1:]]
        calls = [r for r in rows if r[2] == "call"]
        self.assertEqual(sorted(r[3] for r in calls),
                         ["0x6052490", "0x6054ed9", "0x605507b"])
        self.assertEqual(sorted(r[4] for r in calls),
                         ["0x6051a20", "0x6054680", "0x6054680"])
        # WriteBufferedWithChecksum.cold: four tail jumps from the
        # main FDE tail.
        jmps = [r for r in rows if r[2] == "jmp"]
        self.assertEqual(len(jmps), 4)
        self.assertEqual(sorted(r[0] for r in jmps),
                         ["0x604ef0e"] * 4)
        self.assertEqual(sorted(r[3] for r in jmps),
                         ["0x604fca8", "0x604fd2c",
                          "0x604fd38", "0x604fd44"])


class BindingTests(unittest.TestCase):
    def test_body_hashes(self):
        data = open(m._bin_path(), "rb").read()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         m.ARTIFACT_SHA256)
        for start, end, want in (
                (m.WBC_ADDR, m.WBC_FDE_END,
                 "fc3c41a26936962546b56e0fc736a889923b776a48b864edb6038e6a2bda1d4c"),
                (m.WBC_COLD_ADDR, m.WBC_COLD_FDE_END,
                 "b8f141f440ff4f95813e455e5a3fe3ef6e30c0450897655934fd46899b7bee48")):
            body = data[m._va_to_off(start):m._va_to_off(end)]
            self.assertEqual(hashlib.sha256(body).hexdigest(), want)

    def test_source_hash_reproduced_for_cold(self):
        census = json.load(open(m.ROOT / m.CENSUS_PATH))["records"]
        by_start = {r["start"]: r for r in census}
        data = open(m._bin_path(), "rb").read()
        rec = by_start[m.WBC_COLD_ADDR]
        body = data[m._va_to_off(m.WBC_COLD_ADDR):
                    m._va_to_off(rec["end"])]
        self.assertEqual(hashlib.sha256(body).hexdigest(),
                         rec["target_body_sha256"])
        zeroed = bytearray(body)
        for rel in rec["relocations"]:
            o, w = rel["offset"], rel["width"]
            zeroed[o:o + w] = b"\x00" * w
        self.assertEqual(hashlib.sha256(bytes(zeroed)).hexdigest(),
                         rec["source_body_sha256"])
        self.assertEqual(len(rec["relocations"]), 14)

    def test_main_has_no_census_record(self):
        census = json.load(open(m.ROOT / m.CENSUS_PATH))["records"]
        by_start = {r["start"]: r for r in census}
        self.assertNotIn(m.WBC_ADDR, by_start)

    def test_crc_vectors(self):
        self.assertEqual(m.crc32c_value(b"123456789"), 0xE3069283)
        self.assertEqual(m.crc32c_value(b""), 0)
        self.assertEqual(m.crc32c_unmask(m.crc32c_mask(0xE3069283)),
                         0xE3069283)

    def test_decide_priority_matrix(self):
        self.assertEqual(m.decide_rate_limiter_priority(4, 4), 4)
        self.assertEqual(m.decide_rate_limiter_priority(4, 1), 1)
        self.assertEqual(m.decide_rate_limiter_priority(1, 4), 1)
        self.assertEqual(m.decide_rate_limiter_priority(2, 3), 3)

    def test_layout_offsets(self):
        self.assertEqual(m.OFF_BUF_CAPACITY, 0x50)
        self.assertEqual(m.OFF_BUF_CURSIZE, 0x58)
        self.assertEqual(m.OFF_BUF_START, 0x60)
        self.assertEqual(m.OFF_FLUSHED_SIZE, 0x78)
        self.assertEqual(m.OFF_NEXT_WRITE_OFFSET, 0x80)
        self.assertEqual(m.OFF_PENDING_SYNC, 0x88)
        self.assertEqual(m.OFF_SEEN_ERROR, 0x89)
        self.assertEqual(m.OFF_RATE_LIMITER, 0xA0)
        self.assertEqual(m.OFF_LISTENERS, 0xB0)
        self.assertEqual(m.OFF_PERFORM_DATA_VERIFICATION, 0xD1)
        self.assertEqual(m.OFF_BUFFERED_DATA_CRC32C, 0xD4)
        self.assertEqual(m.WRITER_SIZE, 0xE0)


class LiveTests(unittest.TestCase):
    def test_live_engine_check(self):
        ok, report = m.live_engine_check()
        self.assertTrue(ok, report)
        self.assertEqual(len(report["legs"]), 8)


if __name__ == "__main__":
    unittest.main()
