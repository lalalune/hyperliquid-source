"""Tests for the node #115 rocksdb::WritableFileWriter::Flush model.

Replays all 2,400 cases in cases.tsv through the tool, then checks
the model's key behaviours directly: the seen-error gate, the
buffered/direct-io write dispatch (with the pending_sync_ gate on
the direct arm), the file_->Flush call and its listener finish /
failure events, the RangeSync arm (1 MiB not-synced range, 4 KiB
align-down, last_sync_size_ advance), the RangeSync member itself
(seen-error gate, timer guard, listener events), the CRC32C chain
(Value + Mask + Combine), the DecideRateLimiterPriority matrix,
the IOOptions defaults, the writer layout bindings, the FDE body
hashes, and the live engine check (a real file written by the
model matches the model's file image).
"""

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import writable_file_writer_flush115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-rocksdb-writable-file-writer-flush-115")


def _read_cases():
    rows = []
    with open(PACKET / "cases.tsv") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    return rows


def _writer(over=None, file_over=None, script=None):
    return m.make_writer(over, file_over, script)


def _flush(state, priority=m.IO_TOTAL):
    return m.flush(state, priority)


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
        self.assertEqual(groups, {"gate": 600, "write_paths": 600,
                                  "rangesync": 600, "bindings": 600})

    def test_all_cases_replay(self):
        self.assertTrue(m.verify_cases(PACKET / "cases.tsv"))

    def test_case_ids_unique(self):
        rows = _read_cases()
        ids = [r["case_id"] for r in rows]
        self.assertEqual(len(ids), len(set(ids)))


class GateTests(unittest.TestCase):
    def test_seen_error_returns_prev_error_and_writes_nothing(self):
        state = _writer({"seen_error": True, "cursize": 5,
                         "buf_hex": b"hello".hex()})
        s = _flush(state)
        self.assertFalse(s.is_ok())
        self.assertEqual(s.code, 5)
        self.assertEqual(s.state, 1)
        # 26 chars + NUL = the 27-byte heap state_ the binary
        # allocates (rodata "Writer has previ" + " previous error.").
        self.assertEqual(m.PREV_ERROR_MSG, "Writer has previous error.")
        self.assertEqual(len(m.PREV_ERROR_MSG), 26)
        self.assertEqual(state.filesize, 0)
        self.assertEqual(len(state.file.image), 0)
        # The gate returns before any event is recorded.
        self.assertEqual(_events(state), [])

    def test_empty_buffer_still_flushes_file(self):
        state = _writer({"cursize": 0})
        s = _flush(state)
        self.assertTrue(s.is_ok())
        self.assertIn("file_flush", _ops(state))
        self.assertNotIn("write_buffered", _ops(state))
        self.assertNotIn("file_append", _ops(state))
        self.assertEqual(state.buf.cursize, 0)

    def test_buffered_write_then_file_flush(self):
        state = _writer({"cursize": 11,
                         "buf_hex": b"hello flush".hex()})
        s = _flush(state)
        self.assertTrue(s.is_ok())
        self.assertEqual(bytes(state.file.image), b"hello flush")
        self.assertEqual(state.flushed_size, 11)
        self.assertEqual(state.buf.cursize, 0)
        self.assertEqual(state.buffered_data_crc32c_checksum, 0)
        ops = _ops(state)
        self.assertLess(ops.index("write_buffered"),
                        ops.index("file_flush"))

    def test_buffered_write_failure_sets_seen_error_no_file_flush(self):
        state = _writer({"cursize": 4, "buf_hex": b"data".hex()},
                        script={"write_statuses": [{"code": 5,
                                                    "state": 2}]})
        s = _flush(state)
        self.assertFalse(s.is_ok())
        self.assertEqual(s.code, 5)
        self.assertTrue(state.seen_error)
        # WriteBuffered clears buf_ on failure; Flush returns early.
        self.assertEqual(state.buf.cursize, 0)
        self.assertNotIn("file_flush", _ops(state))
        self.assertNotIn("file_append", _ops(state))

    def test_direct_io_pending_sync_clear_skips_write(self):
        state = _writer({"cursize": 4096,
                         "buf_hex": (b"\xab" * 4096).hex(),
                         "pending_sync": False},
                        {"direct_io": True})
        s = _flush(state)
        self.assertTrue(s.is_ok())
        self.assertNotIn("write_direct", _ops(state))
        self.assertNotIn("positioned_append", _ops(state))
        self.assertEqual(state.buf.cursize, 4096)
        self.assertEqual(len(state.file.image), 0)
        self.assertIn("file_flush", _ops(state))

    def test_direct_io_pending_sync_writes_page(self):
        state = _writer({"cursize": 4096,
                         "buf_hex": (b"\xab" * 4096).hex(),
                         "pending_sync": True},
                        {"direct_io": True})
        s = _flush(state)
        self.assertTrue(s.is_ok())
        self.assertEqual(bytes(state.file.image), b"\xab" * 4096)
        self.assertEqual(state.flushed_size, 4096)
        self.assertEqual(state.buf.cursize, 0)
        self.assertEqual(state.next_write_offset, 4096)
        self.assertIn("file_flush", _ops(state))

    def test_direct_io_tail_refit(self):
        data = b"\xab" * 5000
        state = _writer({"cursize": 5000, "capacity": 8192,
                         "buf_hex": data.hex(), "pending_sync": True},
                        {"direct_io": True})
        s = _flush(state)
        self.assertTrue(s.is_ok())
        # 5000 bytes page-pad to 8192; the tail (904 B) stays buffered.
        self.assertEqual(len(state.file.image), 8192)
        self.assertEqual(bytes(state.file.image[:5000]), data)
        self.assertEqual(bytes(state.file.image[5000:]), b"\x00" * 3192)
        # flushed_size_ advances by the PADDED size (8192), matching
        # the physical file growth; only the 904 B tail stays buffered.
        self.assertEqual(state.flushed_size, 8192)
        self.assertEqual(state.buf.cursize, 904)
        self.assertEqual(state.next_write_offset, 4096)


class RangeSyncArmTests(unittest.TestCase):
    def _big_writer(self, **over):
        base = {"cursize": 0, "filesize": 2 * 1024 * 1024,
                "bytes_per_sync": 4096}
        base.update(over)
        return _writer(base)

    def test_small_file_skips_rangesync(self):
        state = self._big_writer(filesize=1024 * 1024)
        s = _flush(state)
        self.assertTrue(s.is_ok())
        self.assertNotIn("range_sync", _ops(state))
        self.assertEqual(state.last_sync_size, 0)

    def test_gap_too_small_skips_rangesync(self):
        state = self._big_writer(bytes_per_sync=2 * 1024 * 1024)
        s = _flush(state)
        self.assertTrue(s.is_ok())
        self.assertNotIn("range_sync", _ops(state))
        self.assertEqual(state.last_sync_size, 0)

    def test_rangesync_fires_and_advances_last_sync(self):
        state = self._big_writer()
        s = _flush(state)
        self.assertTrue(s.is_ok())
        rs = [e for e in _events(state) if e["op"] == "range_sync"]
        self.assertEqual(len(rs), 1)
        self.assertEqual(rs[0]["offset"], 0)
        self.assertEqual(rs[0]["nbytes"], 1024 * 1024)
        self.assertEqual(state.last_sync_size, 1024 * 1024)

    def test_direct_io_skips_rangesync_arm(self):
        state = self._big_writer()
        state.file.direct_io = True
        s = _flush(state)
        self.assertTrue(s.is_ok())
        self.assertNotIn("range_sync", _ops(state))
        self.assertEqual(state.last_sync_size, 0)

    def test_rangesync_failure_still_advances_last_sync(self):
        state = _writer(
            {"cursize": 0, "filesize": 2 * 1024 * 1024,
             "bytes_per_sync": 4096},
            None,
            {"range_sync_file_statuses": [{"code": 5, "state": 2}]})
        s = _flush(state)
        self.assertFalse(s.is_ok())
        self.assertEqual(s.code, 5)
        self.assertTrue(state.seen_error)
        # last_sync_size_ = offset_sync_to UNCONDITIONALLY, even
        # when the RangeSync status is not OK.
        self.assertEqual(state.last_sync_size, 1024 * 1024)


class RangeSyncMemberTests(unittest.TestCase):
    def test_member_seen_error_gate(self):
        state = _writer({"seen_error": True})
        s = m._range_sync_member(state, 0, 4096)
        self.assertFalse(s.is_ok())
        self.assertEqual(s.code, 5)
        self.assertEqual(s.state, 1)
        self.assertNotIn("range_sync", _ops(state))

    def test_member_timer_guard_armed_above_perf_2(self):
        state = _writer(
            {"perf_level": 3,
             "clock_pairs": [(1000000, 500000), (1000200, 500200)]})
        s = m._range_sync_member(state, 0, 4096)
        self.assertTrue(s.is_ok())
        self.assertIn("timer_guard_start", _ops(state))
        self.assertIn("timer_guard_stop", _ops(state))
        self.assertEqual(state.range_sync_nanos, 200)

    def test_member_timer_guard_not_armed_at_perf_2(self):
        state = _writer(
            {"perf_level": 2,
             "clock_pairs": [(1000000, 500000), (1000200, 500200)]})
        s = m._range_sync_member(state, 0, 4096)
        self.assertTrue(s.is_ok())
        self.assertNotIn("timer_guard_start", _ops(state))
        self.assertEqual(state.range_sync_nanos, 0)

    def test_member_sync_point_event(self):
        state = _writer({"sync_point_enabled": True})
        s = m._range_sync_member(state, 0, 4096)
        self.assertTrue(s.is_ok())
        sp = [e for e in _events(state) if e["op"] == "sync_point"]
        self.assertEqual(len(sp), 1)
        self.assertEqual(sp[0]["name"],
                         "WritableFileWriter::RangeSync:0")


class ListenerTests(unittest.TestCase):
    def test_finish_event_on_success(self):
        state = _writer({"cursize": 0, "listeners": ["L1"]})
        s = _flush(state)
        self.assertTrue(s.is_ok())
        self.assertIn("listener_start_times", _ops(state))
        fin = [e for e in _events(state) if e["op"] == "notify_finish"]
        self.assertEqual(len(fin), 1)
        self.assertEqual(fin[0]["type"], m.FILE_OP_FLUSH)
        self.assertEqual(fin[0]["slot"], "0x118")
        self.assertEqual(fin[0]["listener"], "L1")
        self.assertIsNone(fin[0]["offset"])
        self.assertNotIn("notify_failure", _ops(state))

    def test_failure_event_on_file_flush_failure(self):
        state = _writer({"cursize": 0, "listeners": ["L1"]},
                        script={"file_flush_statuses": [{"code": 5,
                                                         "state": 2}]})
        s = _flush(state)
        self.assertFalse(s.is_ok())
        self.assertEqual(s.code, 5)
        # The finish event fires first; seen_error_ is set only
        # after both notifications.
        self.assertTrue(state.seen_error)
        fin = [e for e in _events(state) if e["op"] == "notify_finish"]
        fail = [e for e in _events(state)
                if e["op"] == "notify_failure"]
        self.assertEqual(len(fin), 1)
        self.assertEqual(len(fail), 1)
        self.assertEqual(fail[0]["type"], m.FILE_OP_FLUSH)
        self.assertEqual(fail[0]["slot"], "0x178")
        self.assertEqual(fail[0]["file_name"], "test.wal")


class BindingTests(unittest.TestCase):
    def test_fde_body_hashes(self):
        hashes = m._fde_body_hashes()
        self.assertEqual(
            hashes["flush"],
            "fc5f4ed6a546b13e6ffeccdf9629bd4f9c1c704c8e8a0e9eaeb0013c679d2bc6")
        self.assertEqual(
            hashes["cold"],
            "be6981880b6cb3112ea941ebda10eb684990c24149069b682b361513e85c2588")
        self.assertEqual(
            hashes["range_sync"],
            "ea8c92fe81c54b3e73dfcdf644de23fc169290efcab403030c3c95d101627013")
        # Cross-check against the packet's functions.tsv.
        rows = {}
        with open(PACKET / "functions.tsv") as fh:
            header = fh.readline().rstrip("\n").split("\t")
            for line in fh:
                d = dict(zip(header, line.rstrip("\n").split("\t")))
                rows[d["name"]] = d
        self.assertEqual(rows["rocksdb::WritableFileWriter::Flush"]
                         ["body_sha256"], hashes["flush"])
        self.assertEqual(rows["rocksdb::WritableFileWriter::Flush.cold"]
                         ["body_sha256"], hashes["cold"])
        self.assertEqual(rows["rocksdb::WritableFileWriter::RangeSync"]
                         ["body_sha256"], hashes["range_sync"])

    def test_caller_census(self):
        census = json.load(open(PACKET / "census.json"))
        self.assertEqual(census["targets"]["0x6051a20"]["calls"], 13)
        self.assertEqual(census["targets"]["0x6051a20"]["jumps"], 0)
        self.assertEqual(census["targets"]["0x6051938"]["calls"], 0)
        self.assertEqual(census["targets"]["0x6051938"]["jumps"], 1)
        self.assertEqual(census["validated_sites"], 14)
        with open(PACKET / "callers.tsv") as fh:
            self.assertEqual(len(fh.readlines()) - 1, 14)

    def test_decide_rate_limiter_priority(self):
        decide = m.decide_rate_limiter_priority
        self.assertEqual(decide(4, 4), 4)
        self.assertEqual(decide(4, 1), 1)
        self.assertEqual(decide(1, 4), 1)
        self.assertEqual(decide(0, 1), 1)
        self.assertEqual(decide(2, 3), 3)

    def test_crc32c_vectors(self):
        self.assertEqual(m.crc32c_value(b"123456789"), 0xE3069283)
        crc = m.crc32c_value(b"hello flush")
        self.assertEqual(m.crc32c_unmask(m.crc32c_mask(crc)), crc)
        a, b = b"hello ", b"flush"
        self.assertEqual(m.crc32c_combine(m.crc32c_value(a),
                                          m.crc32c_value(b), len(b)),
                         m.crc32c_value(a + b))

    def test_io_options_defaults(self):
        opts = m.io_options_default(4)
        self.assertEqual(opts["timeout"], 0)
        self.assertEqual(opts["prio"], 0)
        self.assertEqual(opts["rate_limiter_priority"], 4)
        self.assertEqual(opts["type"], 7)
        self.assertEqual(opts["property_bag_count"], 1)
        self.assertEqual(opts["max_load_factor"], 1.0)
        self.assertFalse(opts["force_dir_fsync"])
        self.assertFalse(opts["do_not_recurse"])
        self.assertEqual(len(opts["image_hex"]), 0x58 * 2)

    def test_file_op_types_and_slots(self):
        self.assertEqual(m.FILE_OP_FLUSH, 4)
        self.assertEqual(m.FILE_OP_RANGE_SYNC, 7)
        self.assertEqual(m.NOTIFY_FLUSH_FINISH_SLOT, 0x118)
        self.assertEqual(m.NOTIFY_RANGE_SYNC_FINISH_SLOT, 0x128)
        self.assertEqual(m.NOTIFY_FAILURE_SLOT, 0x178)


class LiveEngineTests(unittest.TestCase):
    def test_live_engine_check(self):
        ok, report = m.live_engine_check()
        self.assertTrue(ok, report)
        self.assertEqual(len(report["legs"]), 4)


if __name__ == "__main__":
    unittest.main()
