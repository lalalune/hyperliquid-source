"""Tests for the node #115 rocksdb::WritableFileWriter::Append model.

Replays all 2,400 cases in cases.tsv through the tool, then checks
the model's key behaviours directly: the seen-error gate, the
buffer-growth doubling loop, the four write arms (buffered single
append, direct-io loop, buffered-with-checksum, plain direct write),
the Flush oracle (buffered/direct, RangeSync arm, failure paths),
the CRC32C chain (Value + Extend + Combine + Mask), the
DecideRateLimiterPriority matrix, the IOOptions defaults, the writer
layout offsets, the FDE body hashes, and the live engine check (a
real file written by the model matches the model's file image).
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import writable_file_writer_append115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-rocksdb-writable-file-writer-append-115")


def _read_cases():
    rows = []
    with open(PACKET / "cases.tsv") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    return rows


def _writer(**over):
    state = m.make_writer(over, None, None)
    return state


def _append(state, data, crc=0, priority=m.IO_TOTAL):
    return m.append(state, data, crc, priority)


class ReplayTests(unittest.TestCase):
    def test_case_count(self):
        rows = _read_cases()
        self.assertEqual(len(rows), 2400)
        groups = {}
        for r in rows:
            groups[r["group"]] = groups.get(r["group"], 0) + 1
        self.assertEqual(groups, {"gate": 600, "growth": 600,
                                  "write_paths": 600, "bindings": 600})

    def test_all_cases_replay(self):
        self.assertTrue(m.verify_cases(PACKET / "cases.tsv"))

    def test_case_ids_unique(self):
        rows = _read_cases()
        ids = [r["case_id"] for r in rows]
        self.assertEqual(len(ids), len(set(ids)))


class GateTests(unittest.TestCase):
    def test_seen_error_returns_prev_error_and_writes_nothing(self):
        state = _writer(seen_error=True)
        s = _append(state, b"data", 0)
        self.assertFalse(s.is_ok())
        self.assertEqual(s.code, 5)
        self.assertEqual(s.state, 1)
        # 26 chars + NUL = the 27-byte heap state_ the binary
        # allocates (rodata "Writer has previ" + " previous error.").
        self.assertEqual(len(m.PREV_ERROR_MSG), 26)
        self.assertEqual(state.filesize, 0)
        self.assertEqual(len(state.file.image), 0)

    def test_seen_error_message(self):
        self.assertEqual(m.PREV_ERROR_MSG, "Writer has previous error.")
        # 26 chars; the binary allocates 27 bytes (message + NUL).
        self.assertEqual(len(m.PREV_ERROR_MSG), 26)

    def test_empty_append_advances_nothing_but_sets_pending_sync(self):
        state = _writer()
        s = _append(state, b"", 0)
        self.assertTrue(s.is_ok())
        self.assertTrue(state.pending_sync)
        self.assertEqual(state.filesize, 0)

    def test_filesize_advances_on_ok(self):
        state = _writer()
        s = _append(state, b"hello", 0)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.filesize, 5)

    def test_checksum_generator_records_update(self):
        state = _writer(checksum_generator=True)
        _append(state, b"abc", 0)
        ops = [e["op"] for e in state.events]
        self.assertIn("update_file_checksum", ops)


class GrowthTests(unittest.TestCase):
    def test_no_growth_when_it_fits(self):
        state = _writer(capacity=4096, cursize=0)
        _append(state, b"x" * 100, 0)
        self.assertEqual(state.buf.capacity, 4096)

    def test_doubling_growth(self):
        state = _writer(capacity=4096, cursize=0)
        _append(state, b"x" * 5000, 0)
        self.assertEqual(state.buf.capacity, 8192)

    def test_growth_stops_at_max(self):
        # No desired size satisfies the loop condition for a 20000 B
        # write with max 8192, so the buffer does NOT grow at all.
        state = _writer(capacity=4096, cursize=0, max_buffer_size=8192)
        _append(state, b"x" * 20000, 0)
        self.assertEqual(state.buf.capacity, 4096)
        # A 6000 B write does satisfy it: desired 8192 >= 6000.
        state = _writer(capacity=4096, cursize=0, max_buffer_size=8192)
        _append(state, b"x" * 6000, 0)
        self.assertEqual(state.buf.capacity, 8192)

    def test_direct_io_max_arm(self):
        # Direct I/O + desired == max grows even when the grown
        # buffer still cannot hold the write.
        state = _writer(capacity=4096, cursize=0, max_buffer_size=8192)
        state.file.direct_io = True
        _append(state, b"x" * 20000, 0)
        self.assertEqual(state.buf.capacity, 8192)

    def test_allocate_skip_guard_unreachable_from_growth(self):
        # AllocateNewBuffer skips when copy_data and
        # desired < cursize; the growth loop can never request that
        # (desired >= capacity >= cursize), so pin it directly.
        buf = m.AlignedBuffer(4096, capacity=4096, cursize=1000,
                              data=bytes(1000))
        events = []
        self.assertFalse(buf.allocate_new_buffer(100, copy_data=True,
                                                 events=events))
        self.assertEqual(buf.capacity, 4096)
        self.assertEqual(buf.cursize, 1000)


class WritePathTests(unittest.TestCase):
    def test_buffered_append_stays_in_buffer(self):
        state = _writer(capacity=4096, cursize=0)
        _append(state, b"hello", 0)
        self.assertEqual(state.buf.cursize, 5)
        self.assertEqual(len(state.file.image), 0)
        self.assertEqual(state.flushed_size, 0)

    def test_flush_moves_buffer_to_file(self):
        state = _writer(capacity=4096, cursize=0)
        _append(state, b"hello", 0)
        s = m._flush_oracle(state, m.IO_TOTAL)
        self.assertTrue(s.is_ok())
        self.assertEqual(bytes(state.file.image), b"hello")
        self.assertEqual(state.buf.cursize, 0)
        self.assertEqual(state.flushed_size, 5)

    def test_verification_single_append_combines(self):
        state = _writer(perform_data_verification=True,
                        buffered_data_with_checksum=True,
                        buffered_data_crc32c_checksum=0x11111111)
        crc = m.crc32c_value(b"data")
        _append(state, b"data", crc)
        self.assertEqual(
            state.buffered_data_crc32c_checksum,
            m.crc32c_combine(0x11111111, crc, 4))

    def test_verification_zero_crc_takes_plain_arm(self):
        # crc == 0 skips the verification arm, but the plain arm
        # still Extends the checksum when both flags are set.
        state = _writer(perform_data_verification=True,
                        buffered_data_with_checksum=True)
        s = _append(state, b"data", 0)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.buffered_data_crc32c_checksum,
                         m.crc32c_value(b"data"))

    def test_direct_io_loop_extends_and_flushes(self):
        # max 4096 caps growth, so the 5000 B write takes the
        # direct-io loop: 4096 B flushed positionally, the 904 B
        # tail stays buffered until Flush.
        state = _writer(capacity=4096, cursize=0, max_buffer_size=4096,
                        perform_data_verification=True,
                        buffered_data_with_checksum=True)
        state.file.direct_io = True
        data = b"A" * 5000
        s = _append(state, data, m.crc32c_value(data))
        self.assertTrue(s.is_ok())
        self.assertEqual(state.filesize, 5000)
        self.assertEqual(bytes(state.file.image), data[:4096])
        self.assertEqual(state.buf.cursize, 904)
        s = m._flush_oracle(state, m.IO_TOTAL)
        self.assertTrue(s.is_ok())
        # WriteDirect pads the 904 B tail to the 4096 B page, so the
        # physical file is 8192 B: the 5000 data bytes, then zeros.
        self.assertEqual(bytes(state.file.image[:5000]), data)
        self.assertEqual(len(state.file.image), 8192)
        self.assertEqual(bytes(state.file.image[5000:]),
                         bytes(8192 - 5000))

    def test_flush_failure_sets_seen_error(self):
        # max 4096 caps growth, so the 500 B write over a 4000 B
        # buffer must Flush first.
        state = _writer(capacity=4096, cursize=4000,
                        max_buffer_size=4096, buf_seed=7)
        script = {"flush_write_statuses": [dict(m.ERR_IO)]}
        state.script = {k: [dict(x) for x in v]
                        for k, v in script.items()}
        s = _append(state, b"x" * 500, 0)
        self.assertFalse(s.is_ok())
        self.assertTrue(state.seen_error)

    def test_write_buffered_failure_clears_buffer(self):
        # max 4096 caps growth, so the 5000 B write takes the
        # direct WriteBuffered path from Append.
        state = _writer(capacity=4096, cursize=0, max_buffer_size=4096)
        script = {"write_buffered_statuses": [dict(m.ERR_IO)]}
        state.script = {k: [dict(x) for x in v]
                        for k, v in script.items()}
        s = _append(state, b"x" * 5000, 0)
        self.assertFalse(s.is_ok())
        self.assertTrue(state.seen_error)
        self.assertEqual(state.buf.cursize, 0)

    def test_range_sync_arm(self):
        # filesize > 1 MiB + bytes_per_sync fires RangeSync in Flush.
        state = _writer(capacity=4096, cursize=100, buf_seed=3,
                        filesize=2 * 1024 * 1024, bytes_per_sync=4096,
                        flushed_size=2 * 1024 * 1024)
        s = m._flush_oracle(state, m.IO_TOTAL)
        self.assertTrue(s.is_ok())
        ops = [e["op"] for e in state.events]
        self.assertIn("flush_range_sync", ops)
        self.assertEqual(state.last_sync_size, 2 * 1024 * 1024
                         - 1024 * 1024 - (1024 * 1024 % 4096))

    def test_plain_direct_write_bypasses_buffer(self):
        # max 4096 caps growth, so the 5000 B write bypasses the
        # buffer entirely.
        state = _writer(capacity=4096, cursize=0, max_buffer_size=4096)
        data = b"y" * 5000
        s = _append(state, data, 0)
        self.assertTrue(s.is_ok())
        self.assertEqual(bytes(state.file.image), data)
        self.assertEqual(state.buf.cursize, 0)


class CrcTests(unittest.TestCase):
    def test_check_vector(self):
        self.assertEqual(m.crc32c_value(b"123456789"), 0xE3069283)

    def test_empty_value_is_zero(self):
        self.assertEqual(m.crc32c_value(b""), 0)

    def test_combine_matches_direct(self):
        a, b = b"hello ", b"world"
        self.assertEqual(
            m.crc32c_combine(m.crc32c_value(a), m.crc32c_value(b),
                             len(b)),
            m.crc32c_value(a + b))

    def test_combine_degenerate(self):
        self.assertEqual(m.crc32c_combine(0x11111111, 0x22222222, 0),
                         0x11111111 ^ 0x22222222)

    def test_mask_round_trip(self):
        crc = 0xE3069283
        self.assertEqual(m.crc32c_unmask(m.crc32c_mask(crc)), crc)


class PriorityTests(unittest.TestCase):
    def test_matrix(self):
        self.assertEqual(m.decide_rate_limiter_priority(4, 4), 4)
        self.assertEqual(m.decide_rate_limiter_priority(4, 1), 1)
        self.assertEqual(m.decide_rate_limiter_priority(1, 4), 1)
        self.assertEqual(m.decide_rate_limiter_priority(2, 3), 3)
        self.assertEqual(m.decide_rate_limiter_priority(0, 0), 0)

    def test_io_options_defaults(self):
        io = m.io_options_default(m.IO_TOTAL)
        self.assertEqual(io["timeout"], 0)
        self.assertEqual(io["prio"], 0)
        self.assertEqual(io["rate_limiter_priority"], m.IO_TOTAL)
        self.assertEqual(io["type"], 7)
        self.assertEqual(io["force_dir_fsync"], 0)
        self.assertEqual(io["do_not_recurse"], 0)
        self.assertEqual(len(bytes.fromhex(io["image_hex"])), 0x58)


class LayoutTests(unittest.TestCase):
    def test_writer_offsets(self):
        self.assertEqual(m.OFF_FILESIZE, 0x70)
        self.assertEqual(m.OFF_PENDING_SYNC, 0x88)
        self.assertEqual(m.OFF_SEEN_ERROR, 0x89)
        self.assertEqual(m.OFF_CHECKSUM_GENERATOR, 0xC8)
        self.assertEqual(m.OFF_BUFFERED_DATA_CRC32C, 0xD4)
        self.assertEqual(m.WRITER_SIZE, 0xE0)

    def test_vtable_slots(self):
        self.assertEqual(m.USE_DIRECT_IO_SLOT, 12)
        self.assertEqual(m.GET_IO_PRIORITY_SLOT, 16)
        self.assertEqual(m.PREPARE_WRITE_SLOT, 24)

    def test_body_hashes(self):
        hashes = m._fde_body_hashes()
        self.assertEqual(
            hashes["append"],
            "f796b02fe4615a8144a11d474f52be53aa2f2e08605c09a46d895a86c0b006da")
        self.assertEqual(
            hashes["cold"],
            "a8869d110687c35e137ab978008411040c8dd2416f0333650e9372e56bd199b2")

    def test_cold_census_relocations(self):
        census = json.load(open(m.ROOT / m.CENSUS_PATH))["records"]
        cold = [r for r in census if r["start"] == m.COLD_ADDR][0]
        self.assertEqual(len(cold["relocations"]), 8)
        self.assertEqual(cold["relocations"][0]["offset"], 14)

    def test_timer_guard_armed_above_perf_level_2(self):
        for level in range(6):
            state = _writer(perf_level=level,
                            clock_values=[1000, 1500])
            _append(state, b"x", 0)
            armed = any(e["op"] == "timer_guard_start"
                        for e in state.events)
            self.assertEqual(armed, level > 2)

    def test_file_selection(self):
        self.assertEqual(m.FakeFile(tracer=None).select_file(),
                         "raw")
        self.assertEqual(
            m.FakeFile(tracer={"enabled": False}).select_file(),
            "raw")
        self.assertEqual(
            m.FakeFile(tracer={"enabled": True}).select_file(),
            "wrapper")


class LiveTests(unittest.TestCase):
    def test_live_engine_check(self):
        ok, report = m.live_engine_check()
        self.assertTrue(ok, report)
        self.assertEqual(len(report["legs"]), 3)


if __name__ == "__main__":
    unittest.main()
