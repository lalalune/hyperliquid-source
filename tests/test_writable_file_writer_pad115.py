"""Tests for the node #115 rocksdb::WritableFileWriter::Pad model.

Replays all 2,400 cases in cases.tsv through the tool, then checks
the model's key behaviours directly: the seen-error gate, the
zero-fill loop (chunking at the free-space boundary, the mid-loop
Flush call, the full-buffer-at-entry flush), the Flush-failure
return (seen_error_ set, filesize_ NOT advanced), the epilogue
(pending_sync_ set, filesize_ advanced), the verification arm
(Extend over buffer + ENTRY cursize_, pinned when no Flush
intervened, unpinned -- null -- when one did), the sole caller
(BlockBasedTableBuilder::WriteMaybeCompressedBlock alignment
math), the CRC32C chain (Value + Mask + Combine), the
DecideRateLimiterPriority matrix, the IOOptions defaults, the
writer layout bindings, the FDE body hashes, and the live engine
check (a real file written by the model matches the model's file
image).
"""

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import writable_file_writer_pad115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-rocksdb-writable-file-writer-pad-115")


def _read_cases():
    rows = []
    with open(PACKET / "cases.tsv") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    return rows


def _writer(over=None, file_over=None, script=None):
    return m.make_writer(over, file_over, script)


def _pad(state, size, priority=m.IO_TOTAL):
    return m.pad(state, size, priority)


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
        self.assertEqual(groups, {"gate": 600, "pad_paths": 600,
                                  "verification": 600, "bindings": 600})

    def test_all_cases_replay(self):
        self.assertTrue(m.verify_cases(PACKET / "cases.tsv"))

    def test_case_ids_unique(self):
        rows = _read_cases()
        ids = [r["case_id"] for r in rows]
        self.assertEqual(len(ids), len(set(ids)))

    def test_verification_rows_split_pinned_unpinned(self):
        rows = _read_cases()
        vrows = [json.loads(r["expected_json"])
                 for r in rows if r["group"] == "verification"]
        pinned = [e for e in vrows
                  if e.get("pad_extend_pinned") is True]
        unpinned = [e for e in vrows
                    if e.get("pad_extend_pinned") is False]
        # Both sides of the boundary are exercised: pinned rows
        # carry an exact checksum, unpinned rows carry null.
        self.assertGreater(len(pinned), 100)
        self.assertGreater(len(unpinned), 50)
        for e in unpinned:
            self.assertIsNone(e["buffered_data_crc32c_checksum"])


class GateTests(unittest.TestCase):
    def test_seen_error_returns_prev_error_and_writes_nothing(self):
        state = _writer({"seen_error": True, "cursize": 5,
                         "buf_hex": b"hello".hex()})
        s = _pad(state, 100)
        self.assertFalse(s.is_ok())
        self.assertEqual(s.code, 5)
        self.assertEqual(s.state, 1)
        # 26 chars + NUL = the 27-byte heap state_ the binary
        # allocates (rodata "Writer has previ" + " previous error.").
        self.assertEqual(m.PREV_ERROR_MSG, "Writer has previous error.")
        self.assertEqual(len(m.PREV_ERROR_MSG), 26)
        self.assertEqual(state.filesize, 0)
        self.assertFalse(state.pending_sync)
        self.assertEqual(len(state.file.image), 0)
        # The gate returns before any event is recorded.
        self.assertEqual(_events(state), [])

    def test_zero_size_pad_sets_pending_sync_only(self):
        state = _writer({"cursize": 100,
                         "buf_hex": (b"\xab" * 100).hex(),
                         "filesize": 1000})
        s = _pad(state, 0)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.pad_flush_calls, 0)
        self.assertEqual(state.pad_chunks, [])
        self.assertTrue(state.pending_sync)
        self.assertEqual(state.filesize, 1000)
        self.assertEqual(state.buf.cursize, 100)
        self.assertNotIn("file_flush", _ops(state))

    def test_single_chunk_no_flush(self):
        state = _writer({"cursize": 11,
                         "buf_hex": b"hello pad!!".hex()})
        s = _pad(state, 100)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.pad_flush_calls, 0)
        self.assertEqual(state.pad_chunks, [100])
        self.assertEqual(state.buf.cursize, 111)
        self.assertEqual(bytes(state.buf.data[:11]), b"hello pad!!")
        self.assertEqual(bytes(state.buf.data[11:111]), b"\x00" * 100)
        self.assertEqual(state.filesize, 100)
        self.assertTrue(state.pending_sync)
        self.assertEqual(len(state.file.image), 0)

    def test_exact_free_space_no_flush(self):
        state = _writer({"capacity": 4096, "cursize": 4000,
                         "buf_hex": (b"\xab" * 4000).hex()})
        s = _pad(state, 96)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.pad_flush_calls, 0)
        self.assertEqual(state.pad_chunks, [96])
        self.assertEqual(state.buf.cursize, 4096)
        self.assertEqual(state.filesize, 96)

    def test_one_byte_over_free_space_flushes_once(self):
        state = _writer({"capacity": 4096, "cursize": 4000,
                         "buf_hex": (b"\xab" * 4000).hex()})
        s = _pad(state, 97)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.pad_flush_calls, 1)
        self.assertEqual(state.pad_chunks, [96, 1])
        self.assertEqual(state.buf.cursize, 1)
        self.assertEqual(len(state.file.image), 4096)
        self.assertEqual(bytes(state.file.image[:4000]),
                         b"\xab" * 4000)
        self.assertEqual(bytes(state.file.image[4000:]), b"\x00" * 96)
        self.assertEqual(state.filesize, 97)
        self.assertEqual(state.flushed_size, 4096)

    def test_full_buffer_at_entry_flushes_first(self):
        state = _writer({"capacity": 4096, "cursize": 4096,
                         "buf_hex": (b"\xab" * 4096).hex()})
        s = _pad(state, 100)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.pad_flush_calls, 1)
        self.assertEqual(state.pad_chunks, [0, 100])
        self.assertEqual(state.buf.cursize, 100)
        self.assertEqual(len(state.file.image), 4096)

    def test_multi_buffer_pad(self):
        state = _writer({"capacity": 1024, "cursize": 0})
        s = _pad(state, 2500)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.pad_flush_calls, 2)
        self.assertEqual(state.pad_chunks, [1024, 1024, 452])
        self.assertEqual(state.buf.cursize, 452)
        self.assertEqual(len(state.file.image), 2048)
        self.assertEqual(state.filesize, 2500)

    def test_flush_write_failure_sets_seen_error(self):
        state = _writer({"capacity": 4096, "cursize": 0},
                        script={"write_statuses": [dict(m.ERR_IO)]})
        s = _pad(state, 5000)
        self.assertFalse(s.is_ok())
        self.assertEqual(s.code, 5)
        self.assertTrue(state.seen_error)
        # The failed WriteBuffered clears buf_; filesize_ is NOT
        # advanced and pending_sync_ is NOT set.
        self.assertEqual(state.buf.cursize, 0)
        self.assertEqual(state.filesize, 0)
        self.assertFalse(state.pending_sync)
        self.assertEqual(len(state.file.image), 0)

    def test_flush_file_failure_sets_seen_error(self):
        state = _writer({"capacity": 4096, "cursize": 0},
                        script={"file_flush_statuses":
                                [dict(m.ERR_CORRUPTION)]})
        s = _pad(state, 5000)
        self.assertFalse(s.is_ok())
        self.assertEqual(s.code, 2)
        self.assertTrue(state.seen_error)
        self.assertEqual(state.filesize, 0)
        self.assertFalse(state.pending_sync)

    def test_direct_io_no_progress_raises(self):
        # Direct I/O with pending_sync_ clear: Flush skips the
        # write, the buffer stays full, the binary loops forever.
        # The model refuses instead of hanging.
        state = _writer({"capacity": 4096, "cursize": 4096,
                         "buf_hex": (b"\xab" * 4096).hex(),
                         "pending_sync": False},
                        {"direct_io": True})
        with self.assertRaises(ValueError):
            _pad(state, 100)


class VerificationTests(unittest.TestCase):
    def test_verify_off_leaves_checksum_alone(self):
        entry = 0x12345678
        state = _writer({"cursize": 11,
                         "buf_hex": b"hello pad!!".hex(),
                         "perform_data_verification": False,
                         "buffered_data_crc32c_checksum": entry})
        s = _pad(state, 100)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.buffered_data_crc32c_checksum, entry)
        self.assertIsNone(state.pad_extend_pinned)

    def test_verify_on_no_flush_pins_checksum(self):
        entry = 0x12345678
        state = _writer({"cursize": 11,
                         "buf_hex": b"hello pad!!".hex(),
                         "perform_data_verification": True,
                         "buffered_data_crc32c_checksum": entry})
        s = _pad(state, 100)
        self.assertTrue(s.is_ok())
        self.assertTrue(state.pad_extend_pinned)
        self.assertEqual(state.pad_extend_ptr_offset, 11)
        self.assertEqual(state.pad_extend_len, 100)
        self.assertEqual(state.buffered_data_crc32c_checksum,
                         m.crc32c_extend(entry, b"\x00" * 100))

    def test_verify_on_ignores_with_checksum_flag(self):
        # Pad's arm tests ONLY perform_data_verification_ (+0xd1);
        # buffered_data_with_checksum_ (+0xd8) is not consulted.
        entry = 0x12345678
        for with_cksum in (False, True):
            state = _writer({"cursize": 0,
                             "perform_data_verification": True,
                             "buffered_data_with_checksum": with_cksum,
                             "buffered_data_crc32c_checksum": entry})
            s = _pad(state, 64)
            self.assertTrue(s.is_ok())
            self.assertEqual(state.buffered_data_crc32c_checksum,
                             m.crc32c_extend(entry, b"\x00" * 64))

    def test_verify_on_flush_intervened_unpins_checksum(self):
        entry = 0x12345678
        state = _writer({"capacity": 4096, "cursize": 4000,
                         "buf_hex": (b"\xab" * 4000).hex(),
                         "perform_data_verification": True,
                         "buffered_data_crc32c_checksum": entry})
        s = _pad(state, 1000)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.pad_flush_calls, 1)
        self.assertFalse(state.pad_extend_pinned)
        self.assertEqual(state.pad_extend_ptr_offset, 4000)
        self.assertEqual(state.pad_extend_len, 1000)
        self.assertEqual(state.pad_extend_input_len, 96)
        # The Extend reads past the buffer capacity: heap bytes
        # the model cannot pin -- recorded as null, not a guess.
        self.assertIsNone(state.buffered_data_crc32c_checksum)

    def test_verify_zero_size_leaves_checksum(self):
        entry = 0xDEADBEEF
        state = _writer({"cursize": 100,
                         "perform_data_verification": True,
                         "buffered_data_crc32c_checksum": entry})
        s = _pad(state, 0)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.buffered_data_crc32c_checksum, entry)
        self.assertTrue(state.pad_extend_pinned)

    def test_stale_buffer_bytes_survive_flush(self):
        # AlignedBuffer::Clear resets cursize_ only; the first
        # chunk's zeros must still be in the buffer after the
        # mid-loop Flush, because the Extend input starts there.
        state = _writer({"capacity": 4096, "cursize": 4000,
                         "buf_hex": (b"\xab" * 4000).hex(),
                         "perform_data_verification": False})
        s = _pad(state, 1000)
        self.assertTrue(s.is_ok())
        self.assertEqual(bytes(state.buf.data[4000:4096]),
                         b"\x00" * 96)


class CallerTests(unittest.TestCase):
    def test_caller_alignment_math(self):
        # (block_size - ((offset + 5) % block_size)) % block_size.
        self.assertEqual(m.caller_pad_size(4096, 0), 4091)
        self.assertEqual(m.caller_pad_size(4096, 4091), 0)
        self.assertEqual(m.caller_pad_size(4096, 4092), 4095)
        self.assertEqual(m.caller_pad_size(4096, 4096), 4091)
        self.assertEqual(m.caller_pad_size(8192, 12345), 4034)
        self.assertEqual(m.caller_pad_size(4096, 100000), 2395)
        for block_size in (4096, 8192, 16384, 32768, 65536):
            for offset in range(0, 20000, 997):
                pad = m.caller_pad_size(block_size, offset)
                self.assertGreaterEqual(pad, 0)
                self.assertLess(pad, block_size)
                self.assertEqual((offset + 5 + pad) % block_size, 0)

    def test_caller_census_single_call_site(self):
        pkt = json.load(open(PACKET / "census.json"))
        self.assertEqual(pkt["validated_sites"], 2)
        self.assertEqual(pkt["targets"]["0x60525b0"]["calls"], 1)
        self.assertEqual(pkt["targets"]["0x60525b0"]["jumps"], 0)
        self.assertEqual(pkt["targets"]["0x60525b0"]["lea_refs"], 0)
        rows = [l.split("\t") for l in
                open(PACKET / "callers.tsv").read().splitlines()[1:]]
        call = [r for r in rows if r[2] == "call"][0]
        self.assertEqual(call[3], "0x60e7649")
        self.assertEqual(call[4], "0x60e7200")
        self.assertEqual(call[5], "0x60e7844")
        # Pad.cold: one tail jump from Pad's own landing-pad tail.
        jmp = [r for r in rows if r[2] == "jmp"][0]
        self.assertEqual(jmp[0], "0x605257c")
        self.assertEqual(jmp[3], "0x60527a0")


class BindingTests(unittest.TestCase):
    def test_body_hashes(self):
        data = open(m._bin_path(), "rb").read()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         m.ARTIFACT_SHA256)
        for start, end, want in (
                (m.PAD_ADDR, m.PAD_FDE_END,
                 "6f8cee586bf154c1348c2458f5925fb69943ee01e05c24d95bcdc8348ae55f0b"),
                (m.COLD_ADDR, m.COLD_FDE_END,
                 "41b351719351e161fb7ae9bafede7ce7b4f7dad768c2f61b4092fc047b789191")):
            body = data[m._va_to_off(start):m._va_to_off(end)]
            self.assertEqual(hashlib.sha256(body).hexdigest(), want)

    def test_source_hashes_reproduced(self):
        census = json.load(open(m.ROOT / m.CENSUS_PATH))["records"]
        by_start = {r["start"]: r for r in census}
        data = open(m._bin_path(), "rb").read()
        for addr in (m.PAD_ADDR, m.COLD_ADDR):
            rec = by_start[addr]
            body = data[m._va_to_off(addr):
                        m._va_to_off(rec["end"])]
            self.assertEqual(hashlib.sha256(body).hexdigest(),
                             rec["target_body_sha256"])
            zeroed = bytearray(body)
            for rel in rec["relocations"]:
                o, w = rel["offset"], rel["width"]
                zeroed[o:o + w] = b"\x00" * w
            self.assertEqual(hashlib.sha256(bytes(zeroed)).hexdigest(),
                             rec["source_body_sha256"])

    def test_crc_vectors(self):
        self.assertEqual(m.crc32c_value(b"123456789"), 0xE3069283)
        self.assertEqual(m.crc32c_value(b""), 0)
        self.assertEqual(m.crc32c_mask(0xE3069283),
                         m.crc32c_mask(0xE3069283))
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
        self.assertEqual(m.OFF_PENDING_SYNC, 0x88)
        self.assertEqual(m.OFF_SEEN_ERROR, 0x89)
        self.assertEqual(m.OFF_PERFORM_DATA_VERIFICATION, 0xD1)
        self.assertEqual(m.OFF_BUFFERED_DATA_CRC32C, 0xD4)
        self.assertEqual(m.WRITER_SIZE, 0xE0)


class LiveTests(unittest.TestCase):
    def test_live_engine_check(self):
        ok, report = m.live_engine_check()
        self.assertTrue(ok, report)
        self.assertEqual(len(report["legs"]), 6)


if __name__ == "__main__":
    unittest.main()
