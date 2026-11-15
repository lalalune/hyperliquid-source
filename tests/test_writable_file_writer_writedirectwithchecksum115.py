"""Tests for the node #115 rocksdb::WritableFileWriter::WriteDirectWithChecksum model.

Replays all 2,400 cases in cases.tsv through the tool, then checks
the model's key behaviours directly: the seen-error gate, the
entry-empty call (ONE zero-length PositionedAppend carrying the
recomputed buffered checksum -- unlike WriteDirect, which skips
its loop entirely -- and the success epilogue resetting the
buffered checksum to 0), the page pad (PadToAlignmentWith(0)
then the lazy file_advance / leftover_tail split at the
epilogue), the checksum recompute over the pad (Combine of the
entry buffered value with Extend(0, pad bytes, pad), UNCONDITIONAL),
the rate-limiter drain (grants are consumed and DISCARDED, then
one PositionedAppend of the whole padded buffer at
next_write_offset_; the IO_TOTAL skip), the checksum handoff
(the recomputed buffered value, always, through slot 5 -- no
verification gate), the single-append failure return (cursize_
restored to the ENTRY value, the buffered checksum recomputed
FRESH over the entry buffer, seen_error_ set after the
notifications, no flushed_size_ advance), the listener events
(finish type 1, failure type 9 = kPositionedAppend with trailing
(size, write_offset) where size is the PADDED size), the timer
guards (nanos armed iff perf_level > 2, the CPU half NEVER
armed -- it is dead in this FDE, pinned difference from the
siblings), the IOStats bytes counter and its flag, the three
TEST_SYNC_POINT sites, the caller census (one call, from Flush;
one tail jump into .cold), the CRC32C chain (Value + Mask +
Combine), the DecideRateLimiterPriority matrix, the IOOptions
defaults, the writer layout bindings, the FDE body hashes, and
the live engine check (a real file written by the model matches
the model's file image).
"""

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import writable_file_writer_writedirectwithchecksum115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-rocksdb-writable-file-writer-writedirectwithchecksum-115")


def _read_cases():
    rows = []
    with open(PACKET / "cases.tsv") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    return rows


def _writer(over=None, file_over=None, script=None):
    return m.make_writer(over, file_over, script)


def _wd(state, priority=m.IO_TOTAL):
    return m.write_direct_with_checksum(state, priority)


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
        self.assertEqual(groups, {"gate": 600, "drain": 600,
                                  "checksum": 600,
                                  "bindings": 600})

    def test_all_cases_replay(self):
        self.assertTrue(m.verify_cases(PACKET / "cases.tsv"))

    def test_case_ids_unique(self):
        rows = _read_cases()
        ids = [r["case_id"] for r in rows]
        self.assertEqual(len(ids), len(set(ids)))

    def test_drain_rows_cover_failures(self):
        rows = _read_cases()
        grows = [json.loads(r["expected_json"])
                 for r in rows if r["group"] == "drain"]
        failed = [e for e in grows if e.get("seen_error")]
        multi = [e for e in grows
                 if len(e.get("wdwc_grants", [])) >= 2]
        # Both the single-append failure arm and multi-grant
        # drains are exercised: failed rows restore the entry
        # cursize and recompute the buffered checksum fresh.
        self.assertGreater(len(failed), 50)
        self.assertGreater(len(multi), 100)
        for e in failed:
            # The scripted failure is ERR_IO (code 5) on the
            # single PositionedAppend.
            self.assertEqual(e["return_status"]["code"], 5)

    def test_checksum_rows_cover_recompute(self):
        rows = _read_cases()
        grows = [json.loads(r["expected_json"])
                 for r in rows if r["group"] == "checksum"]
        # Some checksum rows fail (fresh recompute over the
        # entry buffer) and some succeed with a leftover tail
        # (fresh recompute over the tail).
        failed = [e for e in grows if e.get("seen_error")]
        tailed = [e for e in grows
                  if e.get("wdwc_leftover_tail", 0) > 0]
        self.assertGreater(len(failed), 30)
        self.assertGreater(len(tailed), 100)


class GateTests(unittest.TestCase):
    def test_seen_error_returns_prev_error_and_writes_nothing(self):
        state = _writer({"seen_error": True, "cursize": 5,
                         "buf_hex": b"hello".hex()})
        s = _wd(state)
        self.assertFalse(s.is_ok())
        self.assertEqual(s.code, 5)
        self.assertEqual(s.summary()["state"], 1)
        self.assertEqual(len(state.file.image), 0)
        self.assertEqual(state.wdwc_positioned_appends, 0)
        # The gate reads seen_error_ first: nothing else changes.
        self.assertEqual(state.buf.cursize, 5)
        self.assertEqual(state.flushed_size, 0)

    def test_empty_buffer_returns_ok_with_zero_length_append(self):
        state = _writer({"cursize": 0,
                         "perform_data_verification": True,
                         "buffered_data_crc32c_checksum": 0xDEADBEEF})
        s = _wd(state)
        self.assertTrue(s.is_ok())
        # PINNED DIFFERENCE from WriteDirect: the entry-empty
        # path makes ONE zero-length PositionedAppend carrying
        # the recomputed buffered checksum (pad 0, so Combine
        # leaves it 0xDEADBEEF); no file write, no flushed_size_
        # advance, no refit -- and the success epilogue RESETS
        # the buffered checksum to 0 (fresh Extend over 0 bytes).
        self.assertEqual(state.wdwc_positioned_appends, 1)
        appends = [e for e in state.file.events
                   if e["op"] == "positioned_append"]
        self.assertEqual(len(appends), 1)
        self.assertEqual(appends[0]["len"], 0)
        self.assertEqual(appends[0]["checksum"], 0xDEADBEEF)
        self.assertEqual(state.buf.cursize, 0)
        self.assertEqual(state.flushed_size, 0)
        self.assertEqual(state.buffered_data_crc32c_checksum, 0)
        self.assertEqual(len(state.file.image), 0)

    def test_single_positional_write_no_limiter(self):
        state = _writer({"cursize": 10,
                         "buf_hex": b"0123456789".hex()})
        s = _wd(state)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.wdwc_grants, [])
        self.assertEqual(state.wdwc_positioned_appends, 1)
        # Pad 4086 (alignment 4096): one 4096-byte chunk.
        self.assertEqual(state.wdwc_pad, 4086)
        self.assertEqual(state.flushed_size, 4096)
        self.assertEqual(bytes(state.file.image),
                         b"0123456789" + b"\x00" * 4086)
        # file_advance 0 (10 < 4096): the whole buffer is the tail.
        self.assertEqual(state.next_write_offset, 0)
        self.assertEqual(state.buf.cursize, 10)

    def test_io_total_priority_skips_limiter(self):
        limiter = m.FakeRateLimiter([1])
        state = _writer({"rate_limiter_grants": [1],
                         "cursize": 10,
                         "buf_hex": b"0123456789".hex()})
        state.rate_limiter = limiter
        s = _wd(state, m.IO_TOTAL)
        self.assertTrue(s.is_ok())
        self.assertEqual(limiter.calls, [])
        self.assertEqual(state.wdwc_grants, [])
        self.assertEqual(state.wdwc_positioned_appends, 1)

    def test_non_total_priority_drains_then_single_append(self):
        state = _writer({"rate_limiter_grants": [4], "cursize": 10,
                         "buf_hex": b"0123456789".hex()})
        s = _wd(state, m.IO_LOW)
        self.assertTrue(s.is_ok())
        # The drain consumes [4, 4092] (the scripted grants run
        # out, so the tail grant takes the remainder) and the
        # grants are DISCARDED: exactly ONE PositionedAppend of
        # the whole padded 4096 bytes.
        self.assertEqual(state.wdwc_grants, [4, 4092])
        self.assertEqual(state.wdwc_positioned_appends, 1)
        self.assertEqual(state.flushed_size, 4096)


class DrainTests(unittest.TestCase):
    def test_drain_consumes_grants_then_single_append(self):
        state = _writer({"rate_limiter_grants": [100, 1000, 4096],
                         "capacity": 8192, "cursize": 5000,
                         "buf_seed": 7})
        data = bytes(state.buf.data[:5000])
        s = _wd(state, m.IO_LOW)
        self.assertTrue(s.is_ok())
        # left 8192 after the 3192-byte pad: grants [100, 1000,
        # 4096] then the 2996-byte remainder -- all DISCARDED;
        # one 8192-byte PositionedAppend at offset 0.
        self.assertEqual(state.wdwc_grants, [100, 1000, 4096, 2996])
        self.assertEqual(state.wdwc_positioned_appends, 1)
        self.assertEqual(state.flushed_size, 8192)
        self.assertEqual(bytes(state.file.image),
                         data + b"\x00" * 3192)
        # file_advance 4096, leftover tail 904.
        self.assertEqual(state.next_write_offset, 4096)
        self.assertEqual(state.buf.cursize, 904)
        self.assertEqual(bytes(state.buf.data[:904]), data[4096:5000])

    def test_grant_exhaustion_falls_back_to_remaining(self):
        state = _writer({"rate_limiter_grants": [4], "cursize": 10,
                         "buf_hex": b"0123456789".hex()})
        s = _wd(state, m.IO_LOW)
        self.assertTrue(s.is_ok())
        # The limiter's scripted grants run out after one call;
        # the tail grant takes granted = remaining.
        self.assertEqual(state.wdwc_grants, [4, 4092])
        self.assertEqual(state.wdwc_positioned_appends, 1)
        self.assertEqual(state.flushed_size, 4096)

    def test_failure_on_single_append_restores_entry_cursize(self):
        state = _writer({"rate_limiter_grants": [4096, 4096],
                         "capacity": 8192, "cursize": 5000,
                         "buf_seed": 7})
        data = bytes(state.buf.data[:5000])
        state.script = {"positioned_append_statuses": [dict(m.ERR_IO)]}
        s = _wd(state, m.IO_LOW)
        self.assertFalse(s.is_ok())
        self.assertEqual(s.code, 5)
        self.assertTrue(state.seen_error)
        self.assertEqual(state.wdwc_grants, [4096, 4096])
        self.assertEqual(state.wdwc_positioned_appends, 1)
        # The drain grants stay consumed but nothing is flushed;
        # cursize_ is restored to the ENTRY value (5000), and
        # the buffered checksum is recomputed FRESH over the
        # entry buffer.
        self.assertEqual(state.flushed_size, 0)
        self.assertEqual(state.next_write_offset, 0)
        self.assertEqual(state.buf.cursize, 5000)
        self.assertEqual(state.buffered_data_crc32c_checksum,
                         m.crc32c_value(data))
        self.assertEqual(len(state.file.image), 0)

    def test_aligned_cursize_has_no_pad_and_no_refit(self):
        state = _writer({"cursize": 4096, "buf_seed": 11})
        s = _wd(state)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.wdwc_pad, 0)
        self.assertEqual(state.wdwc_file_advance, 4096)
        self.assertEqual(state.wdwc_leftover_tail, 0)
        self.assertEqual(state.next_write_offset, 4096)
        self.assertEqual(state.buf.cursize, 0)


class ChecksumTests(unittest.TestCase):
    def test_handoff_is_recomputed_buffered_value(self):
        # The handoff is Combine(entry buffered, Extend(0, pad
        # bytes, pad), pad) -- never a fresh per-chunk Extend
        # and never the entry value alone when pad > 0.
        state = _writer({"perform_data_verification": True,
                         "buffered_data_crc32c_checksum": 0x12345678,
                         "buffered_data_with_checksum": True,
                         "rate_limiter_grants": [5, 6],
                         "alignment": 512, "capacity": 1024,
                         "cursize": 11,
                         "buf_hex": b"hello world".hex()})
        s = _wd(state, m.IO_LOW)
        self.assertTrue(s.is_ok())
        appends = [e for e in state.file.events
                   if e["op"] == "positioned_append"]
        # Pad 501 (alignment 512): ONE 512-byte append.
        self.assertEqual(len(appends), 1)
        self.assertEqual(appends[0]["checksum"],
                         m.crc32c_combine(
                             0x12345678,
                             m.crc32c_value(b"\x00" * 501), 501))
        self.assertNotEqual(appends[0]["checksum"], 0x12345678)
        # The checksum arm is UNCONDITIONAL: slot 5 always.
        calls = [e for e in state.events
                 if e["op"] == "positioned_append_call"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["slot"], 5)
        # Success recompute: fresh Extend over the 11-byte tail.
        self.assertEqual(state.buffered_data_crc32c_checksum,
                         m.crc32c_value(b"hello world"))

    def test_verification_flags_do_not_gate_the_checksum(self):
        # perform_data_verification_ off AND
        # buffered_data_with_checksum_ off: the append STILL
        # carries the recomputed buffered checksum via slot 5.
        state = _writer({"perform_data_verification": False,
                         "buffered_data_crc32c_checksum": 0x12345678,
                         "buffered_data_with_checksum": False,
                         "alignment": 512, "capacity": 1024,
                         "cursize": 11,
                         "buf_hex": b"hello world".hex()})
        s = _wd(state)
        self.assertTrue(s.is_ok())
        appends = [e for e in state.file.events
                   if e["op"] == "positioned_append"]
        self.assertEqual(len(appends), 1)
        self.assertEqual(appends[0]["checksum"],
                         m.crc32c_combine(
                             0x12345678,
                             m.crc32c_value(b"\x00" * 501), 501))
        calls = [e for e in state.events
                 if e["op"] == "positioned_append_call"]
        self.assertEqual(calls[0]["slot"], 5)

    def test_zero_pad_leaves_buffered_checksum_unchanged(self):
        # pad == 0: Combine(old, Extend(0, ptr, 0) = 0, 0) =
        # old ^ 0 = old (the degenerate combine, no early
        # return); the handoff is the entry buffered value.
        state = _writer({"cursize": 4096, "buf_seed": 11,
                         "buffered_data_crc32c_checksum": 0x12345678})
        s = _wd(state)
        self.assertTrue(s.is_ok())
        appends = [e for e in state.file.events
                   if e["op"] == "positioned_append"]
        self.assertEqual(appends[0]["checksum"], 0x12345678)
        # Success recompute over the 0-byte leftover: 0.
        self.assertEqual(state.buffered_data_crc32c_checksum, 0)

    def test_failure_recomputes_checksum_fresh_over_entry(self):
        state = _writer({"perform_data_verification": True,
                         "buffered_data_crc32c_checksum": 0x12345678,
                         "cursize": 5,
                         "buf_hex": b"hello".hex()})
        state.script = {"positioned_append_statuses": [dict(m.ERR_IO)]}
        s = _wd(state)
        self.assertFalse(s.is_ok())
        # PINNED DIFFERENCE from WriteDirect: the failure path
        # recomputes the buffered checksum FRESH as Extend(0,
        # entry buffer, entry cursize) -- seed 0, NOT a Combine
        # -- and cursize_ is restored to the entry value.
        self.assertEqual(state.buffered_data_crc32c_checksum,
                         m.crc32c_value(b"hello"))
        self.assertEqual(state.buf.cursize, 5)


class ListenerTests(unittest.TestCase):
    def test_no_listeners_no_notify_events(self):
        state = _writer({"listeners": [], "perf_level": 5,
                         "clock_pairs": m._clock_pairs(),
                         "cursize": 10,
                         "buf_hex": b"0123456789".hex()})
        s = _wd(state)
        self.assertTrue(s.is_ok())
        self.assertEqual([e for e in _events(state)
                          if e["op"].startswith("notify_")], [])

    def test_finish_event_type_1(self):
        pairs = [(1000000 + 1000 * j, 500000 + 700 * j)
                 for j in range(8)]
        state = _writer({"listeners": ["L1"], "perf_level": 5,
                         "clock_pairs": pairs,
                         "next_write_offset": 4096,
                         "cursize": 10,
                         "buf_hex": b"0123456789".hex()})
        s = _wd(state)
        self.assertTrue(s.is_ok())
        finishes = [e for e in state.events
                    if e["op"] == "notify_finish"]
        self.assertEqual(len(finishes), 1)
        self.assertEqual(finishes[0]["type"], 1)
        self.assertEqual(finishes[0]["offset"], 4096)
        # nbytes is the PADDED size (4096), not the cursize (10).
        self.assertEqual(finishes[0]["nbytes"], 4096)
        self.assertEqual(finishes[0]["elapsed_nanos"], 700)

    def test_failure_event_type_9_with_trailing_u64s(self):
        state = _writer({"listeners": ["L1", "L2"],
                         "next_write_offset": 777,
                         "rate_limiter_grants": [4],
                         "cursize": 10,
                         "buf_hex": b"0123456789".hex()})
        state.script = {"positioned_append_statuses": [dict(m.ERR_IO)]}
        s = _wd(state, m.IO_LOW)
        self.assertFalse(s.is_ok())
        failures = [e for e in state.events
                    if e["op"] == "notify_failure"]
        self.assertEqual(len(failures), 2)  # one per listener
        self.assertEqual(failures[0]["type"], 9)
        # PINNED DIFFERENCE from WriteBufferedWithChecksum:
        # (size, write_offset), not (left, old_size) -- and
        # size is the PADDED size (4096), not the first drain
        # grant (4): there is only one append.
        self.assertEqual(failures[0]["size"], 4096)
        self.assertEqual(failures[0]["write_offset"], 777)


class GuardTests(unittest.TestCase):
    def test_perf_0_no_guard_counters(self):
        state = _writer({"perf_level": 0,
                         "clock_pairs": m._clock_pairs(),
                         "cursize": 10,
                         "buf_hex": b"0123456789".hex()})
        s = _wd(state)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.wdwc_nanos, 0)
        self.assertEqual(state.wdwc_cpu_nanos, 0)

    def test_perf_3_nanos_only_never_cpu(self):
        state = _writer({"perf_level": 3,
                         "clock_pairs": m._clock_pairs(),
                         "cursize": 10,
                         "buf_hex": b"0123456789".hex()})
        s = _wd(state)
        self.assertTrue(s.is_ok())
        self.assertGreater(state.wdwc_nanos, 0)
        # PINNED: the CPU half is DEAD in this FDE (flag -0x18f
        # is written 0 and never set; no clock-or-default
        # helper is called), so cpu_nanos stays 0 at every level.
        self.assertEqual(state.wdwc_cpu_nanos, 0)

    def test_perf_5_nanos_only_never_cpu(self):
        state = _writer({"perf_level": 5,
                         "clock_pairs": m._clock_pairs(),
                         "cursize": 10,
                         "buf_hex": b"0123456789".hex()})
        s = _wd(state)
        self.assertTrue(s.is_ok())
        self.assertGreater(state.wdwc_nanos, 0)
        self.assertEqual(state.wdwc_cpu_nanos, 0)

    def test_iostats_bytes_flag_skips_add(self):
        state = _writer({"iostats_bytes_flag": True, "cursize": 10,
                         "buf_hex": b"0123456789".hex()})
        s = _wd(state)
        self.assertTrue(s.is_ok())
        self.assertEqual(state.iostats_bytes_written, 0)
        state = _writer({"iostats_bytes_flag": False, "cursize": 10,
                         "buf_hex": b"0123456789".hex()})
        s = _wd(state)
        self.assertTrue(s.is_ok())
        # The counter advances by the PADDED size (4096).
        self.assertEqual(state.iostats_bytes_written, 4096)

    def test_sync_points_three_sites(self):
        state = _writer({"sync_point_enabled": True,
                         "rate_limiter_grants": [5, 5],
                         "cursize": 10,
                         "buf_hex": b"0123456789".hex()})
        s = _wd(state, m.IO_LOW)
        self.assertTrue(s.is_ok())
        syncs = [e for e in state.events if e["op"] == "sync_point"]
        # One call -> one drain-head gate (0x6050ed1), one
        # success gate (0x6051398) and one bytes-add gate
        # (0x60513c0), in binary order.
        self.assertEqual(len(syncs), 3)
        self.assertEqual([e["site"] for e in syncs],
                         ["0x6050ed1", "0x6051398", "0x60513c0"])


class CensusTests(unittest.TestCase):
    def test_caller_census_one_call_one_tail_jump(self):
        pkt = json.load(open(PACKET / "census.json"))
        self.assertEqual(pkt["validated_sites"], 2)
        self.assertEqual(pkt["targets"]["0x6050c80"]["calls"], 1)
        self.assertEqual(pkt["targets"]["0x6050c80"]["jumps"], 0)
        self.assertEqual(pkt["targets"]["0x6050c80"]["lea_refs"], 0)
        self.assertEqual(pkt["targets"]["0x6050b8a"]["calls"], 0)
        self.assertEqual(pkt["targets"]["0x6050b8a"]["jumps"], 1)
        self.assertEqual(pkt["targets"]["0x6050b8a"]["lea_refs"], 0)
        rows = [l.split("\t") for l in
                open(PACKET / "callers.tsv").read().splitlines()[1:]]
        self.assertEqual(len(rows), 2)
        calls = [r for r in rows if r[2] == "call"]
        self.assertEqual(len(calls), 1)
        # The only caller is Flush (0x6051a20), at 0x60523b1.
        self.assertEqual(calls[0][3], "0x60523b1")
        self.assertEqual(calls[0][4], "0x6051a20")
        jmps = [r for r in rows if r[2] == "jmp"]
        self.assertEqual(len(jmps), 1)
        # The .cold tail jump from the main FDE tail (0x60518de).
        self.assertEqual(jmps[0][0], "0x6050b8a")
        self.assertEqual(jmps[0][3], "0x60518de")


class BindingTests(unittest.TestCase):
    def test_body_hashes(self):
        data = open(m._bin_path(), "rb").read()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         m.ARTIFACT_SHA256)
        for start, end, want in (
                (m.WDWC_ADDR, m.WDWC_FDE_END,
                 "cc22775ea5d3906acc8f401a09272eb2d6942514ae9c922067e756bf5d139de8"),
                (m.WDWC_COLD_ADDR, m.WDWC_COLD_FDE_END,
                 "eb4e08d3e3f13c068bc367c21fc7a9ecbfe27db362d7d04a2d6a35111930637c")):
            body = data[m._va_to_off(start):m._va_to_off(end)]
            self.assertEqual(hashlib.sha256(body).hexdigest(), want)

    def test_source_hash_reproduced_for_cold(self):
        census = json.load(open(m.ROOT / m.CENSUS_PATH))["records"]
        by_start = {r["start"]: r for r in census}
        data = open(m._bin_path(), "rb").read()
        rec = by_start[m.WDWC_COLD_ADDR]
        body = data[m._va_to_off(m.WDWC_COLD_ADDR):
                    m._va_to_off(rec["end"])]
        self.assertEqual(hashlib.sha256(body).hexdigest(),
                         rec["target_body_sha256"])
        zeroed = bytearray(body)
        for rel in rec["relocations"]:
            o, w = rel["offset"], rel["width"]
            zeroed[o:o + w] = b"\x00" * w
        self.assertEqual(hashlib.sha256(bytes(zeroed)).hexdigest(),
                         rec["source_body_sha256"])
        self.assertEqual(len(rec["relocations"]), 12)

    def test_main_has_no_census_record(self):
        census = json.load(open(m.ROOT / m.CENSUS_PATH))["records"]
        by_start = {r["start"]: r for r in census}
        self.assertNotIn(m.WDWC_ADDR, by_start)

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
