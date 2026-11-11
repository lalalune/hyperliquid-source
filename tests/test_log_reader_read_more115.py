"""Tests for the node #115 log::Reader::ReadMore model.

Replays all 2,400 cases in cases.tsv through the tool's replay_case,
then checks the model's key behaviours directly: the read path
(full/short/empty reads, the 0x7fff/0x8000 eof boundary, offset
advance before the status check, the error arm with ReportDrop +
read_error_ + kEof), the drain path (kBadHeader vs kEof, drop_size
discipline, no file read), multi-call sequences (state sticks across
calls), and the live engine check (real file round trip + the
empty-literal byte).
"""

import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import log_reader_read_more115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-rocksdb-log-reader-read-more-115")


def _read_cases():
    rows = []
    with open(PACKET / "cases.tsv") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    return rows


def _run(**kw):
    p = {"buffer": "", "end_of_buffer_offset": 0}
    p.update(kw)
    return m._run_scenario(p)


def _call(out, i=0):
    return out["calls_out"][i]


class ReplayTests(unittest.TestCase):
    def test_case_count(self):
        rows = _read_cases()
        self.assertEqual(len(rows), 2400)
        groups = {}
        for r in rows:
            groups[r["group"]] = groups.get(r["group"], 0) + 1
        self.assertEqual(groups, {"read_path": 600, "drain_path": 600,
                                  "sequences": 600, "bindings": 600})

    def test_all_cases_replay(self):
        bad = []
        for r in _read_cases():
            ok, detail = m.replay_case(r)
            if not ok:
                bad.append((r["id"], detail))
        self.assertEqual(bad, [], f"{len(bad)} cases failed: {bad[:5]}")


class ReadPathTests(unittest.TestCase):
    def _read(self, data, **kw):
        return _run(read_script=[{"ok": True, "bytes": data.hex(),
                                  "state": None}], **kw)

    def test_offset_addition_wraps_u64_before_success_or_failure(self):
        data = m._read_binary()
        offset = m._va_to_off(0x5F019BB)
        self.assertEqual(data[offset:offset + 4], bytes.fromhex("48014360"))
        for ok in (True, False):
            with self.subTest(ok=ok):
                reader = m.Reader(end_of_buffer_offset=(1 << 64) - 1)
                drop_size, error = [7], [8]
                result, events = m.read_more(
                    reader, drop_size, error,
                    lambda *_: (ok, b"ab", b"status" if not ok else None),
                    m.make_report_drop())
                self.assertEqual(reader.end_of_buffer_offset, 1)
                event = next(value for kind, value in events if kind == "file_read")
                self.assertEqual(event["end_of_buffer_offset"], 1)
                self.assertEqual(result, ok)
                self.assertEqual(drop_size[0], 7)
                self.assertEqual(error[0], 8 if ok else m.K_EOF)

    def test_full_block_read_returns_true_without_eof(self):
        out = self._read(m._bytes(m.K_BLOCK_SIZE, 1))
        call = _call(out)
        self.assertTrue(call["return"])
        self.assertEqual(len(bytes.fromhex(call["buffer_after"])),
                         m.K_BLOCK_SIZE)
        self.assertFalse(out["eof_after"])
        self.assertEqual(out["end_of_buffer_offset_after"], m.K_BLOCK_SIZE)
        self.assertEqual(call["buffer_data_after"], "backing_store")

    def test_short_read_sets_eof_and_offset(self):
        out = self._read(m._bytes(100, 3))
        self.assertTrue(_call(out)["return"])
        self.assertTrue(out["eof_after"])
        self.assertEqual(out["eof_offset_after"], 100)
        self.assertEqual(out["end_of_buffer_offset_after"], 100)

    def test_empty_read_sets_eof_with_offset_zero(self):
        out = self._read(b"")
        self.assertTrue(_call(out)["return"])
        self.assertTrue(out["eof_after"])
        self.assertEqual(out["eof_offset_after"], 0)

    def test_eof_boundary_0x7fff_vs_0x8000(self):
        out = self._read(m._bytes(0x7FFF, 1))
        self.assertTrue(out["eof_after"])
        self.assertEqual(out["eof_offset_after"], 0x7FFF)
        out = self._read(m._bytes(0x8000, 1))
        self.assertFalse(out["eof_after"])
        self.assertEqual(out["eof_offset_after"], 0)

    def test_failed_read_clears_buffer_sets_error_and_reports(self):
        out = _run(read_script=[{"ok": False,
                                 "bytes": m._bytes(100, 5).hex(),
                                 "state": "deadbeef"}],
                   end_of_buffer_offset=m.K_BLOCK_SIZE)
        call = _call(out)
        self.assertFalse(call["return"])
        self.assertEqual(call["error"], m.K_EOF)
        self.assertEqual(call["buffer_after"], "")
        self.assertEqual(call["buffer_data_after"], "empty")
        self.assertTrue(out["read_error_after"])
        # Offset still advances by the partial bytes, before the
        # status check (upstream log_reader.cc:754).
        self.assertEqual(out["end_of_buffer_offset_after"],
                         m.K_BLOCK_SIZE + 100)
        self.assertEqual(out["report_drop_calls"], [[m.K_BLOCK_SIZE,
                                                     "deadbeef"]])
        self.assertIn(["status_state_freed", True], out["events"])

    def test_failed_read_with_no_bytes_and_null_state(self):
        out = _run(read_script=[{"ok": False, "bytes": "",
                                 "state": None}],
                   end_of_buffer_offset=500)
        call = _call(out)
        self.assertFalse(call["return"])
        self.assertEqual(call["error"], m.K_EOF)
        self.assertEqual(out["end_of_buffer_offset_after"], 500)
        self.assertEqual(out["report_drop_calls"], [[m.K_BLOCK_SIZE,
                                                     None]])
        self.assertNotIn(["status_state_freed", True], out["events"])

    def test_successful_read_with_state_frees_it(self):
        out = _run(read_script=[{"ok": True, "bytes": m._bytes(10, 1).hex(),
                                 "state": "01020304"}])
        self.assertTrue(_call(out)["return"])
        self.assertIn(["status_state_freed", True], out["events"])

    def test_read_replaces_stale_buffer_wholesale(self):
        out = _run(buffer=m._bytes(500, 9).hex(),
                   end_of_buffer_offset=1000,
                   read_script=[{"ok": True,
                                 "bytes": m._bytes(10, 1).hex(),
                                 "state": None}])
        self.assertEqual(_call(out)["buffer_after"],
                         m._bytes(10, 1).hex())


class DrainPathTests(unittest.TestCase):
    def test_eof_with_truncated_header_reports_bad_header(self):
        out = _run(buffer=m._bytes(5, 5).hex(), eof=True,
                   end_of_buffer_offset=m.K_BLOCK_SIZE)
        call = _call(out)
        self.assertFalse(call["return"])
        self.assertEqual(call["error"], m.K_BAD_HEADER)
        self.assertEqual(call["drop_size"], 5)
        self.assertEqual(call["buffer_after"], "")
        self.assertEqual(call["buffer_data_after"], "empty")
        self.assertEqual(out["report_drop_calls"], [])
        self.assertEqual(out["end_of_buffer_offset_after"], m.K_BLOCK_SIZE)

    def test_eof_with_empty_buffer_reports_eof(self):
        out = _run(buffer="", eof=True, end_of_buffer_offset=100)
        call = _call(out)
        self.assertFalse(call["return"])
        self.assertEqual(call["error"], m.K_EOF)
        self.assertEqual(call["drop_size"], 0)  # no drop_size write
        self.assertEqual(out["end_of_buffer_offset_after"], 100)

    def test_read_error_drains_the_same_way(self):
        out = _run(buffer=m._bytes(7, 7).hex(), read_error=True,
                   end_of_buffer_offset=0)
        call = _call(out)
        self.assertFalse(call["return"])
        self.assertEqual(call["error"], m.K_BAD_HEADER)
        self.assertEqual(call["drop_size"], 7)
        out = _run(buffer="", read_error=True, end_of_buffer_offset=0)
        self.assertEqual(_call(out)["error"], m.K_EOF)

    def test_drain_never_calls_the_file_read(self):
        # The script would fail loudly if consumed; the drain path
        # must not touch it (no file_read event at all).
        out = _run(buffer=m._bytes(3, 3).hex(), eof=True,
                   read_script=[{"ok": False, "bytes": "", "state": "ff"}])
        kinds = [k for k, _ in out["events"]]
        self.assertNotIn("file_read", kinds)
        self.assertNotIn("report_drop", kinds)
        self.assertEqual(_call(out)["error"], m.K_BAD_HEADER)

    def test_both_flags_set_still_drains(self):
        out = _run(buffer=m._bytes(11, 1).hex(), eof=True,
                   read_error=True, end_of_buffer_offset=0)
        self.assertEqual(_call(out)["error"], m.K_BAD_HEADER)
        self.assertEqual(_call(out)["drop_size"], 11)


class SequenceTests(unittest.TestCase):
    def test_two_full_then_short(self):
        out = _run(calls=3, read_script=[
            {"ok": True, "bytes": m._bytes(m.K_BLOCK_SIZE, 1).hex(),
             "state": None},
            {"ok": True, "bytes": m._bytes(m.K_BLOCK_SIZE, 2).hex(),
             "state": None},
            {"ok": True, "bytes": m._bytes(100, 3).hex(),
             "state": None}])
        self.assertEqual([c["return"] for c in out["calls_out"]],
                         [True, True, True])
        self.assertTrue(out["eof_after"])
        self.assertEqual(out["eof_offset_after"], 100)
        self.assertEqual(out["end_of_buffer_offset_after"],
                         2 * m.K_BLOCK_SIZE + 100)

    def test_short_then_drain_then_drain(self):
        out = _run(calls=3, read_script=[
            {"ok": True, "bytes": m._bytes(5, 1).hex(), "state": None}])
        self.assertEqual([c["return"] for c in out["calls_out"]],
                         [True, False, False])
        self.assertEqual(out["calls_out"][1]["error"], m.K_BAD_HEADER)
        self.assertEqual(out["calls_out"][1]["drop_size"], 5)
        self.assertEqual(out["calls_out"][2]["error"], m.K_EOF)
        # The empty-buffer drain does NOT write *drop_size, and each
        # call gets a fresh out-param, so it stays 0 here.
        self.assertEqual(out["calls_out"][2]["drop_size"], 0)

    def test_error_sticks_no_further_reads(self):
        out = _run(calls=3, read_script=[
            {"ok": False, "bytes": m._bytes(10, 1).hex(),
             "state": "cafe"}])
        self.assertEqual([c["return"] for c in out["calls_out"]],
                         [False, False, False])
        self.assertEqual([c["error"] for c in out["calls_out"]],
                         [m.K_EOF, m.K_EOF, m.K_EOF])
        self.assertTrue(out["read_error_after"])
        kinds = [k for k, _ in out["events"]]
        self.assertEqual(kinds.count("file_read"), 1)
        self.assertEqual(kinds.count("report_drop"), 1)


class BindingsTests(unittest.TestCase):
    def test_functions_tsv_matches_binary_and_census(self):
        rows = list(open(PACKET / "functions.tsv"))[1:]
        self.assertEqual(len(rows), 1)
        data = m._read_binary()
        for row in rows:
            cols = row.rstrip("\n").split("\t")
            start, end = int(cols[1], 16), int(cols[2], 16)
            body = data[m._va_to_off(start):m._va_to_off(end)]
            self.assertEqual(hashlib.sha256(body).hexdigest(), cols[4])
            self.assertEqual(cols[4],
                             "bb83379f1674d6eb1b4574cd9fd27e3424428e3a5c55d8"
                             "588b7bfe22cdb3c55d")

    def test_caller_census(self):
        census = json.load(open(PACKET / "census.json"))
        self.assertEqual(census["validated_sites"], 1)
        self.assertEqual(census["targets"]["0x5f018d0"]["calls"], 1)
        self.assertEqual(census["targets"]["0x5f018d0"]["jumps"], 0)
        self.assertEqual(census["targets"]["0x5f018d0"]["lea_refs"], 0)
        sites = [l.split("\t") for l in
                 open(PACKET / "callers.tsv").read().splitlines()[1:]]
        by_site = {row[3]: row for row in sites}
        self.assertEqual(by_site["0x5f01aab"][4], "0x5f01a30")

    def test_reader_layout_pins_the_observed_fields(self):
        layout = {n: (o, s) for n, o, s in m.READER_LAYOUT}
        self.assertEqual(layout["file_"], (0x18, 8))
        self.assertEqual(layout["reporter_"], (0x20, 8))
        self.assertEqual(layout["backing_store_"], (0x30, 8))
        self.assertEqual(layout["buffer_"], (0x38, 16))
        self.assertEqual(layout["eof_"], (0x48, 1))
        self.assertEqual(layout["read_error_"], (0x49, 1))
        self.assertEqual(layout["eof_offset_"], (0x50, 8))
        self.assertEqual(layout["end_of_buffer_offset_"], (0x60, 8))
        self.assertEqual(layout["size"], (0x00, 0xF0))

    def test_reloc_targets_pin_the_engine_callees(self):
        data = m._read_binary()
        by_start = {r["start"]: r for r in m._read_census()}
        rec = by_start[0x5F018D0]
        targets = {}
        for rel in rec["relocations"]:
            o, w = rel["offset"], rel["width"]
            site = 0x5F018D0 + o
            disp = struct.unpack_from("<i", data,
                                      m._va_to_off(site))[0]
            targets[o] = site + w + disp
        self.assertEqual(targets[66], 0x4376FD)    # empty literal
        self.assertEqual(targets[131], 0x4376FD)   # empty literal
        self.assertEqual(targets[155], 0x4376FD)   # empty literal
        self.assertEqual(targets[200], 0x6048E00)  # SeqFileReader::Read
        self.assertEqual(targets[277], 0x63F0DC0)  # PLT _ZdaPv
        self.assertEqual(targets[312], 0x5F01570)  # ReportDrop thunk
        self.assertEqual(targets[336], 0x63F0D70)  # PLT __stack_chk_fail
        self.assertEqual(targets[348], 0x5F0189A)  # landing pad

    def test_live_engine_check(self):
        empty_literal_zero, round_trip_ok = m.live_engine_check()
        self.assertTrue(empty_literal_zero)
        self.assertTrue(round_trip_ok)


if __name__ == "__main__":
    unittest.main()
