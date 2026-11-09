"""Tests for the node #115 log::FragmentBufferedReader::TryReadMore
model.

Replays all 2,400 cases in cases.tsv through the tool's replay_case,
then checks the model's key behaviours directly: the read path (full
and short reads, error arms, end_of_buffer_offset_ accounting, the
stale buffer cleared first), the eof/UnmarkEOFInternal path (tail
preservation, full vs short refill, the two memmove guards, the
ReportDrop(added) only-when-added->0 rule, the foreign-vtable arms),
the drain (kBadHeader with a non-empty buffer, kEof with an empty
one -- and the unconditional *drop_size write that differs from
Reader::ReadMore), and the live engine check (real file round trip
and file growth after EOF).
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import fragment_buffered_reader_try_read_more115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-rocksdb-fragment-buffered-reader-try-read-more-115")


def _read_cases():
    rows = []
    with open(PACKET / "cases.tsv") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    return rows


def _run(p):
    return m._run_scenario(p)


def _read_param(file_bytes=b"", **kw):
    p = {"buffer": b"".hex(), "buffer_offset": None,
         "end_of_buffer_offset": 0, "eof_offset": 0,
         "eof": False, "read_error": False, "reporter": True,
         "file_script": [{"bytes": file_bytes.hex(), "ok": True}]}
    p.update(kw)
    return p


def _eof_param(buf, eof_offset, growth=b"", **kw):
    consumed = eof_offset - len(buf)
    p = {"buffer": buf.hex(), "buffer_offset": consumed,
         "end_of_buffer_offset": eof_offset + 5000,
         "eof_offset": eof_offset, "eof": True,
         "read_error": False, "reporter": True,
         "file_script": [{"bytes": growth.hex(), "ok": True}]}
    p.update(kw)
    return p


class ReplayTests(unittest.TestCase):
    def test_case_count(self):
        rows = _read_cases()
        self.assertEqual(len(rows), 2400)
        groups = {}
        for r in rows:
            groups[r["group"]] = groups.get(r["group"], 0) + 1
        self.assertEqual(groups, {"read_path": 600, "eof_unmark": 600,
                                  "drain": 600, "bindings": 600})

    def test_all_cases_replay(self):
        bad = []
        for r in _read_cases():
            ok, detail = m.replay_case(r)
            if not ok:
                bad.append((r["id"], detail))
        self.assertEqual(bad, [], f"{len(bad)} cases failed: {bad[:5]}")


class ReadPathTests(unittest.TestCase):
    def test_full_block_read_leaves_eof_clear(self):
        out = _run(_read_param(bytes(m.K_BLOCK_SIZE)))
        self.assertTrue(out["ok"])
        self.assertFalse(out["eof_after"])
        self.assertEqual(out["eof_offset_after"], 0)
        self.assertEqual(out["end_of_buffer_offset_after"], m.K_BLOCK_SIZE)
        self.assertEqual(out["error"], None)
        self.assertEqual(out["drop_size"], 0)

    def test_short_read_sets_eof_and_offset(self):
        out = _run(_read_param(b"hello"))
        self.assertTrue(out["ok"])
        self.assertTrue(out["eof_after"])
        self.assertEqual(out["eof_offset_after"], 5)
        self.assertEqual(out["end_of_buffer_offset_after"], 5)
        self.assertEqual(out["buffer_after"], b"hello".hex())

    def test_empty_file_read_sets_eof_with_offset_zero(self):
        out = _run(_read_param(b""))
        self.assertTrue(out["ok"])
        self.assertTrue(out["eof_after"])
        self.assertEqual(out["eof_offset_after"], 0)

    def test_boundary_0x7fff_is_short_but_0x8000_is_full(self):
        out = _run(_read_param(bytes(0x7FFF)))
        self.assertTrue(out["eof_after"])
        self.assertEqual(out["eof_offset_after"], 0x7FFF)
        out = _run(_read_param(bytes(0x8000)))
        self.assertFalse(out["eof_after"])

    def test_error_with_zero_bytes_still_reports_kblocksize(self):
        # Unlike UnmarkEOFInternal (which reports only when added
        # > 0), the read-path error arm ALWAYS calls
        # ReportDrop(kBlockSize, status), even with 0 bytes read.
        out = _run(_read_param(
            b"", file_script=[{"bytes": "", "ok": False, "state": 5}]))
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], m.K_EOF)
        self.assertTrue(out["read_error_after"])
        self.assertEqual(out["report_drops"],
                         [{"bytes": m.K_BLOCK_SIZE, "status_code": 1,
                           "reported": True}])
        self.assertEqual(out["freed_states"], [5])
        self.assertEqual(out["end_of_buffer_offset_after"], 0)

    def test_error_with_bytes_reports_kblocksize_and_advances_offset(self):
        # A failed read still advances end_of_buffer_offset_ by the
        # partial bytes (the add happens before the status check).
        out = _run(_read_param(
            b"", file_script=[{"bytes": m._pattern(100, 2).hex(),
                               "ok": False, "state": 6}]))
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], m.K_EOF)
        self.assertEqual(out["end_of_buffer_offset_after"], 100)
        self.assertEqual(out["report_drops"],
                         [{"bytes": m.K_BLOCK_SIZE, "status_code": 1,
                           "reported": True}])
        self.assertEqual(out["buffer_after"], "")

    def test_error_without_reporter_skips_corruption_call(self):
        out = _run(_read_param(
            b"", file_script=[{"bytes": m._pattern(10, 2).hex(),
                               "ok": False, "state": 7}],
            reporter=False))
        self.assertFalse(out["ok"])
        self.assertEqual(out["report_drops"],
                         [{"bytes": m.K_BLOCK_SIZE, "status_code": 1,
                           "reported": False}])

    def test_stale_buffer_is_cleared_first(self):
        out = _run(_read_param(m._pattern(50, 11), buffer=b"stale".hex(),
                               buffer_offset=0))
        self.assertTrue(out["ok"])
        self.assertEqual(out["buffer_after"],
                         m._pattern(50, 11).hex())

    def test_out_params_untouched_on_ok_read(self):
        out = _run(_read_param(m._pattern(100, 4), drop_size_in=999,
                               error_in=3))
        self.assertTrue(out["ok"])
        self.assertEqual(out["drop_size"], 999)
        self.assertEqual(out["error"], 3)


class UnmarkTests(unittest.TestCase):
    def test_tail_preserved_and_full_refill_clears_eof(self):
        tail = m._pattern(100, 3)
        growth = m._pattern(m.K_BLOCK_SIZE - 100, 17)
        out = _run(_eof_param(tail, 100, growth))
        self.assertTrue(out["ok"])
        self.assertFalse(out["eof_after"])
        self.assertEqual(out["eof_offset_after"], 0)
        self.assertEqual(bytes.fromhex(out["buffer_after"]),
                         tail + growth)
        self.assertEqual(out["buffer_offset_after"], 0)
        self.assertEqual(out["end_of_buffer_offset_after"],
                         100 + 5000 + len(growth))

    def test_short_refill_resets_eof_with_grown_offset(self):
        tail = m._pattern(50, 3)
        out = _run(_eof_param(tail, 100, m._pattern(25, 19)))
        self.assertTrue(out["ok"])
        self.assertTrue(out["eof_after"])
        self.assertEqual(out["eof_offset_after"], 125)
        self.assertEqual(bytes.fromhex(out["buffer_after"]),
                         tail + m._pattern(25, 19))

    def test_empty_eof_then_file_grows(self):
        out = _run(_eof_param(b"", 0, m._pattern(100, 13)))
        self.assertTrue(out["ok"])
        self.assertTrue(out["eof_after"])
        self.assertEqual(out["eof_offset_after"], 100)
        self.assertEqual(bytes.fromhex(out["buffer_after"]),
                         m._pattern(100, 13))

    def test_no_growth_returns_true_with_tail_unchanged(self):
        tail = m._pattern(100, 3)
        out = _run(_eof_param(tail, 100, b""))
        self.assertTrue(out["ok"])
        self.assertTrue(out["eof_after"])
        self.assertEqual(out["eof_offset_after"], 100)
        self.assertEqual(bytes.fromhex(out["buffer_after"]), tail)

    def test_tail_memmove_guard_fires_when_buffer_is_foreign(self):
        tail = m._pattern(10, 3)
        out = _run(_eof_param(tail, 100, m._pattern(20, 21),
                              buffer_offset=None))
        self.assertTrue(out["ok"])
        kinds = [k for k, _ in out["events"]]
        self.assertIn("memmove_tail", kinds)
        self.assertEqual(bytes.fromhex(out["buffer_after"]),
                         tail + m._pattern(20, 21))

    def test_tail_memmove_guard_quiet_in_natural_state(self):
        tail = m._pattern(10, 3)
        out = _run(_eof_param(tail, 100, m._pattern(20, 21)))
        kinds = [k for k, _ in out["events"]]
        self.assertNotIn("memmove_tail", kinds)

    def test_read_memmove_guard_fires_when_result_is_elsewhere(self):
        tail = m._pattern(10, 3)
        out = _run(_eof_param(
            tail, 100, b"",
            file_script=[{"bytes": m._pattern(20, 23).hex(),
                          "ok": True, "data_offset": 5000}]))
        self.assertTrue(out["ok"])
        kinds = [k for k, _ in out["events"]]
        self.assertIn("memmove_read", kinds)

    def test_refill_error_with_bytes_reports_added(self):
        out = _run(_eof_param(
            m._pattern(10, 3), 100, b"",
            file_script=[{"bytes": m._pattern(40, 25).hex(),
                          "ok": False, "state": 23}]))
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], m.K_BAD_HEADER)
        self.assertEqual(out["drop_size"], 10)
        self.assertEqual(out["report_drops"],
                         [{"bytes": 40, "status_code": 1,
                           "reported": True}])
        self.assertTrue(out["read_error_after"])
        # The partial refill bytes are NOT in buffer_.
        self.assertEqual(bytes.fromhex(out["buffer_after"]), b"")

    def test_refill_error_with_zero_bytes_reports_nothing(self):
        out = _run(_eof_param(
            m._pattern(10, 3), 100, b"",
            file_script=[{"bytes": "", "ok": False, "state": 21}]))
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], m.K_BAD_HEADER)
        self.assertEqual(out["report_drops"], [])
        self.assertEqual(out["freed_states"], [21])

    def test_foreign_noop_returns_true_with_eof_still_set(self):
        out = _run(_eof_param(m._pattern(10, 3), 100, m._pattern(20, 29),
                              vtable_unmark_eof="foreign",
                              foreign_script=[{"mode": "noop"}]))
        self.assertTrue(out["ok"])
        self.assertTrue(out["eof_after"])
        self.assertEqual(out["eof_offset_after"], 100)
        self.assertEqual(out["error"], None)

    def test_foreign_set_read_error_drains(self):
        out = _run(_eof_param(m._pattern(10, 3), 100, m._pattern(20, 29),
                              vtable_unmark_eof="foreign",
                              foreign_script=[{"mode": "set_read_error"}]))
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], m.K_BAD_HEADER)
        self.assertEqual(out["drop_size"], 10)

    def test_fragment_unmark_eof_early_return_on_read_error(self):
        reader = m.FragmentBufferedReader(read_error=True)
        events = []
        m.fragment_unmark_eof(reader, m.make_file_reader([]), events)
        self.assertEqual(events, [["unmark_eof_early_return", {}]])
        self.assertFalse(reader.eof)

    def test_fragment_unmark_eof_has_no_eof_offset_early_return(self):
        # Unlike Reader::UnmarkEOF, the fragment override refills
        # even when eof_offset_ == 0 (it calls UnmarkEOFInternal
        # unconditionally after clearing eof_).
        reader = m.FragmentBufferedReader(
            buffer=b"", buffer_offset=None, eof_offset=0, eof=True)
        events = []
        file_read = m.make_file_reader(
            [{"bytes": m._pattern(10, 3).hex(), "ok": True}])
        m.fragment_unmark_eof(reader, file_read, events)
        # The override clears eof_ and refills even with
        # eof_offset_ == 0; the short refill then re-sets eof_
        # with eof_offset_ += added.
        self.assertTrue(reader.eof)
        self.assertEqual(reader.eof_offset, 10)
        self.assertEqual(reader.buffer, m._pattern(10, 3))


class DrainTests(unittest.TestCase):
    def test_empty_drain_writes_drop_size_zero(self):
        # The TryReadMore drain writes *drop_size unconditionally
        # (even 0) -- unlike Reader::ReadMore's drain.
        out = _run(_read_param(b"", eof=True, read_error=True))
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], m.K_EOF)
        self.assertEqual(out["drop_size"], 0)
        self.assertEqual(out["buffer_after"], "")

    def test_nonempty_drain_reports_bad_header(self):
        out = _run(_read_param(b"", buffer=m._pattern(100, 31).hex(),
                               buffer_offset=0, eof=True,
                               read_error=True, drop_size_in=5,
                               error_in=3))
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], m.K_BAD_HEADER)
        self.assertEqual(out["drop_size"], 100)
        self.assertEqual(out["buffer_after"], "")

    def test_drain_without_eof_but_with_read_error(self):
        out = _run(_read_param(b"", buffer=m._pattern(7, 31).hex(),
                               buffer_offset=0, eof=False,
                               read_error=True))
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], m.K_BAD_HEADER)
        self.assertEqual(out["drop_size"], 7)

    def test_drain_never_reads_or_reports(self):
        out = _run(_read_param(b"", buffer=m._pattern(9, 39).hex(),
                               buffer_offset=0, eof=True,
                               read_error=True, reporter=False))
        kinds = [k for k, _ in out["events"]]
        self.assertEqual(kinds, ["drain"])
        self.assertEqual(out["report_drops"], [])


class BindingsTests(unittest.TestCase):
    def test_body_hashes_match_census(self):
        rows = _read_cases()
        by_id = {r["id"]: r for r in rows}
        body = json.loads(by_id["bind-hash-body-try_read_more"]
                          ["expected"])
        self.assertEqual(
            body["sha256"],
            "ffed6babe23f74644c61ef2493500b66ed42afb9fe7e53292b436e55f9d6890b")
        src = json.loads(by_id["bind-hash-source-try_read_more"]
                         ["expected"])
        self.assertEqual(
            src["sha256"],
            "c324b7c3fde6aea1c2e07a7283b02aa99e3a2df2546390addcefcce3f955bc6e")
        internal = json.loads(by_id["bind-hash-body-unmark_eof_internal"]
                              ["expected"])
        self.assertEqual(
            internal["sha256"],
            "98b700cf3d8a6f09bfd130d3bb423c29262db4f70c9b2a255c8869a6a4f4f84e")
        internal_src = json.loads(
            by_id["bind-hash-source-unmark_eof_internal"]["expected"])
        self.assertEqual(
            internal_src["sha256"],
            "47c766956c93a5451202321c7a533d0a65c45c73ad1fc24efefda765072ad9ec")
        unmark = json.loads(by_id["bind-hash-body-unmark_eof_fragment"]
                            ["expected"])
        self.assertEqual(
            unmark["sha256"],
            "8a1ca59cb21900b38395c79e57a23d76a7a4fc9e19ae309f8523d8ae3069e14b")

    def test_no_unknown_reloc_targets(self):
        rows = _read_cases()
        for r in rows:
            if r["scenario"] == "reloc_target":
                exp = json.loads(r["expected"])
                self.assertNotEqual(exp["name"], "UNKNOWN", r["id"])

    def test_caller_sites_are_the_three_tryreadfragment_loops(self):
        rows = _read_cases()
        sites = sorted(
            json.loads(r["expected"])["site"] for r in rows
            if r["scenario"] == "caller_site")
        self.assertEqual(sites, ["0x5f02bab", "0x5f02c57", "0x5f02cb6"])


class LiveEngineTests(unittest.TestCase):
    def test_live_engine_check(self):
        self.assertEqual(m.live_engine_check(), (True, True, True))


if __name__ == "__main__":
    unittest.main()
