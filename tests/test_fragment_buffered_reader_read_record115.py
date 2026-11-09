"""Tests for the node #115 log::FragmentBufferedReader::ReadRecord model.

Replays all 2,400 cases in cases.tsv through the tool's replay_case,
then checks the model's key behaviours directly: the jump-table
dispatch (all 16 codes, recyclable twins, the shared eof-group, the
checksum arm, the default arm for code 0/14/>15), the fragment
assembly (full, first/middle/last, recyclable, pre-seeded state),
the SetCompressionType arm (type 0/7 install, unsupported types,
short records, the flag set only by InitCompression, the low-byte
type check), the length-error guard, the layout (fragments_ +0xb8,
in_fragmented_record_ +0xd8, Reader base ends +0xb8), and the live
engine check (a real WAL file through the model).
"""

import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import fragment_buffered_reader_read_record115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-rocksdb-fragment-buffered-reader-read-record-115")


def _read_cases():
    rows = []
    with open(PACKET / "cases.tsv") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    return rows


def _run(script, **kw):
    p = {"buffer": b"".hex(), "end_of_buffer_offset": 100,
         "log_number": 7, "checksum": False, "uncompress": 0,
         "try_read_fragment_script": script}
    p.update(kw)
    return m._run_scenario(p)


def _full(payload=b"DATA"):
    return m._frag(payload, m.K_FULL_TYPE)


def _setcomp(u32, extra=b""):
    return m._frag(m._setcomp_fragment(u32, extra), m.K_SET_COMPRESSION_TYPE)


def _reports(exp):
    return [v for k, v in exp["events"] if k == "report_corruption"]


class ReplayTests(unittest.TestCase):
    def test_case_count(self):
        rows = _read_cases()
        self.assertEqual(len(rows), 2400)
        groups = {}
        for r in rows:
            groups[r["group"]] = groups.get(r["group"], 0) + 1
        self.assertEqual(groups, {"dispatch": 600, "assembly": 600,
                                  "compression": 600, "bindings": 600})

    def test_all_cases_replay(self):
        bad = []
        for r in _read_cases():
            ok, detail = m.replay_case(r)
            if not ok:
                bad.append((r["id"], detail))
        self.assertEqual(bad, [], f"{len(bad)} cases failed: {bad[:5]}")


class DispatchTests(unittest.TestCase):
    def test_all_16_codes_dispatch(self):
        for code in range(16):
            frag = (m._setcomp_fragment(0) if code == 9 else b"DATA")
            exp = _run([m._frag(frag, code), _full(b"FULL")])
            handler = m.JUMP_TARGETS[code]
            disp = [v for k, v in exp["events"] if k == "dispatch"][0]
            self.assertEqual(disp["handler"], hex(handler),
                             f"code {code}")

    def test_codes_above_15_go_to_default(self):
        for code in (16, 17, 100, 255):
            exp = _run([m._frag(b"DATA", code), _full(b"FULL")])
            self.assertEqual(exp["ok"], True)
            self.assertEqual(exp["record"], b"FULL".hex())
            self.assertEqual(_reports(exp)[0]["reason"],
                             f"unknown record type {code}")

    def test_bad_record_len_goes_to_default(self):
        # Code 14 has no dedicated arm: it is the default handler.
        exp = _run([m._frag(b"DATA", m.K_BAD_RECORD_LEN), _full(b"FULL")])
        self.assertEqual(_reports(exp)[0]["reason"],
                         "unknown record type 14")
        self.assertEqual(exp["ok"], True)

    def test_full_with_empty_fragments_reports_nothing(self):
        # kFullType reports only when in_fragmented AND fragments_
        # non-empty (binary 0x5f03340: test size; je skips).
        exp = _run([_full(b"X")], in_fragmented_record=True,
                   fragments=b"")
        self.assertEqual(exp["ok"], True)
        self.assertEqual(_reports(exp), [])

    def test_full_with_partial_reports(self):
        exp = _run([_full(b"X")], in_fragmented_record=True,
                   fragments=b"SEED")
        self.assertEqual(_reports(exp)[0]["reason"],
                         "partial record without end(1)")
        self.assertEqual(_reports(exp)[0]["bytes"], 4)

    def test_checksum_recycled_returns_false_keeps_flag(self):
        # Recycled checksum failure: fragments_ cleared, return false,
        # in_fragmented_record_ NOT cleared (binary 0x5f03419).
        exp = _run([m._frag(b"X", m.K_BAD_RECORD_CHECKSUM, drop_size=9,
                            recycled=True)],
                   in_fragmented_record=True, fragments=b"SEED")
        self.assertEqual(exp["ok"], False)
        self.assertEqual(exp["fragments_after"], "")
        self.assertEqual(exp["in_fragmented_record_after"], True)
        self.assertEqual(_reports(exp), [])

    def test_checksum_not_recycled_reports_and_loops(self):
        exp = _run([m._frag(b"X", m.K_BAD_RECORD_CHECKSUM, drop_size=9),
                    _full(b"FULL")])
        self.assertEqual(exp["ok"], True)
        self.assertEqual(_reports(exp)[0]["reason"], "checksum mismatch")
        self.assertEqual(_reports(exp)[0]["bytes"], 9)

    def test_eof_group_loops_without_report(self):
        for code in (m.K_EOF, m.K_BAD_RECORD, m.K_BAD_HEADER,
                     m.K_OLD_RECORD):
            exp = _run([m._frag(b"X", code), _full(b"FULL")])
            self.assertEqual(exp["ok"], True)
            self.assertEqual(_reports(exp), [], f"code {code}")

    def test_eof_group_mid_record_reports(self):
        exp = _run([m._frag(b"aa", m.K_FIRST_TYPE),
                    m._frag(b"bb", m.K_EOF), _full(b"FULL")],
                   )
        self.assertEqual(_reports(exp)[0]["reason"],
                         "error in middle of record")
        self.assertEqual(exp["fragments_after"], "")

    def test_try_read_fragment_false_returns_at_once(self):
        # A false return ends the call immediately: no report, the
        # partial fragments_ stays in place.
        exp = _run([m._frag(b"aa", m.K_FIRST_TYPE),
                    m._fail(type=m.K_EOF)],
                   in_fragmented_record=False)
        self.assertEqual(exp["ok"], False)
        self.assertEqual(_reports(exp), [])
        self.assertEqual(exp["fragments_after"], b"aa".hex())
        self.assertEqual(exp["in_fragmented_record_after"], True)

    def test_no_progress_leaves_frag_type_untouched(self):
        exp = _run([m._frag(b"aa", m.K_FIRST_TYPE),
                    m._fail(type_untouched=True)])
        self.assertEqual(exp["ok"], False)
        trf = [v for k, v in exp["events"] if k == "try_read_fragment"]
        self.assertEqual(trf[1]["frag_type"], m.K_FIRST_TYPE)

    def test_recovery_mode_and_checksum_params_ignored(self):
        # The model takes no recovery-mode/checksum params at all:
        # the binary leaves rcx/r8 unreferenced, and upstream marks
        # them /*unused*/ / /* checksum */.
        exp = _run([_full(b"X")])
        self.assertEqual(exp["ok"], True)


class AssemblyTests(unittest.TestCase):
    def test_full_record(self):
        exp = _run([_full(b"hello")])
        self.assertEqual(exp["record"], b"hello".hex())
        self.assertEqual(exp["record_from_scratch"], False)
        self.assertEqual(exp["last_record_offset_after"], 100)
        self.assertEqual(exp["first_record_read_after"], True)

    def test_fragmented_record(self):
        exp = _run([m._frag(b"aa", m.K_FIRST_TYPE),
                    m._frag(b"bb", m.K_MIDDLE_TYPE),
                    m._frag(b"cc", m.K_LAST_TYPE)])
        self.assertEqual(exp["record"], b"aabbcc".hex())
        self.assertEqual(exp["record_from_scratch"], True)
        self.assertEqual(exp["scratch"], b"aabbcc".hex())
        self.assertEqual(exp["fragments_after"], "")

    def test_recyclable_fragmented_record(self):
        exp = _run([m._frag(b"aa", m.K_REC_FIRST_TYPE),
                    m._frag(b"bb", m.K_REC_MIDDLE_TYPE),
                    m._frag(b"cc", m.K_REC_LAST_TYPE)])
        self.assertEqual(exp["record"], b"aabbcc".hex())

    def test_middle_without_first_reports_and_loops(self):
        exp = _run([m._frag(b"bb", m.K_MIDDLE_TYPE), _full(b"FULL")])
        self.assertEqual(_reports(exp)[0]["reason"],
                         "missing start of fragmented record(1)")
        self.assertEqual(exp["record"], b"FULL".hex())

    def test_last_without_first_reports_and_loops(self):
        exp = _run([m._frag(b"bb", m.K_LAST_TYPE), _full(b"FULL")])
        self.assertEqual(_reports(exp)[0]["reason"],
                         "missing start of fragmented record(2)")

    def test_first_then_first_reports_partial(self):
        exp = _run([m._frag(b"aa", m.K_FIRST_TYPE),
                    m._frag(b"bb", m.K_FIRST_TYPE),
                    m._frag(b"cc", m.K_LAST_TYPE)])
        self.assertEqual(_reports(exp)[0]["reason"],
                         "partial record without end(2)")
        self.assertEqual(exp["record"], b"bbcc".hex())

    def test_preseeded_fragmented_record_completes(self):
        exp = _run([m._frag(b"tail", m.K_LAST_TYPE)],
                   in_fragmented_record=True, fragments=b"head-")
        self.assertEqual(exp["record"], b"head-tail".hex())
        self.assertEqual(exp["record_from_scratch"], True)

    def test_set_compression_mid_record_clears_fragments(self):
        exp = _run([m._frag(b"aa", m.K_FIRST_TYPE),
                    _setcomp(0),
                    m._frag(b"bb", m.K_LAST_TYPE),
                    _full(b"FULL")])
        # The SetCompressionType arm clears fragments_ and clears
        # in_fragmented_record_, so the last fragment has no start.
        self.assertEqual(_reports(exp)[0]["reason"],
                         "missing start of fragmented record(2)")
        self.assertEqual(exp["record"], b"FULL".hex())

    def test_last_record_offset_is_entry_time(self):
        # physical_record_offset is computed once, at entry: a
        # SetCompressionType record first does not move it.
        exp = _run([_setcomp(0), _full(b"X")],
                   end_of_buffer_offset=500)
        self.assertEqual(exp["last_record_offset_after"], 500)


class CompressionTests(unittest.TestCase):
    def test_type_zero_installs_null(self):
        exp = _run([_setcomp(0), _full(b"FULL")])
        self.assertEqual(exp["compression_type_record_read_after"], True)
        self.assertEqual(exp["compression_type_after"], 0)
        self.assertEqual(exp["uncompress_after"], 0)
        self.assertEqual(_reports(exp), [])

    def test_type_seven_installs_uncompress(self):
        exp = _run([_setcomp(7), _full(b"FULL")])
        self.assertEqual(exp["compression_type_after"], 7)
        self.assertNotEqual(exp["uncompress_after"], 0)

    def test_unsupported_types_report_and_loop(self):
        for u32 in (1, 2, 3, 4, 5, 6, 8, 9, 10, 15, 0x40, 0xFF):
            exp = _run([_setcomp(u32), _full(b"FULL")])
            self.assertEqual(_reports(exp)[0]["reason"],
                             "could not decode SetCompressionType record",
                             f"u32 {u32:#x}")
            # The flag is set only by InitCompression, so a failed
            # record leaves it clear.
            self.assertEqual(exp["compression_type_record_read_after"],
                             False, f"u32 {u32:#x}")
            self.assertEqual(exp["ok"], True)

    def test_low_byte_only_check(self):
        # CompressionType is `enum : unsigned char`: the u32 is
        # truncated to its low byte before the 0/7 gate.
        exp = _run([_setcomp(0x100), _full(b"FULL")])
        self.assertEqual(exp["compression_type_after"], 0)
        exp = _run([_setcomp(0x107), _full(b"FULL")])
        self.assertEqual(exp["compression_type_after"], 7)
        exp = _run([_setcomp(0xFFFFFF07), _full(b"FULL")])
        self.assertEqual(exp["compression_type_after"], 7)

    def test_short_fragments_decode_error(self):
        for size in (0, 1, 2, 3):
            exp = _run([m._frag(bytes(range(size)),
                                m.K_SET_COMPRESSION_TYPE),
                        _full(b"FULL")])
            self.assertEqual(_reports(exp)[0]["reason"],
                             "could not decode SetCompressionType record")
            self.assertEqual(_reports(exp)[0]["bytes"], size)

    def test_extra_bytes_after_type_ignored(self):
        exp = _run([_setcomp(0, b"EXTRA"), _full(b"FULL")])
        self.assertEqual(exp["compression_type_after"], 0)
        exp = _run([_setcomp(7, b"EXTRA"), _full(b"FULL")])
        self.assertEqual(exp["compression_type_after"], 7)

    def test_multiple_records_report_but_still_process(self):
        exp = _run([_setcomp(0), _setcomp(7), _full(b"FULL")])
        self.assertEqual(_reports(exp)[0]["reason"],
                         "read multiple SetCompressionType records")
        # The second record still runs InitCompression.
        self.assertEqual(exp["compression_type_after"], 7)
        self.assertNotEqual(exp["uncompress_after"], 0)

    def test_error_then_valid_has_no_multiple_report(self):
        # A failed first record does not mark the flag.
        exp = _run([_setcomp(1), _setcomp(7), _full(b"FULL")])
        reasons = [v["reason"] for v in _reports(exp)]
        self.assertNotIn("read multiple SetCompressionType records",
                         reasons)
        self.assertEqual(exp["compression_type_after"], 7)

    def test_not_first_record_reports_but_still_processes(self):
        # first_record_read_ is set by an EARLIER ReadRecord call, so
        # it is preset in the reader state here (a kFullType in the
        # same call would return before the SetCompressionType record
        # is ever read).
        exp = _run([_setcomp(7), _full(b"FULL")], first_record_read=True)
        self.assertEqual(_reports(exp)[0]["reason"],
                         "SetCompressionType not the first record")
        self.assertEqual(exp["compression_type_after"], 7)

    def test_unsupported_report_uses_stripped_size(self):
        # DecodeFrom strips the 4-byte type before the support check,
        # so the report counts the fragment AFTER the strip.
        exp = _run([_setcomp(1, b"EXTRA"), _full(b"FULL")])
        self.assertEqual(_reports(exp)[0]["bytes"], 5)


class LengthCheckTests(unittest.TestCase):
    def test_append_guard_boundary(self):
        m._check_append_capacity(0, m.K_MAX_STRING)
        m._check_append_capacity(10, m.K_MAX_STRING - 10)
        with self.assertRaises(m.LengthError_):
            m._check_append_capacity(0, m.K_MAX_STRING + 1)
        with self.assertRaises(m.LengthError_):
            m._check_append_capacity(10, m.K_MAX_STRING - 9)


class LayoutTests(unittest.TestCase):
    def test_fragments_layout(self):
        layout = {n: (o, s) for n, o, s in m.FRAGMENT_LAYOUT}
        self.assertEqual(layout["fragments_"], (0xB8, 32))
        self.assertEqual(layout["in_fragmented_record_"], (0xD8, 1))
        self.assertEqual(layout["last_record_offset_"], (0x58, 8))
        self.assertEqual(layout["end_of_buffer_offset_"], (0x60, 8))
        self.assertEqual(layout["recycled_"], (0x70, 1))
        self.assertEqual(layout["first_record_read_"], (0x71, 1))
        self.assertEqual(layout["compression_type_record_read_"],
                         (0x73, 1))
        self.assertEqual(layout["uncompress_"], (0x78, 8))

    def test_reader_base_ends_at_0xb8(self):
        # No recorded_cf_to_ts_sz_ in this v8.1.1-based build: the
        # Reader base ends at +0xb8 and fragments_ follows.
        layout = {n: (o, s) for n, o, s in m.FRAGMENT_LAYOUT}
        self.assertEqual(layout["uncompress_hash_state_"], (0xB0, 8))
        self.assertNotIn("recorded_cf_to_ts_sz_", layout)


class LiveCheckTests(unittest.TestCase):
    def test_live_engine_check(self):
        self.assertEqual(m.live_engine_check(),
                         (True, True, True, True, True, True))


if __name__ == "__main__":
    unittest.main()
