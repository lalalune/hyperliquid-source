"""Tests for the node #115 ingest-behind admission gate model.

Runnable under plain python3 (pytest is not installed on this VM):
    python3 tests/test_ingest_behind_check_115.py
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import ingest_behind_check_115 as subject

PACKET = (
    Path(__file__).resolve().parents[1]
    / "research" / "work-items" / "RE-001-ingest-behind-check-115"
)


def make_third():
    return {"f20": 0x1000, "f28": 0x2008, "f40": 0x3000, "f48": 0x4008,
            "f390": None}


def make_source(count, records):
    link = {"selector": "selector-object", "array": records}
    return {"struct40": {"count": count, "link": link}}


def recording_selector(result, seen):
    def selector(selector_obj, index, rec1, rec2):
        seen.append((selector_obj, index, rec1, rec2))
        return result
    return selector


class GateTests(unittest.TestCase):
    def test_wrapper_zero_reports_bottom_message(self):
        seen = []
        status = {}
        out = subject.check_ingest_behind(
            make_source(3, [[5], [7]]), make_third(),
            recording_selector(1, seen), status)
        self.assertEqual(out["code"], 4)
        self.assertEqual(out["message"], subject.BOTTOM_MSG)
        self.assertEqual(len(subject.BOTTOM_MSG), 0x43)
        # Wrapper result is selector ^ 1, so selector 1 means wrapper 0.
        self.assertEqual(seen[0][1], 2)
        self.assertEqual(seen[0][2], (0x1000, 0x2000))
        self.assertEqual(seen[0][3], (0x3000, 0x4000))

    def test_count_one_fast_path_never_calls_selector(self):
        seen = []
        third = make_third()
        status = {"code": 9, "message": "stale"}
        out = subject.check_ingest_behind(
            make_source(1, []), third,
            recording_selector(0, seen), status)
        self.assertEqual(seen, [])
        self.assertEqual(third["f390"], 0)
        self.assertEqual(out["code"], 0)
        self.assertIsNone(out["message"])

    def test_count_zero_passes_index_minus_one_to_selector(self):
        seen = []
        third = make_third()
        out = subject.check_ingest_behind(
            make_source(0, []), third,
            recording_selector(0, seen), {})
        self.assertEqual(seen[0][1], -1)
        self.assertEqual(third["f390"], -1)
        self.assertEqual(out["code"], 0)

    def test_zero_field_in_first_record_reports_upper_message(self):
        third = make_third()
        out = subject.check_ingest_behind(
            make_source(3, [[5, 0], [7]]), third,
            recording_selector(0, []), {})
        self.assertEqual(out["code"], 4)
        self.assertEqual(out["message"], subject.UPPER_MSG)
        self.assertEqual(len(subject.UPPER_MSG), 0x76)
        self.assertIsNone(third["f390"])

    def test_zero_field_in_later_scanned_record_reports(self):
        third = make_third()
        out = subject.check_ingest_behind(
            make_source(4, [[5], [7], [0]]), third,
            recording_selector(0, []), {})
        self.assertEqual(out["message"], subject.UPPER_MSG)
        self.assertIsNone(third["f390"])

    def test_clean_scan_sets_f390_and_zeroes_status(self):
        third = make_third()
        out = subject.check_ingest_behind(
            make_source(4, [[5], [7], [9]]), third,
            recording_selector(0, []), {})
        self.assertEqual(third["f390"], 3)
        self.assertEqual(out["code"], 0)
        self.assertIsNone(out["message"])

    def test_zero_field_only_in_last_record_is_not_scanned(self):
        # The gate scans array[0:count-1]; the last of the count
        # records is skipped, so a zero field there stays clean.
        third = make_third()
        out = subject.check_ingest_behind(
            make_source(3, [[5], [7], [0]]), third,
            recording_selector(0, []), {})
        self.assertEqual(third["f390"], 2)
        self.assertEqual(out["code"], 0)

    def test_empty_inner_ranges_are_skipped(self):
        third = make_third()
        out = subject.check_ingest_behind(
            make_source(3, [[], [5]]), third,
            recording_selector(0, []), {})
        self.assertEqual(third["f390"], 2)
        self.assertEqual(out["code"], 0)

    def test_guards(self):
        with self.assertRaises(ValueError):
            subject.check_ingest_behind(
                make_source(3, [[None], [5]]), make_third(),
                recording_selector(0, []), {})
        with self.assertRaises(ValueError):
            subject.check_ingest_behind(
                make_source(3, [[5]]), make_third(),
                recording_selector(0, []), {})
        with self.assertRaises(ValueError):
            subject.check_ingest_behind(
                make_source(1 << 31, []), make_third(),
                recording_selector(0, []), {})


class StatusBuilderTests(unittest.TestCase):
    def test_empty_second_slice_is_not_joined(self):
        out = subject.build_status({}, 4, 0, 0, "msg", "")
        self.assertEqual(out["message"], "msg")
        self.assertEqual(
            (out["code"], out["byte1"], out["byte2"],
             out["word3"], out["byte5"]),
            (4, 0, 0, 0, 0))

    def test_nonempty_second_slice_joins_with_colon_space(self):
        out = subject.build_status({}, 4, 0, 0, "first", "second")
        self.assertEqual(out["message"], "first: second")

    def test_previous_message_is_replaced(self):
        out = {"message": "stale", "code": 9}
        subject.build_status(out, 4, 0, 0, "fresh", "")
        self.assertEqual(out["message"], "fresh")
        self.assertEqual(out["code"], 4)


class PacketTests(unittest.TestCase):
    def test_records_are_semantic_only(self):
        record = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(record["task"], "RE-001")
        starts = [w["start"] for w in record["windows"]]
        self.assertEqual(starts, [0x5ebd1c0, 0x5ebd130, 0x61cf670])
        blob = json.dumps(record)
        self.assertNotIn("endbr64", blob)
        self.assertNotIn("movq", blob)

    def test_message_lengths_match_rodata(self):
        self.assertEqual(len(subject.BOTTOM_MSG), 0x43)
        self.assertEqual(len(subject.UPPER_MSG), 0x76)


if __name__ == "__main__":
    unittest.main()
