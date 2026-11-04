"""Tests for the node #115 lazy-materialize predicate (0x5f77190).

RE-001 work item. Runs under pytest or under plain python3 via the
__main__ runner below (pytest is not installed on this VM).
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import lazy_materialize_predicate_115 as subject

PACKET = (Path(__file__).resolve().parent.parent / "research"
          / "work-items" / "RE-001-lazy-materialize-predicate-115")


def elt(**over):
    base = {"flag": 0, "p78": 0, "p08": 0,
            "f80": None, "f88": None, "f90": None,
            "f98": None, "fa0": None}
    base.update(over)
    return base


def result(**over):
    base = {"f58": 11, "f68": 22, "f48": 33, "f40": 44, "f78": 55}
    base.update(over)
    return base


class PredicateTests(unittest.TestCase):
    def test_cached_flag_returns_zero_without_oracle_call(self):
        calls = []
        e = elt(flag=1)
        self.assertEqual(
            subject.lazy_materialize_predicate(
                {}, e, lambda o, x: calls.append(1) or (0, result())), 0)
        self.assertEqual(calls, [])
        self.assertEqual(e["flag"], 1)

    def test_nonzero_p78_returns_zero_without_oracle_call_and_flag_stays(self):
        calls = []
        e = elt(p78=7)
        self.assertEqual(
            subject.lazy_materialize_predicate(
                {}, e, lambda o, x: calls.append(1) or (0, result())), 0)
        self.assertEqual(calls, [])
        self.assertEqual(e["flag"], 0)

    def test_fresh_success_copies_all_five_fields_and_returns_one(self):
        e = elt()
        self.assertEqual(
            subject.lazy_materialize_predicate(
                {}, e, lambda o, x: (0, result())), 1)
        self.assertEqual(e["flag"], 1)
        self.assertEqual(
            (e["f80"], e["f88"], e["f98"], e["f90"], e["fa0"]),
            (11, 22, 33, 44, 55))

    def test_fresh_success_null_result_returns_zero_but_flag_set(self):
        e = elt()
        self.assertEqual(
            subject.lazy_materialize_predicate(
                {}, e, lambda o, x: (0, None)), 0)
        self.assertEqual(e["flag"], 1)
        self.assertIsNone(e["f80"])

    def test_error_status_returns_zero_records_report_and_sets_flag(self):
        errors = []
        e = elt(p08=0xFFFFFFFFFFFFFFFF)
        self.assertEqual(
            subject.lazy_materialize_predicate(
                {"error_target": "tgt"}, e,
                lambda o, x: (9, result()), error_calls=errors), 0)
        self.assertEqual(e["flag"], 1)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["code"], 3)
        self.assertEqual(errors[0]["target"], "tgt")
        self.assertEqual(errors[0]["masked_p08"], 0x3FFFFFFFFFFFFFFF)
        self.assertEqual(errors[0]["status"], 9)

    def test_second_call_after_success_is_cached(self):
        calls = []
        e = elt()
        oracle = lambda o, x: calls.append(1) or (0, result())
        self.assertEqual(subject.lazy_materialize_predicate({}, e, oracle), 1)
        self.assertEqual(subject.lazy_materialize_predicate({}, e, oracle), 0)
        self.assertEqual(len(calls), 1)

    def test_second_call_after_error_is_cached(self):
        calls = []
        e = elt()
        oracle = lambda o, x: calls.append(1) or (4, None)
        self.assertEqual(subject.lazy_materialize_predicate({}, e, oracle), 0)
        self.assertEqual(subject.lazy_materialize_predicate({}, e, oracle), 0)
        self.assertEqual(len(calls), 1)

    def test_retry_after_p78_path_then_success(self):
        calls = []
        e = elt(p78=5)
        oracle = lambda o, x: calls.append(1) or (0, result())
        self.assertEqual(subject.lazy_materialize_predicate({}, e, oracle), 0)
        e["p78"] = 0
        self.assertEqual(subject.lazy_materialize_predicate({}, e, oracle), 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(e["f80"], 11)

    def test_masked_p08_keeps_low_62_bits_only(self):
        errors = []
        e = elt(p08=0xC000000000000005)
        subject.lazy_materialize_predicate(
            {}, e, lambda o, x: (1, None), error_calls=errors)
        self.assertEqual(errors[0]["masked_p08"], 5)

    def test_missing_field_is_guarded(self):
        e = elt()
        del e["p78"]
        with self.assertRaises(ValueError):
            subject.lazy_materialize_predicate({}, e, lambda o, x: (0, None))
        e = elt()
        with self.assertRaises(ValueError):
            subject.lazy_materialize_predicate(
                {}, e, lambda o, x: (0, {"f58": 1}))

    def test_packet_records(self):
        records = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(records["task"], "RE-001")
        self.assertEqual(records["windows"]["predicate"]["start"], "0x5f77190")
        self.assertEqual(records["windows"]["predicate"]["stop"], "0x5f77326")
        self.assertEqual(records["windows"]["predicate"]["size_bytes"], 406)
        self.assertEqual(records["census"]["predicate"]["direct_calls"],
                         ["0x5f773ae", "0x5f774ed"])
        self.assertEqual(records["census"]["predicate"]["tail_jumps"], [])
        self.assertEqual(records["census"]["predicate"]["stored_qwords"], 0)
        self.assertEqual(records["census"]["predicate"]["relative_addends"], 0)
        self.assertEqual(records["error_report"]["code"], 3)
        callers = (PACKET / "callers.tsv").read_text().splitlines()
        self.assertIn("predicate\t0x5f773ae\tcall", callers)
        self.assertIn("predicate\t0x5f774ed\tcall", callers)


if __name__ == "__main__":
    unittest.main()
