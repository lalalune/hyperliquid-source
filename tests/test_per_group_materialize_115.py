"""Tests for the node #115 per-group materialize step model.

Runnable under plain python3 (pytest is not installed on this VM):
    python3 tests/test_per_group_materialize_115.py
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import per_group_materialize_115 as subject

PACKET = (
    Path(__file__).resolve().parents[1]
    / "research" / "work-items" / "RE-001-per-group-materialize-115"
)


class RecordingAllocator:
    """Allocator oracle returning a fresh token per call."""

    def __init__(self):
        self.calls = []
        self.count = 0

    def __call__(self, size, rdx, rcx):
        self.calls.append((size, rdx, rcx))
        token = "buf%d" % self.count
        self.count += 1
        return token


def make_element(f00=0x11, seg1=b"AB", seg2=b"CDE"):
    return {"f00": f00, "f08": 0x22, "f10": 0x33, "f18": 0x44,
            "f20": 0x55, "seg1": seg1, "seg2": seg2}


def run(group, allocator=None):
    allocator = allocator or RecordingAllocator()
    out = {}
    result = subject.materialize(out, group, allocator)
    return allocator, out, result


class FactoryTests(unittest.TestCase):
    def test_factory_leaf_form(self):
        self.assertEqual(subject.factory_value(0, 0), 0)
        self.assertEqual(subject.factory_value(0xFF, 0), 0xFF)
        self.assertEqual(subject.factory_value(0, 1), 1 << 62)
        self.assertEqual(subject.factory_value(0x123, 3),
                         0x123 | (3 << 62))
        self.assertEqual(subject.factory_value(0, 4), 0)

    def test_init_pattern(self):
        pattern = subject.init_pattern()
        self.assertEqual(pattern[0x00], 0)
        self.assertEqual(pattern[0x08], 0)
        self.assertEqual(pattern[0x10], 0)
        self.assertEqual(pattern[0x18], 0x00FFFFFFFFFFFFFF)
        self.assertEqual(pattern[0x20], 0)
        self.assertEqual(pattern[0x28], 0)
        self.assertEqual(pattern[0x30], 0x4376FD)
        self.assertEqual(pattern[0x38], 0)
        self.assertEqual(pattern[0x40], 0x4376FD)
        self.assertEqual(pattern[0x48], 0)
        self.assertEqual(len(pattern), 10)


class MaterializeTests(unittest.TestCase):
    def test_empty_span(self):
        allocator, out, result = run({"byte_span": 0, "elements": []})
        self.assertEqual(out, {"count": 0, "buffer": "buf0"})
        self.assertEqual(result["slots"], [])
        self.assertEqual(result["init_slots"], [])
        self.assertEqual(allocator.calls, [(0, 0, 0)])

    def test_two_elements_end_to_end(self):
        elements = [make_element(0x11), make_element(0x99, b"W", b"XYZ")]
        allocator, out, result = run(
            {"byte_span": 16, "elements": elements})
        self.assertEqual(out["count"], 2)
        self.assertEqual(out["buffer"], "buf0")
        self.assertEqual(len(result["init_slots"]), 2)
        self.assertEqual(result["calls"]["factory"], 2)
        self.assertEqual(len(result["slots"]), 2)
        slot0 = result["slots"][0]
        self.assertEqual(slot0[0x00], 0x11)
        self.assertEqual(slot0[0x08], 0x22)
        self.assertEqual(slot0[0x10], 0x33)
        self.assertEqual(slot0[0x18], 0x44)
        self.assertEqual(slot0[0x20], 0x55)
        self.assertEqual(slot0[0x28], ("element", 0))
        self.assertEqual(slot0[0x30], ("buffer", "buf1"))
        self.assertEqual(slot0[0x38], 2)
        self.assertEqual(slot0[0x40], ("buffer_offset", "buf1", 2))
        self.assertEqual(slot0[0x48], 3)
        self.assertEqual(result["concats"][0], b"ABCDE")
        slot1 = result["slots"][1]
        self.assertEqual(slot1[0x00], 0x99)
        self.assertEqual(slot1[0x38], 1)
        self.assertEqual(slot1[0x48], 3)
        self.assertEqual(result["concats"][1], b"WXYZ")
        # Allocator call order: bulk buffer, then one concat per
        # element; the second fill call carries the previous element
        # pointer as its trailing argument, the first carries 0.
        self.assertEqual(allocator.calls, [
            (160, 0, 0),
            (5, 0, 0),
            (4, ("element", 0), 0),
        ])

    def test_partial_span_materializes_one_element(self):
        allocator, out, result = run(
            {"byte_span": 5, "elements": [make_element()]})
        self.assertEqual(out["count"], 0)
        self.assertEqual(result["init_slots"], [])
        self.assertEqual(len(result["slots"]), 1)
        self.assertEqual(result["slots"][0][0x38], 2)
        self.assertEqual(allocator.calls, [(0, 0, 0), (5, 0, 0)])

    def test_partial_span_missing_element_is_guarded(self):
        with self.assertRaises(ValueError):
            run({"byte_span": 5, "elements": []})

    def test_negative_span_throws_after_allocator_call(self):
        allocator = RecordingAllocator()
        out = {}
        with self.assertRaises(subject.BadArrayNewLength):
            subject.materialize(
                out, {"byte_span": -8, "elements": []}, allocator)
        # The bulk allocator call happens before the native throw.
        self.assertEqual(len(allocator.calls), 1)
        self.assertEqual(out["count"], -1)

    def test_most_negative_span_throws(self):
        # Byte span -2**63 reads unsigned as 2**63, above the span
        # limit, so the length throw fires before any loop.
        allocator = RecordingAllocator()
        out = {}
        with self.assertRaises(subject.BadArrayNewLength):
            subject.materialize(
                out, {"byte_span": -(1 << 63), "elements": []},
                allocator)
        self.assertEqual(len(allocator.calls), 1)
        self.assertEqual(out["count"], -(1 << 60))

    def test_huge_span_throws(self):
        allocator = RecordingAllocator()
        with self.assertRaises(subject.BadArrayNewLength):
            subject.materialize(
                {}, {"byte_span": 0xcccccccccccccc9, "elements": []},
                allocator)
        self.assertEqual(len(allocator.calls), 1)

    def test_span_limit_constant(self):
        # The native check fires only strictly above the limit; the
        # huge-span test above covers the firing arm, and this pins
        # the constant itself (a span at the limit is not modeled
        # end to end because its count is astronomically large).
        self.assertEqual(subject.SPAN_LIMIT, 0xcccccccccccccc8)

    def test_empty_segments(self):
        _, _, result = run(
            {"byte_span": 8, "elements": [make_element(0x11, b"", b"")]})
        self.assertEqual(result["concats"][0], b"")
        self.assertEqual(result["slots"][0][0x38], 0)
        self.assertEqual(result["slots"][0][0x48], 0)

    def test_init_slots_are_overwritten(self):
        _, _, result = run(
            {"byte_span": 8, "elements": [make_element()]})
        self.assertEqual(result["init_slots"][0][0x30], 0x4376FD)
        self.assertEqual(result["slots"][0][0x30], ("buffer", "buf1"))
        self.assertNotEqual(result["slots"][0][0x30],
                            result["init_slots"][0][0x30])

    def test_packet_records(self):
        record = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(record["task"], "RE-001")
        self.assertEqual(record["windows"][0]["name"], "main")
        self.assertEqual(record["windows"][0]["size"], 455)
        self.assertEqual(record["windows"][1]["name"], "factory")
        self.assertEqual(record["windows"][1]["size"], 15)
        blob = json.dumps(record)
        self.assertNotIn("endbr64", blob)
        self.assertNotIn("movq", blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
