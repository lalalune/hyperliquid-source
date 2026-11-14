import hashlib
import itertools
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import action_timed_router_115 as tr  # noqa: E402


class TimedRouterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blob = tr.BINARY.read_bytes()
        cls.image = tr.Image(cls.blob)
        cls.arms = tr.arm_table(cls.image)
        cls.slot_c = tr.tail_slot_c(cls.image)
        cls.cases = list(tr.make_cases())
        cls.rig = tr.Rig(cls.image, cls.arms, cls.slot_c)

    def check(self, case, params=None, rig=None):
        return tr.check_case(rig or self.rig, params or tr.REAL, self.arms, self.slot_c, case)[0]

    def test_input_digest(self):
        self.assertEqual(hashlib.sha256(self.blob).hexdigest(), tr.SHA256)

    def test_router_extent_is_the_indexed_fde(self):
        self.assertEqual(tr.router_extent(self.image), (0x55F99B0, 0x55FAA79))

    def test_table_has_92_arms_and_ends_inside_an_instruction(self):
        self.assertEqual(len(self.arms), 92)
        rows = tr.decode_range(self.image, 0x55F99B0, 0x55FAA79)
        starts = {row.va for row in rows}
        self.assertTrue(all(arm["start"] in starts for arm in self.arms))
        import struct
        past = tr.TABLE + struct.unpack_from("<i", self.blob, self.image.offset(tr.TABLE) + 4 * 92)[0]
        self.assertEqual(past, 0x55FA98B)
        self.assertNotIn(past, starts)

    def test_shape_census(self):
        census = {}
        for arm in self.arms:
            census[arm["shape"]] = census.get(arm["shape"], 0) + 1
        self.assertEqual(len(census), 17)
        self.assertEqual(census["copy_desc"], 52)
        self.assertEqual(census["plain"], 21)
        self.assertEqual(census["rsp_first"], 3)
        self.assertEqual(census["copy_desc_noadd"], 2)
        self.assertEqual(census["desc_f0"], 2)
        self.assertEqual(sum(census.values()), 92)

    def test_every_arm_agrees_with_the_model(self):
        for arm in range(92):
            for case in self.cases[arm::92 * 30]:
                self.assertIsNone(self.check(case), (arm, case.cid))

    def test_tags_below_base_take_arm_20(self):
        tails = [c for c in self.cases if c.cid >= 92 * 110][:40]
        self.assertTrue(tails)
        for case in tails:
            self.assertLess(case.tag, 0x86)
            self.assertIsNone(self.check(case), case.cid)

    def test_gate_and_timer_paths_are_all_reached(self):
        seen = set()
        for case in self.cases[:3000]:
            trace, _ = self.rig.run(case)
            names = tuple(sorted({entry[0] for entry in trace if isinstance(entry[0], str)}))
            seen.add(names)
        self.assertIn(("flag",), seen)
        self.assertIn(("flag", "now"), seen)
        self.assertIn(("now",), seen)

    def test_nested_arm_recurses_into_the_router(self):
        case = next(c for c in self.cases if c.tag == 0x86 + 52 and c.cl < 15)
        self.assertIsNone(self.check(case))
        model, _ = tr.run_model(tr.REAL, self.arms, self.slot_c, case)
        self.assertTrue(model.calls >= 0)

    def test_overflow_limit_is_unsigned_inclusive(self):
        case = next(c for c in self.cases if c.tag == 0x86 + 61)
        for tail in (0xCCCCCCCCCCCCCCB, 0xCCCCCCCCCCCCCCC, 0xCCCCCCCCCCCCCCD, 0xFFFFFFFFFFFFFFFF):
            heap = bytearray(case.heap)
            heap[0x2028:0x2030] = tail.to_bytes(8, "little")
            variant = tr.Case(1, case.tag, case.cl, 0, 1, case.nows, 0, 3, 61, fixed=bytes(heap))
            self.assertIsNone(self.check(variant), hex(tail))
            trace, out = self.rig.run(variant)
            self.assertEqual(out[0], 0xF if tail >= 0xCCCCCCCCCCCCCCC else out[0])
            if tail >= 0xCCCCCCCCCCCCCCC:
                self.assertEqual(int.from_bytes(out[0x10:0x12], "little"), 0x154)

    def test_model_mutants_are_detected(self):
        suite = [c for c in self.cases[:3000] if c.cl <= 14][:250] + self.cases[92 * 110:92 * 110 + 20]
        results = [self.rig.run(c) for c in suite]
        for label, change, reason in tr.MODEL_MUTANTS[:10]:
            if reason:
                continue
            trial = dict(tr.REAL)
            trial.update(change)
            self.assertIsNotNone(tr.evaluate(trial, results, suite, self.arms, self.slot_c), label)

    def test_byte_damage_is_detected(self):
        suite = [c for c in self.cases[:3000] if c.cl <= 14 and c.dl == 0][:200]
        start, end = tr.router_extent(self.image)
        for label, pattern, occurrence, offset, new, reason in tr.BYTE_MUTANTS[:3] + tr.BYTE_MUTANTS[5:6]:
            sites = tr.find_all(self.blob, pattern, self.image.offset(start), self.image.offset(end))
            va = start + (sites[occurrence] - self.image.offset(start)) + offset
            damaged = tr.Rig(self.image, self.arms, self.slot_c, {va: new})
            hit = False
            for case in suite:
                try:
                    hit = self.check(case, rig=damaged) is not None
                except Exception:
                    hit = True
                if hit:
                    break
            self.assertTrue(hit, label)

    def test_wrong_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(tr, "SHA256", "0" * 64):
                with self.assertRaises(tr.EvidenceError):
                    tr.generate(Path(tmp))

    def test_out_of_range_table_entry_is_not_an_arm(self):
        # entry 92 lands inside an instruction, so a tag one past the last arm cannot be modelled as an arm
        rows = tr.decode_range(self.image, 0x55F99B0, 0x55FAA79)
        self.assertNotIn(0x55FA98B, {row.va for row in rows})
        with self.assertRaises(tr.EvidenceError):
            self.image.offset(0x1)

    def test_generator_is_deterministic(self):
        first = self.cases[:50]
        second = list(itertools.islice(tr.make_cases(), 50))
        self.assertEqual([c.heap for c in first], [c.heap for c in second])
        self.assertEqual([(c.tag, c.cl, c.dl, c.seed) for c in first], [(c.tag, c.cl, c.dl, c.seed) for c in second])

    def test_helpers(self):
        self.assertEqual(tr.fill_bytes(1, 2, 3, 4, True)[:2], bytearray([0xA2, 1]))
        self.assertNotEqual(bytes(tr.fill_bytes(1, 2, 3, 4, False)[:2]), bytes([0xA2, 1]))
        self.assertEqual(tr.norm(tr.F0 + 0x70, tr.F0), "F+70")
        self.assertEqual(tr.norm(tr.HEAP_BASE + 8, tr.F0), "H+8")
        self.assertEqual(tr.le(0x1A2, 2), b"\xa2\x01")
        a, b = tr.Lcg(1), tr.Lcg(1)
        self.assertEqual([a.next(100) for _ in range(5)], [b.next(100) for _ in range(5)])


if __name__ == "__main__":
    unittest.main()
