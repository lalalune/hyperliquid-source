import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import action_tag_tables_115 as t  # noqa: E402

IMAGE = None


def image():
    global IMAGE
    if IMAGE is None:
        IMAGE = t.Image()
    return IMAGE


class TableTests(unittest.TestCase):
    def test_tables_are_inside_functions(self):
        img = image()
        for spec in (t.SELECTOR, t.CLASSIFIER):
            rows = img.table(spec)
            self.assertEqual(len(rows), 92)
            self.assertTrue(all(spec[0] <= a < spec[1] for a in rows))

    def test_distinct_targets(self):
        img = image()
        self.assertEqual(len(set(img.table(t.SELECTOR))), 36)
        self.assertEqual(len(set(img.table(t.CLASSIFIER))), 7)

    def test_arm_tables_match_jump_tables(self):
        img = image()
        sel = img.table(t.SELECTOR)
        empty = {i for i, a in enumerate(sel) if a == 0x2bdb5f5}
        self.assertEqual(empty, set(range(92)) - set(t.SELECTOR_ARMS))
        cls = img.table(t.CLASSIFIER)
        false_arms = {i for i, a in enumerate(cls) if a == 0x36c3115}
        self.assertEqual(false_arms, set(range(92)) - set(t.CLASSIFIER_ARMS))

    def test_tag_index(self):
        self.assertEqual(t.tag_index(0x86), 0)
        self.assertEqual(t.tag_index(0x85), 0x14)
        self.assertEqual(t.tag_index(0), 0x14)
        self.assertEqual(t.tag_index(0xe1), 91)


class BehaviourTests(unittest.TestCase):
    def test_selector_matches_bytes(self):
        self.assertEqual(t.compare(image(), t.SELECTOR, 1500, 99), (1500, 0))

    def test_classifier_matches_bytes(self):
        self.assertEqual(t.compare(image(), t.CLASSIFIER, 1500, 99), (1500, 0))

    def test_every_arm_is_exercised(self):
        img = image()
        seen = set()
        for c in range(97 * 7):
            tags = t.case_tags(t.Rng(5 + 977 * c), c)
            seen.add(tags[0])
        self.assertTrue(set(range(0x86, 0x86 + 92)) <= seen)

    def test_empty_result_word(self):
        img = image()
        mem, addrs, obs = t.run_bytes(img, t.SELECTOR, [0x86], 3, 9)
        self.assertEqual(obs[0], ())
        self.assertEqual(obs[1][:2], (0x1a2).to_bytes(2, 'little'))
        self.assertEqual(obs[1][8:16], bytes(8))

    def test_default_index_for_low_tags(self):
        img = image()
        for tag in (0, 0x85):
            _, _, obs = t.run_bytes(img, t.CLASSIFIER, [tag], 3, 9)
            self.assertEqual(obs, (0, ()))


class NegativeTests(unittest.TestCase):
    def test_wrong_arm_detected(self):
        arms = t.with_arm(t.SELECTOR_ARMS, 2, (t.SEL_FWD, 0x2cf0450))
        _, bad = t.compare(image(), t.SELECTOR, 300, 1, arms)
        self.assertGreater(bad, 0)

    def test_byte_corruption_detected(self):
        img = image()
        img.patches[0x36c313e] = 0
        try:
            _, bad = t.compare(img, t.CLASSIFIER, 300, 1)
        finally:
            del img.patches[0x36c313e]
        self.assertGreater(bad, 0)

    def test_out_of_table_tag_refused(self):
        img = image()
        mem, addrs = t.fresh(img, t.Rng(1), [0xe2])
        with self.assertRaises(ValueError):
            t.model_selector(mem, addrs[0], 0)
        with self.assertRaises(ValueError):
            t.model_classifier(mem, addrs[0])

    def test_wrong_digest_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            bogus = Path(tmp) / 'x'
            bogus.write_bytes(b'not a node')
            with self.assertRaises(ValueError):
                t.Image(bogus)

    def test_unsupported_opcode_faults(self):
        img = image()
        img.patches[0x36c30f0] = 0xF4
        try:
            with self.assertRaises(t.Fault):
                t.run_bytes(img, t.CLASSIFIER, [0x86], 1, 1)
        finally:
            del img.patches[0x36c30f0]

    def test_all_controls_detected(self):
        rows = t.run_controls(image())
        self.assertGreaterEqual(len(rows), 30)
        self.assertTrue(all(r[2] for r in rows))


class EvidenceTests(unittest.TestCase):
    def test_regeneration_is_deterministic(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            t.generate(Path(a) / 'x', cases_per_function=200)
            t.generate(Path(b) / 'x', cases_per_function=200)
            for p in sorted((Path(a) / 'x').iterdir()):
                self.assertEqual(p.read_bytes(), (Path(b) / 'x' / p.name).read_bytes())
            measure = json.loads((Path(a) / 'x' / 'measure.json').read_text())
            self.assertEqual(measure['mismatches'], 0)
            self.assertEqual(measure['negative_controls'], measure['negative_detected'])


if __name__ == '__main__':
    unittest.main()
