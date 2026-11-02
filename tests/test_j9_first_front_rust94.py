import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-006-j9-first-front-rust-94'
SPEC = importlib.util.spec_from_file_location('j9_front_fixture94', PACKET / 'verify_rust.py')
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)


class J9FrontFixtureTests(unittest.TestCase):
    def test_frozen_two_domains_and_wire(self):
        record, rows, stimulus, expected = V.frozen()
        self.assertEqual(len(stimulus), 1932)
        self.assertEqual([r['kind'] for r in rows], [0] * 5 + [1] * 5)
        self.assertEqual(V.compare(expected, rows), ([], []))
        self.assertFalse(record['rust_source_present'])

    def test_every_scratch_word_is_compared(self):
        _, rows, _, expected = V.frozen()
        for word in range(21):
            altered = bytearray(expected)
            altered[36 + word * 8] ^= 1
            values, _ = V.compare(altered, rows)
            self.assertEqual(len(values), 1)
            self.assertEqual(values[0]['changed_scratch_indices'], [word])

    def test_front_output_and_side_observation_are_separate(self):
        _, rows, _, expected = V.frozen()
        changed = bytearray(expected)
        changed[12 + 192 * 5 + 16] ^= 1
        values, observations = V.compare(changed, rows)
        self.assertEqual(len(values), 1)
        self.assertFalse(observations)
        changed = bytearray(expected)
        changed[12 + 192 * 7 + 12] ^= 1
        values, observations = V.compare(changed, rows)
        self.assertFalse(values)
        self.assertEqual(len(observations), 1)

    def test_malformed_frames_reject(self):
        _, rows, _, expected = V.frozen()
        for changed in (expected[:-1], expected + b'\0', b'WRONGHDR' + expected[8:]):
            with self.assertRaises(ValueError):
                V.compare(changed, rows)
        changed = bytearray(expected)
        changed[12] = 1
        with self.assertRaisesRegex(ValueError, 'ID/kind/order'):
            V.compare(changed, rows)

    def test_fixed_snapshot_and_fixture_artifacts(self):
        with tempfile.TemporaryDirectory() as name:
            out = Path(name) / 'prepared'
            record = V.run(out)
            self.assertIn('component/src/j9_first_front.rs', record['source_manifest'])
            self.assertIn('driver/input_only_driver.rs', record['source_manifest'])
            source = out / 'source-snapshot/component/src/j9_first_front.rs'
            source.write_bytes(source.read_bytes() + b'\n')
            with self.assertRaisesRegex(ValueError, 'snapshot changed'):
                V.S.check_snapshot(out / 'source-snapshot', record['source_manifest'])
            for filename in ('input.bin', 'expected.bin'):
                path = out / filename
                original = path.read_bytes()
                path.write_bytes(original + b'\0')
                with self.assertRaisesRegex(ValueError, 'fixture artifact changed'):
                    V.checked_input(out, record['fixture_identity'])
                path.write_bytes(original)

    def test_control_plan_has_twelve_value_and_one_side_variant(self):
        controls = V.variants(V.MODULE.read_text())
        self.assertEqual(len(controls), 13)
        self.assertIn('front-equality-chooses-right', controls)


if __name__ == '__main__':
    unittest.main()
