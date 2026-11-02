import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-006-first-left-insertion-rust-94'
SPEC = importlib.util.spec_from_file_location('first_insertion_rust94', PACKET / 'verify_rust.py')
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)


class FirstInsertionFixtureTests(unittest.TestCase):
    def test_frozen_eighteen_state_denominator_and_complete_output(self):
        rows, old = V.cases()
        self.assertEqual(len(rows), 18)
        self.assertEqual(V.compare(V.protocol(rows, old, True), rows), ([], []))
        self.assertEqual(sum(row['name'].startswith('unsorted-') for row in rows), 6)

    def test_every_output_word_is_compared(self):
        rows, old = V.cases()
        for word in range(9):
            raw = bytearray(V.protocol(rows, old, True))
            raw[20 + word * 8] ^= 1
            arrays, _ = V.compare(raw, rows)
            self.assertEqual(len(arrays), 1)

    def test_index_only_corruption_is_separate_from_arrays(self):
        rows, old = V.cases()
        raw = bytearray(V.protocol(rows, old, True))
        raw[16] ^= 1
        arrays, indices = V.compare(raw, rows)
        self.assertFalse(arrays)
        self.assertEqual(len(indices), 1)

    def test_malformed_frames_reject(self):
        rows, old = V.cases()
        raw = V.protocol(rows, old, True)
        for changed in (raw[:-1], raw + b'\0', b'BADMAGIC' + raw[8:]):
            with self.assertRaises(ValueError):
                V.compare(changed, rows)
        changed = bytearray(raw)
        changed[12] = 1
        with self.assertRaisesRegex(ValueError, 'ID/order'):
            V.compare(changed, rows)

    def test_fixed_snapshot_and_fixture_artifacts_are_bound(self):
        with tempfile.TemporaryDirectory() as name:
            out = Path(name) / 'prepared'
            record = V.run(out)
            snapshot = out / 'source-snapshot'
            self.assertIn('component/src/first_left_insertion.rs', record['source_manifest'])
            self.assertIn('driver/input_only_driver.rs', record['source_manifest'])
            path = snapshot / 'component/src/first_left_insertion.rs'
            path.write_bytes(path.read_bytes() + b'\n')
            with self.assertRaisesRegex(ValueError, 'snapshot changed'):
                V.check_snapshot(snapshot, record['source_manifest'])
            for filename in ('input.bin', 'expected.bin'):
                artifact = out / filename
                original = artifact.read_bytes()
                artifact.write_bytes(original + b'\0')
                with self.assertRaisesRegex(ValueError, 'artifact changed'):
                    V.checked_input(out, record['fixture'])
                artifact.write_bytes(original)

    def test_original_control_plan_is_preserved(self):
        controls = V.variants(V.MODULE.read_text())
        self.assertEqual(len(controls), 8)
        self.assertIn('shift-equal-predecessors', controls)

    def test_frozen_unsorted_equality_counterexample_changes_array(self):
        rows, old = V.cases()
        index = next(i for i, r in enumerate(rows) if r['name'] == 'unsorted-last-equality-no-shift')
        raw = bytearray(V.protocol(rows, old, True))
        wrong = [9, 0, 8, 1, 7, 2, 5, 6, 5]
        raw[12 + 80 * index:12 + 80 * (index + 1)] = struct.pack('<II9Q', index, 6, *wrong)
        arrays, indices = V.compare(raw, rows)
        self.assertEqual([r['name'] for r in arrays], ['unsorted-last-equality-no-shift'])
        self.assertFalse(indices)


if __name__ == '__main__':
    unittest.main()
