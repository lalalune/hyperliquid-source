import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]/'research/work-items/RE-006-fixed-n21-delegate-rust-94/prepared'
SPEC = importlib.util.spec_from_file_location('n21_prepared_fixture', HERE/'verify_rust.py')
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)


class PreparedN21FixtureTests(unittest.TestCase):
    def test_frozen_native_and_policy_denominators(self):
        _, rows, stimulus, expected = V.frozen()
        self.assertEqual(len(rows), 84)
        self.assertEqual(sum(r['native_domain'] for r in rows), 80)
        self.assertEqual(len(stimulus), 39324)
        self.assertEqual(len(expected), 125340)
        self.assertFalse(V.compare(expected, rows))

    def test_all_fifty_eight_array_words_are_compared(self):
        _, rows, _, expected = V.frozen()
        for word in range(58):
            altered = bytearray(expected)
            altered[20 + 8*word] ^= 1
            changed = V.compare(altered, rows)
            self.assertEqual(len(changed), 1)
            self.assertEqual(changed[0]['groups'], ['array-values'])

    def test_provenance_and_logical_write_differences_are_not_array_kills(self):
        _, rows, _, expected = V.frozen()
        for offset, group in [(12+504+4, 'cursor-index-provenance'), (12+628+8, 'chosen-logical-writes')]:
            changed = bytearray(expected)
            changed[offset] ^= 1
            differences = V.compare(changed, rows)
            self.assertEqual(len(differences), 1)
            self.assertEqual(differences[0]['groups'], [group])

    def test_policy_refusal_cannot_count_as_native_value_witness(self):
        _, rows, _, expected = V.frozen()
        altered = bytearray(expected)
        altered[12 + 80*1492 + 8] ^= 1
        changed = V.compare(altered, rows)
        self.assertEqual(len(changed), 1)
        self.assertFalse(changed[0]['native_domain'])
        self.assertIn('array-values', changed[0]['groups'])

    def test_frames_counts_ids_and_trace_bounds_reject(self):
        _, rows, _, expected = V.frozen()
        for changed in [expected[:-1], expected+b'\0', b'BADMAGIC'+expected[8:]]:
            with self.assertRaisesRegex(ValueError, 'frame/length'):
                V.compare(changed, rows)
        changed = bytearray(expected);changed[8] ^= 1
        with self.assertRaisesRegex(ValueError, 'output count'):V.compare(changed, rows)
        changed = bytearray(expected);changed[12] ^= 1
        with self.assertRaisesRegex(ValueError, 'ID/order'):V.compare(changed, rows)
        changed = bytearray(expected);changed[12+624] = 55
        with self.assertRaisesRegex(ValueError, 'write count'):V.compare(changed, rows)

    def test_source_snapshot_and_both_wire_artifacts_are_guarded(self):
        with tempfile.TemporaryDirectory() as name:
            out = Path(name)/'prepared'
            record = V.run(out)
            self.assertIn('component/src/n21_right_merge.rs', record['source_manifest'])
            path = out/'source-snapshot/component/src/n21_right_merge.rs'
            path.write_bytes(path.read_bytes()+b'\n')
            with self.assertRaisesRegex(ValueError, 'snapshot changed'):
                V.S.check_snapshot(out/'source-snapshot', record['source_manifest'])
            for name in ['input.bin','expected.bin']:
                path=out/name;original=path.read_bytes();path.write_bytes(original+b'\0')
                with self.assertRaisesRegex(ValueError, 'artifact changed'):
                    V.checked_input(out,record['fixture_identity'])
                path.write_bytes(original)

    def test_preplanned_nineteen_mutations_are_operative_source_edits(self):
        variants = V.variants(V.MODULE.read_text())
        self.assertEqual(len(variants),19)
        self.assertTrue(all(source!=V.MODULE.read_text() for source in variants.values()))


if __name__=='__main__':
    unittest.main()
