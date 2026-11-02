import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE=Path(__file__).resolve().parents[1]/'research/work-items/RE-006-fixed-n21-delegate-rust-94'
SPEC=importlib.util.spec_from_file_location('original_n21_fixture',HERE/'verify_rust.py')
V=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)


class OriginalN21FixtureTests(unittest.TestCase):
    def test_original_input_denominator_and_preserved_wire(self):
        record,rows,stimulus,expected=V.frozen()
        self.assertEqual(len(rows),80)
        self.assertFalse(record['rust_source_present'])
        self.assertEqual(len(stimulus),37452)
        self.assertEqual(len(expected),98572)
        self.assertFalse(V.compare(expected,rows))

    def test_all_one_hundred_fifty_three_cutpoint_words_are_compared(self):
        _,rows,_,expected=V.frozen()
        for word in range(153):
            changed=bytearray(expected);changed[20+8*word]^=1
            differences=V.compare(changed,rows)
            self.assertEqual(len(differences),1)
            self.assertEqual(differences[0]['changed_word_indices'],[word])
            self.assertEqual(differences[0]['groups'],['array-values'])

    def test_chosen_rust_result_status_is_separate_from_native_values(self):
        _,rows,_,expected=V.frozen();changed=bytearray(expected);changed[16]=1
        differences=V.compare(changed,rows)
        self.assertEqual(len(differences),1)
        self.assertEqual(differences[0]['groups'],['api-status'])
        self.assertFalse(differences[0]['changed_word_indices'])

    def test_framing_count_and_id_corruption_reject(self):
        _,rows,_,expected=V.frozen()
        for changed in [expected[:-1],expected+b'\0',b'BADMAGIC'+expected[8:]]:
            with self.assertRaisesRegex(ValueError,'frame/length'):V.compare(changed,rows)
        changed=bytearray(expected);changed[8]^=1
        with self.assertRaisesRegex(ValueError,'output count'):V.compare(changed,rows)
        changed=bytearray(expected);changed[12]^=1
        with self.assertRaisesRegex(ValueError,'ID/order'):V.compare(changed,rows)

    def test_full_component_snapshot_and_both_fixture_artifacts_are_bound(self):
        with tempfile.TemporaryDirectory() as name:
            out=Path(name)/'prepared';record=V.run(out)
            for module in ['first_left_insertion','j9_first_front','n21_right_merge','n21_seed_prepare']:
                self.assertIn('component/src/'+module+'.rs',record['source_manifest'])
            path=out/'source-snapshot/component/src/n21_seed_prepare.rs';path.write_bytes(path.read_bytes()+b'\n')
            with self.assertRaisesRegex(ValueError,'snapshot changed'):
                V.S.check_snapshot(out/'source-snapshot',record['source_manifest'])
            for name in ['input.bin','expected.bin']:
                path=out/name;original=path.read_bytes();path.write_bytes(original+b'\0')
                with self.assertRaisesRegex(ValueError,'artifact changed'):V.checked_input(out,record['fixture_identity'])
                path.write_bytes(original)

    def test_all_seventeen_pre_source_semantic_edits_are_operative(self):
        variants=V.variants(V.MODULE.read_text())
        self.assertEqual(len(variants),17)
        self.assertTrue(all(source!=V.MODULE.read_text() for source in variants.values()))


if __name__=='__main__':unittest.main()
