"""Comparator/fixture checks only; compiled Rust has a separate required gate."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

PACKET=Path(__file__).resolve().parents[1]/'research/work-items/RE-006-monotone-keys-rust-94'
spec=importlib.util.spec_from_file_location('monotone_rust_fixture94',PACKET/'verify_rust.py')
packet=importlib.util.module_from_spec(spec); spec.loader.exec_module(packet)


class FixtureComparatorTests(unittest.TestCase):
    def test_frozen_native_and_safe_api_denominators_are_separate(self):
        rows=packet.cases()
        self.assertEqual(len(rows),81)
        self.assertEqual(sum(r['scope']=='qualified native value relation' for r in rows),76)
        self.assertEqual(sum(r['scope']=='chosen safe API policy only' for r in rows),5)

    def test_exact_full_buffer_output_and_qualified_corruption(self):
        rows=packet.cases(); golden=packet.protocol(rows,expected=True)
        self.assertEqual(packet.compare(golden,rows),[])
        changed=bytearray(golden); changed[21]^=1
        misses=packet.compare(changed,rows)
        self.assertEqual(len(misses),1)
        self.assertEqual(misses[0]['name'],'increasing-21')
        self.assertEqual(misses[0]['scope'],'qualified native value relation')

    def test_malformed_output_is_rejected(self):
        rows=packet.cases(); golden=packet.protocol(rows,expected=True)
        for corrupt in [b'',b'BADOUT01'+golden[8:],golden[:-1],golden+b'\0']:
            with self.subTest(bytes=len(corrupt)),self.assertRaises(ValueError): packet.compare(corrupt,rows)

    def test_planned_source_mutants_have_explicit_counterexample_domains(self):
        source=packet.MODULE.read_text(); variants=packet.wrong_variants(source)
        self.assertEqual(len(variants),6)
        self.assertEqual(len(set(variants.values())),6)
        self.assertTrue(all(value!=source for value in variants.values()))
        self.assertEqual(set(variants),set(packet.MUTANT_DOMAINS))
        self.assertEqual(sum(scope=='qualified native value relation' for scope in packet.MUTANT_DOMAINS.values()),5)
        self.assertEqual(packet.MUTANT_DOMAINS['allow-descending-ties'],'chosen safe API policy only')

    def test_fixed_source_snapshot_covers_component_and_driver(self):
        with tempfile.TemporaryDirectory(prefix='monotone-source-review-') as temporary:
            directory,manifest=packet.source_snapshot(Path(temporary))
            self.assertIn('component/src/lib.rs',manifest)
            self.assertIn('component/src/monotone_keys.rs',manifest)
            self.assertIn('component/src/book.rs',manifest)
            self.assertIn('driver/input_only_driver.rs',manifest)
            packet.check_snapshot(directory,manifest)
            packet.check_live_source(manifest)
            source=directory/'component/src/monotone_keys.rs'
            source.write_text(source.read_text()+'\n// corrupt snapshot\n')
            with self.assertRaisesRegex(ValueError,'snapshot changed'):
                packet.check_snapshot(directory,manifest)

    def test_input_and_expected_artifact_corruption_is_rejected(self):
        rows=packet.cases(); stimulus=packet.protocol(rows); golden=packet.protocol(rows,expected=True)
        fixture={'input_sha256':packet.sha(stimulus),'expected_sha256':packet.sha(golden)}
        with tempfile.TemporaryDirectory(prefix='monotone-fixture-review-') as temporary:
            out=Path(temporary); (out/'input.bin').write_bytes(stimulus); (out/'expected.bin').write_bytes(golden)
            self.assertEqual(packet.checked_fixture_artifacts(out,fixture),stimulus)
            (out/'input.bin').write_bytes(b'X'+stimulus[1:])
            with self.assertRaisesRegex(ValueError,'artifact changed: input.bin'):
                packet.checked_fixture_artifacts(out,fixture)
            (out/'input.bin').write_bytes(stimulus)
            (out/'expected.bin').write_bytes(golden[:-1]+bytes([golden[-1]^1]))
            with self.assertRaisesRegex(ValueError,'artifact changed: expected.bin'):
                packet.checked_fixture_artifacts(out,fixture)


if __name__=='__main__': unittest.main()
