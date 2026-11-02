"""Offline source/receipt integrity for the qualified RE006 r20 relation."""
import hashlib
import json
from pathlib import Path
import re
import struct
import unittest

from test_n21_outer_admission94 import audit_current_library, member, unique

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-006-n21-r20-tail1-rust-94'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(name):
    return json.loads((PACKET / name).read_text(), object_pairs_hook=unique)


class Run20Evidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive = load('RAW-COMPARISONS.json')['members']
        cls.report = load('compiled-results.json')
        cls.freeze = load('PRE-SOURCE-FREEZE.json')
        cls.rows = [dict(row, native_domain=True) for row in cls.freeze['cases']] + [dict(row, native_domain=False) for row in cls.freeze['exclusions_cases']]

    def test_frozen_literals_and_policy_frames(self):
        self.assertEqual(sha((PACKET / 'PRE-SOURCE-FREEZE.json').read_bytes()), '6e83dde660d28198ce140eae49b615cdae66c0ccec5e8be3fb9536d1eaabe65c')
        stimulus = member(self.archive['compiled/input.bin'])
        expected = member(self.archive['compiled/expected.bin'])
        self.assertEqual(sha(stimulus), 'e351101b430808fe44e51a164e3837cf16e0c58e22e0fc63cf501b818d747433')
        self.assertEqual(sha(expected), 'e44064ab0b2e5d2e00cf8f62d3ba990c6c220311c28e15c5b4cbadee913c90e5')
        self.assertEqual((len(stimulus), len(expected), len(self.rows)), (11028, 101964, 54))
        for i, row in enumerate(self.rows):
            inputs = struct.unpack_from('<I25Q', stimulus, 12 + 204 * i)
            rid, status, *words = struct.unpack_from('<II235Q', expected, 12 + 1888 * i)
            self.assertEqual(inputs[0], rid)
            self.assertEqual(list(inputs[1:22]), row['source21'])
            self.assertEqual(status, 0 if row['native_domain'] else 1)
            if row['native_domain']:
                self.assertEqual(words[:21], row['source21_final'])
                self.assertEqual(words[21:25], row['final_scratch_prefix4'])
                self.assertEqual(words[25:46], row['post_normalization21'])
                self.assertEqual(words[48:51], [row['upper_bound_index'], row['loop_store_count'], row['source_reversal_word_writes']])
            else:
                self.assertEqual(words[:25], list(inputs[1:]))
                self.assertEqual(words[25:46], row['source21'])
                self.assertEqual(words[48:], [0] * (235 - 48))

    def test_phased_actual_commands_and_four_outputs(self):
        report = self.report
        self.assertEqual(len(report['commands']), 47)
        self.assertEqual(sum(row['execution_phase'] == 'actual resumed command' for row in report['commands']), 45)
        self.assertEqual(sum('reused without execution' in row['execution_phase'] for row in report['commands']), 2)
        old = json.loads(member(self.archive['compiled/commands.json']))
        self.assertEqual([row['label'] for row in old], ['rustc-version', 'o0-r0-library'])
        for a, b in zip(old, report['commands'][:2]):
            self.assertEqual(a, {key: value for key, value in b.items() if key != 'execution_phase'})
        for row in report['commands']:
            self.assertEqual(row['exit_code'], 0)
            self.assertGreaterEqual(row['free_bytes_after'], 300 * 1024 * 1024)
            for channel in ['stdout', 'stderr']:
                raw = member(self.archive['compiled/commands/' + row['label'] + '.' + channel])
                self.assertEqual(sha(raw), row[channel + '_sha256'])
                if channel == 'stderr':
                    self.assertEqual(raw, b'')
        expected = member(self.archive['compiled/expected.bin'])
        for row in report['production']:
            self.assertEqual(member(self.archive['compiled/commands/' + row['label'] + '-client-run.stdout']), expected)
        for profile in ['o0', 'o3']:
            self.assertIn(b'test result: ok. 46 passed;', member(self.archive[f'compiled/commands/{profile}-unit-run.stdout']))

    def test_exact_executed_guards_and_integrated_snapshot(self):
        report = self.report
        qualification = report['resume_qualification']
        self.assertEqual(sha(member(self.archive['compiled/executed-initial-guard.py'])), qualification['original_harness_sha256'])
        self.assertEqual(sha(member(self.archive['compiled/executed-resume-guard.py'])), report['harness_sha256'])
        stop = load('GUARD-STOP.json')
        self.assertEqual(stop['shortfall_bytes'], 110592)
        self.assertFalse(stop['client_or_unit_or_mutant_executed'])
        first = report['removed_completed_binary_cache'][0]
        library = next(row for row in first['files'] if row['file'].endswith('.rlib'))
        self.assertEqual(library['sha256'], stop['retained_library']['sha256'])
        current = load('integrated-preparation.json')
        self.assertEqual(current['status'], 'prepared, no compiler invoked')
        self.assertNotEqual(current['harness_sha256'], report['harness_sha256'])
        self.assertEqual(current['conservative_compiler_manifest'], report['conservative_compiler_manifest'])
        self.assertEqual(len(report['conservative_compiler_manifest']), 18)
        for name, pin in report['conservative_compiler_manifest'].items():
            raw = member(self.archive['compiled/source-snapshot/' + name])
            self.assertEqual((len(raw), sha(raw)), (pin['bytes'], pin['sha256']))
            if name.startswith('component/'):
                live = ROOT / 'src/node94-orderbook' / name.removeprefix('component/')
            elif name.startswith('driver/'):
                live = PACKET / 'input_only_driver.rs'
            else:
                live = ROOT / 'src/node94-orderbook/src/n21_run20_tail1.rs'
            self.assertEqual(live.read_bytes(), raw)

    def test_seven_array_and_three_observation_control_witnesses(self):
        expected = member(self.archive['compiled/expected.bin'])
        plan = load('PRE-SOURCE-RUST-PLAN-v2.json')
        self.assertEqual([sum(row['planned_kind'] == kind for row in self.report['controls']) for kind in ['array-values', 'metadata-only']], [7, 3])
        for control in self.report['controls']:
            raw = member(self.archive['compiled/commands/' + control['name'] + '-client-run.stdout'])
            differences = []
            for i, row in enumerate(self.rows):
                at = 12 + i * 1888
                rid, status, *actual = struct.unpack_from('<II235Q', raw, at)
                want_id, want_status, *wanted = struct.unpack_from('<II235Q', expected, at)
                self.assertEqual(rid, want_id)
                changed = [j for j, pair in enumerate(zip(actual, wanted)) if pair[0] != pair[1]]
                if changed or status != want_status:
                    differences.append(dict(name=row['name'], native_domain=row['native_domain'], status_changed=status != want_status,
                                            final_array_indices=[j for j in changed if j < 25],
                                            normalization_indices=[j - 25 for j in changed if 25 <= j < 46],
                                            observation_indices=[j - 46 for j in changed if j >= 46]))
            self.assertEqual(differences, control['differences'])
            predicted = next(row for row in plan['source_controls'] if row['name'] == control['name'])
            witness = next(row for row in differences if row['name'] == predicted['witness'])
            self.assertTrue(witness['native_domain'])
            self.assertTrue(all(row['native_domain'] for row in differences))
            if predicted['planned_kind'] == 'array-values':
                self.assertTrue(witness['final_array_indices'])
            else:
                self.assertTrue(witness['observation_indices'])
                self.assertTrue(all(not row['final_array_indices'] and not row['normalization_indices'] and not row['status_changed'] for row in differences))

    def test_raw_local_dependency_receipts(self):
        self.assertEqual(len(self.report['local_dependency_receipts']), 30)
        for row in self.report['local_dependency_receipts']:
            raw = member(self.archive['compiled/dependencies/' + row['label'] + '.d'])
            self.assertEqual((len(raw), sha(raw)), (row['bytes'], row['sha256']))
            observed = sorted(set(re.findall(r'[^\s:]+\.rs', raw.decode())))
            self.assertEqual(observed, row['local_rust_sources'])
            count = 1 if row['label'].endswith('-client-build') else 13 if '-unit-' in row['label'] else 12
            self.assertEqual(len(observed), count)

    def test_historical_migration_still_audits_current_library(self):
        prior = ROOT / 'research/work-items/RE-006-n21-outer-admission-rust-94'
        historical_lib = (PACKET / 'predecessor/outer-admission/lib.rs').read_bytes()
        historical_test = (PACKET / 'predecessor/outer-admission/test_n21_outer_admission94.py').read_bytes()
        self.assertEqual(sha(historical_lib), '236c8e60dc3c1541fb52aa8399e455c8c75ff633c749bb1f98db61cba72e226d')
        self.assertEqual(sha(historical_test), '9652d0e139ef4f5ed8404898105e69fa6ddc2ed61d0c01bb9bf2440dbc33ecf1')
        original = member(self.archive['history/outer-MANIFEST.sha256']).decode()
        for pin, before, after in [
            (sha(historical_lib), '../../../src/node94-orderbook/src/lib.rs', '../RE-006-n21-r20-tail1-rust-94/predecessor/outer-admission/lib.rs'),
            (sha(historical_test), '../../../tests/test_n21_outer_admission94.py', '../RE-006-n21-r20-tail1-rust-94/predecessor/outer-admission/test_n21_outer_admission94.py'),
        ]:
            self.assertEqual(original.count(pin + '  ' + before), 1)
            original = original.replace(pin + '  ' + before, pin + '  ' + after)
        self.assertEqual((prior / 'MANIFEST.sha256').read_text(), original)
        current = (ROOT / 'src/node94-orderbook/src/lib.rs').read_bytes()
        audit_current_library(historical_lib, current)
        with self.assertRaises(ValueError):
            audit_current_library(historical_lib, current + b'// unreviewed source drift\n')
        with self.assertRaises(ValueError):
            audit_current_library(historical_lib, current.replace(b'pub mod n21_outer_admission;', b''))

    def test_errata_and_external_import_boundary_remain_explicit(self):
        original, corrected = load('PRE-SOURCE-RUST-PLAN.json'), load('PRE-SOURCE-RUST-PLAN-v2.json')
        old = next(row for row in original['source_controls'] if row['name'] == 'merge-signed-compare')
        new = next(row for row in corrected['source_controls'] if row['name'] == 'merge-signed-compare')
        self.assertEqual((old['witness'], new['witness']), ('ascending-r20-high-bit-crossing', 'descending-r20-max-tail'))
        result = load('STATIC-CONTROL-RESULTS.json')
        self.assertEqual(result['control_erratum_sha256'], sha((PACKET / 'CONTROL-ERRATUM.json').read_bytes()))
        self.assertTrue(all(not row['counted_as_array_output_control'] for row in result['controls']))
        self.assertNotIn('remaining-copy-wrong-destination', [row['name'] for row in corrected['source_controls']])
        boundary = load('NATIVE-INTAKE.json')['copy_import']
        self.assertTrue(boundary['undefined'])
        self.assertIsNone(boundary['local_provider_fde'])
        self.assertEqual((boundary['symbol'], boundary['version'], boundary['required_library']), ('memcpy', 'GLIBC_2.14', 'libc.so.6'))

    def test_bounded_archive_rejects_corruption(self):
        total = sum(len(member(entry)) for entry in self.archive.values())
        self.assertLess(total, 10 * 1024 * 1024)
        bad = dict(self.archive['compiled/expected.bin'])
        bad['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            member(bad)
        bad = dict(self.archive['compiled/expected.bin'])
        bad['zlib_base64'] += '!'
        with self.assertRaises(ValueError):
            member(bad)


if __name__ == '__main__':
    unittest.main()
