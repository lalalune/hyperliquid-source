"""Offline integrity controls for the bounded RE006 outer-route evidence."""
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import struct
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-006-n21-outer-admission-rust-94'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('duplicate JSON key')
        result[name] = value
    return result


def load(name):
    return json.loads((PACKET / name).read_text(), object_pairs_hook=unique)


def member(entry):
    size = entry['bytes']
    if type(size) is not int or not 0 <= size <= 2 * 1024 * 1024:
        raise ValueError('member bound')
    raw = base64.b64decode(entry['zlib_base64'], validate=True)
    if base64.b64encode(raw).decode() != entry['zlib_base64']:
        raise ValueError('noncanonical base64')
    decoder = zlib.decompressobj()
    value = decoder.decompress(raw, size + 1)
    if len(value) != size or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError('zlib boundary')
    if sha(value) != entry['sha256'] or value.startswith((b'\x7fELF', b'!<arch>\n')):
        raise ValueError('hash or executable/archive member')
    return value


class OuterAdmissionEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive = load('RAW-COMPARISONS.json')['members']
        cls.report = load('compiled-results.json')

    def test_archive_is_bounded_and_every_payload_authenticated(self):
        total = 0
        for name, entry in self.archive.items():
            path = PurePosixPath(name)
            self.assertFalse(path.is_absolute())
            self.assertNotIn('..', path.parts)
            total += len(member(entry))
        self.assertLess(total, 10 * 1024 * 1024)

    def test_corrupt_archive_member_is_rejected(self):
        example = dict(next(iter(self.archive.values())))
        example['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            member(example)
        example = dict(next(iter(self.archive.values())))
        example['zlib_base64'] += '!'
        with self.assertRaises(ValueError):
            member(example)

    def test_pre_source_cases_and_literal_wire_binding(self):
        native, plan = load('PRE-SOURCE-BOUNDARIES.json'), load('PRE-SOURCE-RUST-PLAN.json')
        self.assertEqual(sha((PACKET / 'PRE-SOURCE-BOUNDARIES.json').read_bytes()), 'c5840053ecfa7976768d2d861e344bf7b2f8f7e9fb441532226200863ab093f4')
        self.assertEqual(len(native['cases']), 76)
        self.assertEqual(sum(row['first_short_run_delegate'] for row in native['cases']), 56)
        self.assertEqual(native['impossible_run_one']['status'], 'not an input case')
        stimulus, expected = b'', b''
        for case, projection in zip(native['cases'], plan['cases']):
            self.assertEqual(case['name'], projection['name'])
            words = [int(value, 16) for value in case['a21']]
            self.assertEqual(sha(struct.pack('<21Q', *words)), case['a21_le_sha256'])
            self.assertGreaterEqual(case['natural_run'], 2)
            stimulus += struct.pack('<22Q', *words, int(projection['opaque_context'], 16))
            e = projection['expected']
            expected += struct.pack('<27Q', *words, int(e['admitted']), e['natural_run'], int(e['ascending']), e['word_count'], e['scratch_capacity_qwords'], int(e['opaque_context'], 16))
        self.assertEqual(member(self.archive['compiled/input.bin']), stimulus)
        self.assertEqual(member(self.archive['compiled/expected.bin']), expected)
        self.assertEqual(sha(expected), '60bea63167fe7f994c6d6eaf34c6891d15d943c5c64efbfe5a88baa30ea4a2b0')

    def test_historical_execution_and_integrated_preparation_are_distinct(self):
        report = self.report
        self.assertEqual(report['harness_sha256'], '6d8a8263fc5a71b3ea0462c5290ea9921af730976f3011f2ab473fb5f4639b42')
        self.assertEqual(sha(member(self.archive['compiled/executed-guard.py'])), report['harness_sha256'])
        current = load('integrated-preparation.json')
        self.assertEqual(current['status'], 'prepared, not compiled')
        self.assertEqual(current['compiler_manifest'], report['compiler_manifest'])
        self.assertNotEqual(current['harness_sha256'], report['harness_sha256'])
        self.assertEqual(len(report['compiler_manifest']), 17)
        for name, pin in report['compiler_manifest'].items():
            archived = member(self.archive['compiled/source-snapshot/' + name])
            self.assertEqual((len(archived), sha(archived)), (pin['bytes'], pin['sha256']))
            if name.startswith('component/'):
                live = ROOT / 'src/node94-orderbook' / name.removeprefix('component/')
            elif name == 'driver/input_only_driver.rs':
                live = PACKET / 'input_only_driver.rs'
            else:
                live = ROOT / 'src/node94-orderbook/src/n21_outer_admission.rs'
            self.assertEqual(live.read_bytes(), archived)

    def test_all_actual_command_streams_and_four_production_comparisons(self):
        self.assertEqual(len(self.report['commands']), 46)
        expected = member(self.archive['compiled/expected.bin'])
        for command in self.report['commands']:
            self.assertEqual(command['exit_code'], 0)
            for channel in ['stdout', 'stderr']:
                raw = member(self.archive['compiled/commands/' + command['label'] + '.' + channel])
                self.assertEqual(sha(raw), command[channel + '_sha256'])
                if channel == 'stderr':
                    self.assertEqual(raw, b'')
        for row in self.report['production']:
            raw = member(self.archive['compiled/commands/' + row['label'] + '-client-run.stdout'])
            self.assertEqual(raw, expected)
        for profile in ['o0', 'o3']:
            self.assertIn(b'test result: ok. 42 passed;', member(self.archive[f'compiled/commands/{profile}-unit-run.stdout']))

    def test_ten_controls_have_their_preplanned_field_witness(self):
        plan = load('PRE-SOURCE-RUST-PLAN.json')
        names = [row['name'] for row in plan['cases']]
        expected = member(self.archive['compiled/expected.bin'])
        self.assertEqual(len(self.report['controls']), 10)
        base = {name.removeprefix('component/'): pin for name, pin in self.report['compiler_manifest'].items() if name.startswith('component/')}
        for control in self.report['controls']:
            predicted = next(row for row in plan['controls'] if row['name'] == control['name'])
            source = member(self.archive['compiled/mutant-module/' + control['name'] + '.rs'])
            manifest = dict(base)
            manifest['src/n21_outer_admission.rs'] = dict(bytes=len(source), sha256=sha(source))
            self.assertEqual(manifest, control['source_manifest'])
            raw = member(self.archive['compiled/commands/' + control['name'] + '-client-run.stdout'])
            self.assertEqual(len(raw), len(expected))
            index = names.index(predicted['witness'])
            field = {'admission': 21, 'word_count': 24, 'scratch_capacity_qwords': 25, 'opaque_context': 26}[predicted['field']]
            value = predicted['predicted_mutant']
            self.assertEqual(struct.unpack_from('<27Q', raw, index * 216)[field], int(value, 16) if isinstance(value, str) else int(value))
            differences = []
            for i, name in enumerate(names):
                a, b = struct.unpack_from('<27Q', raw, i * 216), struct.unpack_from('<27Q', expected, i * 216)
                changed = [j for j, pair in enumerate(zip(a, b)) if pair[0] != pair[1]]
                if changed:
                    self.assertTrue(all(j >= 21 for j in changed))
                    differences.append(dict(name=name, changed_word_indices=changed))
            self.assertEqual(differences, control['differences'])

    def test_old_fixed21_library_pin_is_preserved(self):
        old = (PACKET / 'predecessor/fixed-n21/lib.rs').read_bytes()
        self.assertEqual(sha(old), '3f8d62652dfb2d96f7bfcb7ceec96817da39a0efafaa2910d7d1821a99a4dbd9')
        current = (ROOT / 'src/node94-orderbook/src/lib.rs').read_bytes()
        self.assertEqual(current, old.replace(b'pub mod n21_right_merge;', b'pub mod n21_right_merge;\npub mod n21_outer_admission;'))
        manifest = (ROOT / 'research/work-items/RE-006-fixed-n21-delegate-rust-94/MANIFEST.sha256').read_text()
        self.assertIn('3f8d62652dfb2d96f7bfcb7ceec96817da39a0efafaa2910d7d1821a99a4dbd9  ../RE-006-n21-outer-admission-rust-94/predecessor/fixed-n21/lib.rs\n', manifest)

    def test_all_static_fragment_channels_match_separate_native_receipt(self):
        result = load('native-results.json')
        self.assertFalse(result['captured_execution'])
        self.assertFalse(result['instruction_evaluation'])
        self.assertEqual(len(result['native_controls']), 16)
        self.assertEqual(result['decoder_processes'], 64)
        for control in result['native_controls']:
            self.assertEqual([row['kind'] for row in control['observations']], ['native', 'overlay'])
            for row in control['observations']:
                for tool in ['gnu', 'llvm']:
                    for channel in ['stdout', 'stderr']:
                        key = 'native/raw/' + '.'.join([control['name'], row['kind'], tool, channel])
                        raw = member(self.archive[key])
                        self.assertEqual(sha(raw), row[tool + '_' + channel + '_sha256'])
                        if channel == 'stderr':
                            self.assertEqual(raw, b'')


if __name__ == '__main__':
    unittest.main()
