import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import gap_candidate_release_mapping as mapping


class GapReleaseMappingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='gap-release-test-')
        cls.folder = Path(cls.temp.name)
        cls.baseline = cls.folder / 'baseline'
        cls.report = mapping.produce(cls.baseline)
        cls.records = json.loads((cls.baseline / 'instructions.json').read_text())
        cls.paths = {r: ROOT / 'artifacts/node' / r / 'hl-node' for r in mapping.TARGETS}
        cls.raw, cls.layouts = {}, {}
        for release, (size, sha, _) in mapping.TARGETS.items():
            image = mapping.admit_image(cls.paths[release], size, sha)
            cls.layouts[release] = mapping.layout(image)
            for candidate in cls.report['targets'][release]['candidates']:
                cls.raw[release, candidate['label']] = image[candidate['offset']:candidate['offset'] + candidate['bytes']]
            del image

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def candidate(self, release, label):
        return next(c for c in self.report['targets'][release]['candidates'] if c['label'] == label)

    def file_hashes(self, folder):
        return {p.name: mapping.digest(p.read_bytes()) for p in folder.iterdir() if p.is_file()}

    def test_complete_actual_mapping_and_separate_unwind_context(self):
        self.assertEqual(self.report['denominator'], {'code_byte_pairs': 2418, 'instruction_pairs': 609,
                                                     'local_branch_pairs': 12})
        self.assertTrue(self.report['all_facts_from_digest_authenticated_immutable_bytes'])
        for label, start, end, count in [('A', 0x62e4700, 0x62e4b7d, 285),
                                         ('B', 0x62e4b7d, 0x62e5072, 324)]:
            a, b = self.candidate('94', label), self.candidate('115', label)
            self.assertEqual((b['start'], b['end'], b['native_rows']), (start, end, count))
            self.assertEqual(a['sha256'], b['sha256'])
            self.assertEqual(b['reachable_rows'], count)
            self.assertEqual(len(b['block_leaders']), 9)
            self.assertEqual(len(b['local_branches']), 6)
            self.assertEqual(b['unwind_context']['intersecting_fdes'], [])
            self.assertEqual(self.records['94-' + label]['normalized_rows'],
                             self.records['115-' + label]['normalized_rows'])
        n94 = self.candidate('94', 'A')['unwind_context']['following']
        n115 = self.candidate('115', 'A')['unwind_context']['following']
        self.assertEqual((n94['end'] - n94['start'], n115['end'] - n115['start']), (408, 2914))
        self.assertNotEqual(n94['raw_fde']['sha256'], n115['raw_fde']['sha256'])

    def test_unique_search_refuses_missing_and_duplicate_complete_actual_body(self):
        raw = self.raw['115', 'B']
        self.assertEqual(mapping.unique_match(b'\xcc' + raw + b'\xcc', raw), 1)
        for haystack in (raw[:-1], raw + b'\xcc' + raw):
            with self.assertRaisesRegex(ValueError, 'exactly once'):
                mapping.unique_match(haystack, raw)

    def test_actual_one_sided_scalar_memory_and_branch_changes_have_no_masks(self):
        raw = self.raw['115', 'B']
        rows = self.records['115-B']['rows']
        scalar = next(r for r in rows if '0x2492492492492493' in r['operand'])
        memory = next(r for r in rows if 'r14+' in r['operand'] and '*4' in r['operand'])
        branch = next(r for r in rows if r['mnemonic'] == 'je')
        offsets = [scalar['offset'] + len(bytes.fromhex(scalar['encoding'])) - 1,
                   memory['offset'] + len(bytes.fromhex(memory['encoding'])) - 1,
                   branch['offset'] + 2]
        for off in offsets:
            changed = bytearray(raw)
            changed[off] ^= 1
            with self.subTest(offset=off), self.assertRaisesRegex(ValueError, 'no byte masks'):
                mapping.compare_bodies(self.raw['94', 'B'], 0x56319fd, bytes(changed), 0x62e4b7d, 324)

    def test_native_rendered_branch_target_must_equal_encoded_destination(self):
        raw = self.raw['94', 'A']

        def bad_display(data, start):
            text = mapping.native_listing(data, start)
            return re.sub(r'(\bje\s+)(0x[0-9a-f]+)',
                          lambda m: m[1] + hex(int(m[2], 16) + 1), text, count=1)

        with self.assertRaisesRegex(ValueError, 'display disagrees'):
            mapping.decode(raw, 0x5631580, 285, bad_display)

    def test_stale_wrong_native_view_and_address_refused(self):
        raw = self.raw['94', 'A']

        def stale(data, start):
            return mapping.native_listing(data[:-1] + b'\x90', start)

        with self.assertRaisesRegex(ValueError, 'address/bytes'):
            mapping.decode(raw, 0x5631580, 285, stale)
        with self.assertRaisesRegex(ValueError, 'address/bytes'):
            mapping.decode(raw, 0x5631580, 285,
                           lambda data, start: mapping.native_listing(data, start + 1))

    def test_nonbranch_native_operand_is_not_normalized(self):
        def wrong_operand(data, start):
            text = mapping.native_listing(data, start)
            return text.replace('0x2492492492492493', '0x2492492492492492', 1) if start == 0x62e4b7d else text

        with self.assertRaisesRegex(ValueError, 'scalar/memory/CFG operands differ'):
            mapping.compare_bodies(self.raw['94', 'B'], 0x56319fd,
                                   self.raw['115', 'B'], 0x62e4b7d, 324, wrong_operand)

    def test_coordinate_ambiguity_and_actual_header_field_inconsistency(self):
        secs, loads = self.layouts['115']
        c = self.candidate('115', 'A')
        text = next(s for s in secs if s['name'] == '.text')
        load = next(p for p in loads if p['offset'] <= c['offset'] < p['offset'] + p['size'])
        cases = [(secs + [dict(text)], loads), (secs, loads + [dict(load)])]
        for field, delta in [('address', 1), ('offset', 1), ('flags', -1)]:
            altered = copy.deepcopy(loads)
            item = next(p for p in altered if p == load)
            item[field] += delta
            cases.append((secs, altered))
        for ss, ps in cases:
            with self.subTest(sections=len(ss), loads=len(ps)), self.assertRaises(ValueError):
                mapping.coordinate(ss, ps, c['offset'], c['bytes'], c['start'])
        with self.assertRaisesRegex(ValueError, 'coordinates disagree'):
            mapping.coordinate(secs, loads, c['offset'], c['bytes'], c['start'] + 1)

    def test_actual_branch_to_noninstruction_boundary_is_rejected(self):
        raw = bytearray(self.raw['94', 'B'])
        branch = next(r for r in self.records['94-B']['rows'] if r['mnemonic'] == 'je')
        raw[branch['offset'] + 2] += 1
        with self.assertRaisesRegex(ValueError, 'instruction boundary'):
            mapping.decode(bytes(raw), 0x56319fd, 324)

    def test_actual_unwind_record_and_intersection_controls(self):
        c = self.candidate('115', 'A')
        context = c['unwind_context']
        intersecting = dict(context['previous'], end=c['start'] + 1)
        with self.assertRaisesRegex(ValueError, 'intersects an FDE'):
            mapping.unwind_context(b'', [], [intersecting, context['following']], c['start'], c['end'])
        actual = bytes.fromhex(context['previous']['raw_fde']['hex'])
        frame = {'offset': 0, 'address': context['previous']['fde'], 'size': len(actual)}
        self.assertEqual(mapping.frame_record(actual, frame, frame['address'])['sha256'], mapping.digest(actual))
        changed = bytearray(actual)
        changed[:4] = (len(actual) + 4).to_bytes(4, 'little')
        with self.assertRaisesRegex(ValueError, 'Invalid selected unwind record'):
            mapping.frame_record(bytes(changed), frame, frame['address'])

    def test_admitted_bytes_survive_real_private_source_mutation(self):
        raw = self.raw['94', 'A']
        path = self.folder / 'private-admission-view.bin'
        path.write_bytes(raw)
        admitted = mapping.admit_image(path, len(raw), mapping.digest(raw))
        changed = raw[:-1] + b'\x90'
        path.write_bytes(changed)
        self.assertIs(type(admitted), bytes)
        self.assertEqual(admitted, raw)
        self.assertEqual(mapping.decode(admitted, 0x5631580, 285)['reachable_rows'], 285)
        with self.assertRaisesRegex(ValueError, 'digest'):
            mapping.admit_image(path, len(raw), mapping.digest(raw))

    def test_production_source_alias_replacement_cannot_reopen_wrong_image(self):
        alias = self.folder / 'private-node115-alias'
        alias.symlink_to(self.paths['115'])
        wrong = self.folder / 'wrong-image.bin'
        wrong.write_bytes(b'X')
        replaced = False

        def change_private_path(data, start):
            nonlocal replaced
            if not replaced:
                replacement = self.folder / 'replacement-alias'
                replacement.symlink_to(wrong)
                os.replace(replacement, alias)
                replaced = True
            return mapping.native_listing(data, start)

        out = self.folder / 'alias-replaced-result'
        mapping.produce(out, {'94': self.paths['94'], '115': alias}, change_private_path)
        self.assertTrue(replaced)
        self.assertEqual(alias.read_bytes(), b'X')
        self.assertEqual(self.file_hashes(out), self.file_hashes(self.baseline))

    def test_real_cli_reproduction_existing_directory_and_wrong_identity(self):
        tool = ROOT / 'tools/gap_candidate_release_mapping.py'
        for name in ('cli-a', 'cli-b'):
            out = self.folder / name
            result = subprocess.run([sys.executable, '-B', str(tool), '--output-dir', str(out)],
                                    cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.file_hashes(out), self.file_hashes(self.baseline))
        before = self.file_hashes(self.folder / 'cli-a')
        repeated = subprocess.run([sys.executable, '-B', str(tool), '--output-dir', str(self.folder / 'cli-a')],
                                  capture_output=True, text=True)
        self.assertNotEqual(repeated.returncode, 0)
        self.assertIn('Refusing existing evidence', repeated.stderr)
        self.assertEqual(before, self.file_hashes(self.folder / 'cli-a'))
        bad = self.folder / 'bad-image'
        bad.write_bytes(b'bad')
        out = self.folder / 'must-not-exist'
        rejected = subprocess.run([sys.executable, '-B', str(tool), '--node115', str(bad),
                                   '--output-dir', str(out)], capture_output=True, text=True)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn('Wrong captured target size', rejected.stderr)
        self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
