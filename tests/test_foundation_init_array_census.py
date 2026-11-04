#!/usr/bin/env python3
"""Exercise the RE-001 node #115 static-initializer census checker.

The test loads tools/foundation_init_array_census.py and runs its main() on the
saved research/work-items/RE-001-node115-init-array-census packet, so the
committed checker itself is executed on the recorded bytes. It also calls the
checker's own derive() and asserts the target values that the retained baseline
proof output observed: the four section headers, the .rela.dyn census, the 168
.init_array slots and the single .fini_array slot. The pinned target is read in
place; it is never executed and never copied.
"""

import importlib.util
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / 'tools' / 'foundation_init_array_census.py'

INIT_FIRST_LINE = 'slot .init_array[0] va=0x63f36c8 word=0x0 relative=0x5ca55c0'
FINI_FIRST_LINE = 'slot .fini_array[0] va=0x63f36c0 word=0x0 relative=0x14193a0'


def load_checker():
    assert CHECKER.is_file(), 'missing packet checker ' + str(CHECKER)
    spec = importlib.util.spec_from_file_location('foundation_init_array_census', CHECKER)
    assert spec is not None and spec.loader is not None, 'cannot load ' + str(CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InitArrayCensusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checker = load_checker()
        cls.derived, cls.lines = cls.checker.derive(ROOT)

    def test_packet_verifies_against_pinned_target(self):
        output = io.StringIO()
        with redirect_stdout(output):
            status = self.checker.main()
        self.assertEqual(status, 0, output.getvalue())
        self.assertIn('packet verified', output.getvalue())

    def test_derived_target_identity(self):
        self.assertEqual(
            self.derived['target_sha256'],
            'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301')
        self.assertEqual(self.derived['target_size'], 105896032)

    def test_derived_section_headers(self):
        sections = self.derived['sections']
        self.assertEqual(sections['.init_array'], {
            'index': 22, 'type': 14, 'flags': '0x200003', 'addr': '0x63f36c8',
            'offset': '0x63f16c8', 'size': 1344, 'entsize': 0,
        })
        self.assertEqual(sections['.fini_array'], {
            'index': 21, 'type': 15, 'flags': '0x3', 'addr': '0x63f36c0',
            'offset': '0x63f16c0', 'size': 8, 'entsize': 8,
        })
        self.assertEqual(sections['.rela.dyn'], {
            'index': 9, 'type': 4, 'flags': '0x2', 'addr': '0x6be8',
            'offset': '0x6be8', 'size': 1457352, 'entsize': 24,
        })

    def test_derived_relocation_census(self):
        self.assertEqual(self.derived['rela_dyn'], {
            'records': 60723, 'relative_targets': 59534,
        })

    def test_derived_eh_frame_records(self):
        self.assertEqual(self.derived['sections']['.eh_frame'], {
            'index': 14, 'type': 1, 'flags': '0x2', 'addr': '0xca6ed8',
            'offset': '0xca6ed8', 'size': 7803772, 'entsize': 0,
        })
        self.assertEqual(self.derived['eh_frame'], {
            'cie_records': 3, 'fde_records': 135313,
        })

    def test_every_recorded_slot_word_is_zero(self):
        words = set()
        for line in self.lines['init_lines'] + self.lines['fini_lines']:
            words.add(line.split('word=')[1].split(' ')[0])
        self.assertEqual(words, {'0x0'})

    def test_derived_init_array_census(self):
        init = self.derived['init_array']
        self.assertEqual(init['count'], 168)
        self.assertEqual(init['size'], 1344)
        self.assertEqual(init['covered_by_relative'], 168)
        self.assertEqual(len(self.lines['init_lines']), 168)
        self.assertEqual(self.lines['init_lines'][0], INIT_FIRST_LINE)

    def test_derived_fini_array_census(self):
        fini = self.derived['fini_array']
        self.assertEqual(fini['count'], 1)
        self.assertEqual(fini['size'], 8)
        self.assertEqual(fini['covered_by_relative'], 1)
        self.assertEqual(self.lines['fini_lines'], [FINI_FIRST_LINE])

    def test_fde_partitions_each_array(self):
        for name in ('init_array', 'fini_array'):
            entry = self.derived[name]
            self.assertEqual(
                entry['fde_covered'] + entry['fde_missing'], entry['count'],
                name + ' FDE mapping does not partition the slots')

    def test_comparator_reports_a_changed_scalar(self):
        mismatches = []
        self.checker.compare('control', {'value': 1}, {'value': 2}, mismatches)
        self.assertEqual(len(mismatches), 1)

    def test_comparator_accepts_an_identical_scalar(self):
        mismatches = []
        self.checker.compare('control', {'value': 1}, {'value': 1}, mismatches)
        self.assertEqual(mismatches, [])

    def test_comparator_reports_a_missing_record(self):
        mismatches = []
        self.checker.compare('control', {}, {'value': 1}, mismatches)
        self.assertEqual(len(mismatches), 1)

    def test_excerpt_digest_binds_each_derived_line_set(self):
        for key in sorted(self.lines):
            body = self.lines[key]
            self.assertTrue(body, key + ' derived no recorded line')
            mutated = list(body)
            mutated[0] = mutated[0] + 'x'
            self.assertNotEqual(
                self.checker.digest_lines(body), self.checker.digest_lines(mutated),
                key + ' digest does not bind its recorded lines')

    def test_excerpt_count_mismatch_is_reported(self):
        packet = ROOT / self.checker.PACKET_DIR
        self.assertEqual(packet, ROOT / 'research' / 'work-items'
                         / 'RE-001-node115-init-array-census')
        recorded = json.loads((packet / 'evidence.json').read_text(encoding='utf-8'))
        tampered = dict(recorded)
        tampered['excerpts'] = dict(recorded.get('excerpts', {}))
        first = sorted(tampered['excerpts'])[0]
        tampered['excerpts'][first] = int(tampered['excerpts'][first]) + 1
        mismatches = []
        self.checker.check_excerpts(packet, self.lines, tampered, mismatches)
        self.assertEqual(
            [path for path, _, _ in mismatches], ['excerpts.' + first])


if __name__ == '__main__':
    unittest.main()
