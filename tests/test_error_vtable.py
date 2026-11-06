import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from error_vtable import (BODIES, DROP_CALLERS, PACKET,
                          SHARED_METHOD_VTABLES, SHA, SIZE, TARGET,
                          VTABLE, analyze, generate)
from elf_index import sections


def payload(path):
    return json.loads(Path(path).read_text())


class ErrorVtableTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TARGET.exists() or TARGET.stat().st_size != SIZE:
            raise unittest.SkipTest('pinned node115 target is not '
                                    'materialised')
        cls.data = TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != SHA:
            raise unittest.SkipTest('target digest is not the '
                                    'pinned node115 distribution')
        cls.retained = payload(PACKET / 'records.json')
        cls.payload = analyze(cls.data)

    def mutated(self, va, delta, value):
        data = bytearray(self.data)
        offset = self.offset_of(va)
        data[offset + delta] = value
        return bytes(data)

    def offset_of(self, va):
        for s in sections(self.data):
            if (s['type'] != 8 and s['address'] <= va
                    < s['address'] + s['size']):
                return s['offset'] + va - s['address']
        raise AssertionError('unmapped va')

    def test_regeneration_matches_retained_packet(self):
        self.assertEqual(self.payload, self.retained)
        regen_dir = Path(tempfile.mkdtemp())
        generate(self.payload, regen_dir)
        names = (['records.json', 'frames.txt', 'README.md',
                  'MANIFEST.sha256']
                 + [f'{role}.objdump.txt' for role in BODIES])
        for name in names:
            self.assertEqual((regen_dir / name).read_bytes(),
                             (PACKET / name).read_bytes(), name)

    def test_nine_bodies_and_cross_checks(self):
        self.assertEqual(len(self.payload['bodies']), 9)
        roles = {b['role'] for b in self.payload['bodies']}
        self.assertEqual(roles, set(BODIES))
        by_role = {b['role']: b for b in self.payload['bodies']}
        self.assertEqual(
            by_role['panic_msg_thunk']['sha256'],
            '2d00fd36dc6102ab0738e08907482bb818bca6e76e32a5b941eab'
            'f431f20767a')
        self.assertEqual(
            by_role['error_drop']['sha256'],
            'b885e0eb89f25e75b60b385a076b04e5e2469790d0fa6d97bf25'
            'c6c611b6b52a')
        self.assertEqual(by_role['method_stub']['bytes'], 6)
        self.assertEqual(by_role['method_body']['bytes'], 1237)
        self.assertEqual(by_role['adapter_b']['bytes'], 16)
        self.assertTrue(
            self.payload['cross_checks']
            ['panic_msg_thunk_matches_pr3000_pr3012'])

    def test_vtable_decode(self):
        vt = self.payload['vtable']
        self.assertEqual(vt['base'], '0x64005f0')
        self.assertEqual(vt['drop_in_place'], '0x15be1a0')
        self.assertEqual(vt['size'], 8)
        self.assertEqual(vt['align'], 8)
        self.assertEqual(vt['method_stub'], '0x5ca5610')
        self.assertEqual(vt['method_body'], '0x5ca7ea0')
        self.assertEqual(vt['method_got_slot'], '0x64e1878')
        self.assertEqual(vt['relocations_landing'],
                         ['0x64005f0', '0x6400608'])

    def test_reference_census_exactly_one(self):
        census = self.payload['census']
        self.assertEqual(
            census['rip_refs_to_vtable'],
            [{'site': '0x15d5c42', 'target': '0x64005f0',
              'kind': 'lea', 'in_body': '0x15d5b00'}])
        self.assertEqual(census['movabs_immediates_to_vtable'], [])
        self.assertEqual(
            census['relocation_addends_into_vtable'], [])
        self.assertEqual(census['raw_qwords_naming_vtable'], [])
        got = [(c['site'], c['in_body'])
               for c in census['direct_rel32_callers_of_error_drop']]
        self.assertEqual(got, [tuple(x) for x in DROP_CALLERS])
        self.assertEqual(len(got), 7)

    def test_shared_method_census(self):
        shared = self.payload['shared_method_census']
        self.assertEqual(shared['vtable_count'], 32)
        self.assertEqual(shared['got_cell'], '0x64e0170')
        self.assertEqual(len(shared['method_cells']), 33)
        bases = [int(v['base'], 16) for v in shared['vtables']]
        self.assertEqual(bases, SHARED_METHOD_VTABLES)
        drops = {v['drop_in_place'] for v in shared['vtables']}
        self.assertEqual(len(drops), 30)
        self.assertTrue(all(v['size'] == 8 and v['align'] == 8
                            for v in shared['vtables']))
        ours = [v for v in shared['vtables'] if v['is_this_vtable']]
        self.assertEqual(len(ours), 1)
        self.assertEqual(ours[0]['base'], '0x64005f0')
        self.assertEqual(shared['vtables_naming_error_drop'],
                         ['0x64005f0'])

    def test_jump_table_arms(self):
        jt = self.payload['method_jump_table']
        self.assertEqual(jt['table'], '0x948c90')
        self.assertEqual(
            [(a['tag'], a['arm']) for a in jt['arms']],
            [(0, '0x5ca7ecc'), (1, '0x5ca80fe'),
             (2, '0x5ca7f3f'), (3, '0x5ca8073')])
        self.assertEqual(jt['kind_name_table'], '0x94a778')

    def test_mutation_supervisor_lea(self):
        with self.assertRaises(ValueError):
            analyze(self.mutated(0x15d5c42, 0, 0x49))

    def test_mutation_method_stub(self):
        with self.assertRaises(ValueError):
            analyze(self.mutated(0x5ca5610, 5, 0x99))

    def test_mutation_vtable_size(self):
        with self.assertRaises(ValueError):
            analyze(self.mutated(VTABLE + 8, 0, 9))

    def test_mutation_error_string(self):
        with self.assertRaises(ValueError):
            analyze(self.mutated(0x94a2f2, 0, ord('X')))

    def test_mutation_adapter_b_method_slot(self):
        with self.assertRaises(ValueError):
            analyze(self.mutated(0x1687267, 2, 0x10))

    def test_mutation_write_body_tag_or(self):
        with self.assertRaises(ValueError):
            analyze(self.mutated(0x1533e1b, 3, 3))

    def test_mutation_thunk_vtable_save(self):
        with self.assertRaises(ValueError):
            analyze(self.mutated(0x1680c44, 2, 0x4c))

    def test_mutation_jump_table(self):
        with self.assertRaises(ValueError):
            analyze(self.mutated(0x948c90, 0, 0xff))


if __name__ == '__main__':
    unittest.main()
