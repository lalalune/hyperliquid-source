import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from accessor_parents import (PACKET, SHA256, SIZE, TARGET, analyze)


def payload(path):
    return json.loads(Path(path).read_text())


class AccessorParentsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TARGET.exists() or TARGET.stat().st_size != SIZE:
            raise unittest.SkipTest('pinned node115 target is not '
                                    'materialised')
        cls.data = TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != SHA256:
            raise unittest.SkipTest('target digest is not the '
                                    'pinned node115 distribution')
        cls.retained = payload(PACKET / 'records.json')
        cls.payload = analyze(cls.data)

    def test_retained_records_match_binary(self):
        self.assertEqual(self.retained, self.payload)

    def test_error_layout_slots(self):
        offsets = [row['offset']
                   for row in self.payload['error_vtable_layout']]
        self.assertEqual(offsets, ['0x18', '0x20', '0x28', '0x30',
                                   '0x38', '0x40', '0x48', '0x50'])
        self.assertEqual(self.payload['description_text'],
                         'description() is deprecated; use Display')

    def test_enum_parents_are_two_error_types(self):
        parents = {p['vtable']: p
                   for p in self.payload['enum_parents']}
        self.assertEqual(sorted(parents),
                         ['0x63f9150', '0x63f9240', '0x640e648',
                          '0x644e7f8', '0x64c7438'])
        for base, size in (('0x63f9150', 32), ('0x64c7438', 32),
                           ('0x63f9240', 40), ('0x640e648', 40),
                           ('0x644e7f8', 40)):
            self.assertEqual(parents[base]['self_size'], size)
        self.assertTrue(parents['0x63f9150']['identity']
                        .startswith('openssl::ssl::Error'))
        self.assertTrue(parents['0x64c7438']['identity']
                        .startswith('openssl::ssl::Error'))
        for base in ('0x63f9240', '0x640e648', '0x644e7f8'):
            self.assertIn('native-tls', parents[base]['identity'])

    def test_type_id_constant_is_per_type(self):
        consts = {p['vtable']: p['slots']['0x38']['type_id_const']
                  for p in self.payload['enum_parents']}
        self.assertEqual(consts['0x63f9150'], consts['0x64c7438'])
        self.assertEqual(consts['0x63f9240'], consts['0x640e648'])
        self.assertEqual(consts['0x63f9240'], consts['0x644e7f8'])
        self.assertNotEqual(consts['0x63f9150'], consts['0x63f9240'])

    def test_error_stack_is_a_leaf_error(self):
        es = self.payload['error_stack_vtable']
        self.assertEqual(es['vtable'], '0x63f8fd0')
        self.assertEqual(es['self_size'], 24)
        self.assertEqual(es['slots']['0x30']['target'], '0x14c5840')
        self.assertEqual(es['slots']['0x48']['target'], '0x14c5840')
        self.assertEqual(es['identity'], 'openssl::error::ErrorStack')

    def test_field_parents_share_one_subtrait(self):
        parents = {p['vtable']: p
                   for p in self.payload['field_parents']}
        self.assertEqual(sorted(parents),
                         ['0x63fa140', '0x6444b60', '0x64845c0',
                          '0x6494f80', '0x6496a80', '0x649e3f0'])
        groups = {b: p['groups'] for b, p in parents.items()}
        self.assertEqual(groups, {'0x6444b60': 8, '0x64845c0': 4,
                                  '0x6494f80': 2, '0x6496a80': 4,
                                  '0x649e3f0': 7, '0x63fa140': 15})
        for p in parents.values():
            acc = p['field_accessor']
            self.assertEqual(acc['field_offset'], '0x38')
            self.assertEqual(acc['returns_vtable'], '0x63f8f58')
            self.assertEqual(acc['body_bytes'], 12)

    def test_store_and_clone_census(self):
        stores = self.payload['store_bodies']
        clones = self.payload['clone_bodies']
        self.assertEqual(len(stores), 7)
        self.assertEqual(sum(len(s['sites']) for s in stores), 14)
        self.assertEqual(len(clones), 3)
        self.assertEqual(sum(len(s['sites']) for s in clones), 3)
        big = {s['body']: s['body_bytes'] for s in stores}
        self.assertEqual(big['0x2e7db50'], 3229)

    def test_boundary_is_recorded(self):
        boundary = ' '.join(self.payload['boundary'])
        self.assertIn('not named anywhere in the binary', boundary)
        self.assertIn('not re-claimed', boundary)


if __name__ == '__main__':
    unittest.main()
