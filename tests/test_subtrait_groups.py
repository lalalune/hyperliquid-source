import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from subtrait_groups import (FAMILY, IO_TYPE_ID, KEY_EXCEPTIONS,
                             PACKET, SHA256, SIZE, TARGET, analyze)


def payload(path):
    return json.loads(Path(path).read_text())


class SubtraitGroupsTest(unittest.TestCase):
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

    def test_family_has_eight_members(self):
        members = {m['vtable']: m for m in self.payload['members']}
        self.assertEqual(sorted(members),
                         sorted(hex(b) for b in FAMILY))
        counts = {b: m['groups_count'] for b, m in members.items()}
        self.assertEqual(counts,
                         {hex(b): k for b, k in FAMILY.items()})
        self.assertEqual(sum(counts.values()), 46)

    def test_every_group_probes_the_same_field(self):
        for m in self.payload['members']:
            for g in m['groups']:
                self.assertEqual(g['accessor']['field_offset'],
                                 '0x38')
                self.assertEqual(g['keyed_lookup']['field_offset'],
                                 '0x38')
                self.assertEqual(g['accessor']['body_bytes'], 12)
                self.assertEqual(g['pair_return']['body_bytes'], 11)
                self.assertEqual(g['keyed_lookup']['body_bytes'],
                                 33)
                self.assertEqual(g['zero_slot4']['body_bytes'], 3)

    def test_one_self_group_and_io_groups(self):
        for m in self.payload['members']:
            g = m['groups'][m['self_group_index']]
            self.assertTrue(g['pair_return']['is_self_vtable'])
            self.assertEqual(g['pair_return']['returns_type_id'],
                             m['type_id_const'])
        io_counts = {m['vtable']: len(m['io_group_indices'])
                     for m in self.payload['members']}
        for base in ('0x63fa140', '0x6444b60', '0x64845c0',
                     '0x6494f80', '0x6496a80', '0x649e3f0'):
            self.assertEqual(io_counts[base], 1)
        self.assertEqual(io_counts['0x6408b48'], 0)
        self.assertEqual(io_counts['0x640a448'], 0)

    def test_slot3_and_own58_sizes_follow_pair_types(self):
        for m in self.payload['members']:
            first = m['groups'][0]
            self.assertEqual(
                m['own_method_0x58']['dealloc_size'],
                first['pair_return']['returns_size'])
            for g in m['groups']:
                self.assertEqual(
                    g['drop_shim_slot3']['dealloc_size'],
                    g['pair_return']['returns_size'])

    def test_slot5_rule_has_no_exceptions(self):
        rule = self.payload['slot5_rule']
        self.assertEqual(rule['checked'], 38)
        self.assertEqual(rule['conforming'], 38)
        self.assertEqual(rule['exceptions'], [])

    def test_keys_are_type_ids_except_two_shared_roles(self):
        roles = {r['key']: r for r in self.payload['roles']}
        self.assertEqual(len(roles), 20)
        for key, role in roles.items():
            if key in KEY_EXCEPTIONS:
                self.assertEqual(role['key_va'],
                                 KEY_EXCEPTIONS[key])
                self.assertNotEqual(key,
                                    role['accessor_type_id'])
            else:
                self.assertEqual(key, role['accessor_type_id'])
        io = [r for r in roles.values()
              if r['accessor_type_id'] == IO_TYPE_ID]
        self.assertEqual(len(io), 1)
        self.assertEqual(io[0]['key'], IO_TYPE_ID)

    def test_boundary_is_recorded(self):
        boundary = ' '.join(self.payload['boundary'])
        self.assertIn('source-level name is not in the binary',
                      boundary)
        self.assertIn('boundary cell', boundary)
        for m in self.payload['members']:
            self.assertIsNone(
                m['groups'][-1]['drop_shim_slot5'])


if __name__ == '__main__':
    unittest.main()
