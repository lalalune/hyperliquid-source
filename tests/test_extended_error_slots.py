import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from extended_error_slots import (DESC_TEXT, EXPECTED_BASES, FWD_CAUSE,
                                  FWD_SOURCE, PACKET, SHA256, SIZE, TARGET,
                                  TYPEID_CONST, TYPEID_VALUE, WRAPPER_BODY,
                                  WRAPPER_VTABLE, analyze, hx)
from elf_index import sections


def payload(path):
    return json.loads(Path(path).read_text())


class ExtendedErrorSlotsTest(unittest.TestCase):
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

    def offset_of(self, va):
        for s in sections(self.data):
            if (s['type'] != 8 and s['address'] <= va
                    < s['address'] + s['size']):
                return s['offset'] + va - s['address']
        raise AssertionError('unmapped va')

    def mutated(self, va, value):
        data = bytearray(self.data)
        data[self.offset_of(va)] = value
        return bytes(data)

    def test_regeneration_matches_retained_packet(self):
        self.assertEqual(self.payload, self.retained)

    def test_manifest_matches_packet_files(self):
        lines = (PACKET / 'MANIFEST.sha256').read_text().splitlines()
        self.assertTrue(lines)
        for line in lines:
            digest, name = line.split('  ', 1)
            actual = hashlib.sha256(
                (PACKET / name).read_bytes()).hexdigest()
            self.assertEqual(actual, digest, name)

    def test_layout_roles_in_order(self):
        roles = [(e['offset'], e['role']) for e in self.payload['layout']]
        self.assertEqual(roles, [
            ('0x0', 'drop_in_place'), ('0x8', 'size'),
            ('0x10', 'align'), ('0x18', 'Debug::fmt'),
            ('0x20', 'Display::fmt'),
            ('0x28', 'Display supertrait upcast'),
            ('0x30', 'Error::source'), ('0x38', 'Error::type_id'),
            ('0x40', 'Error::description'), ('0x48', 'Error::cause'),
            ('0x50', 'Error::provide')])

    def test_thirteen_extended_vtables(self):
        vtables = self.payload['extended_vtables']
        self.assertEqual([v['base'] for v in vtables],
                         [hx(b) for b in EXPECTED_BASES])
        for v in vtables:
            self.assertEqual(v['slots']['0x30'], hx(FWD_SOURCE))
            self.assertEqual(v['slots']['0x48'], hx(FWD_CAUSE))
            self.assertEqual(v['slots']['0x28'],
                             hx(int(v['base'], 16) - 0x20))

    def test_type_id_bodies_share_one_constant(self):
        bodies = [v['type_id'] for v in self.payload['extended_vtables']]
        self.assertEqual(len({b['body'] for b in bodies}), 13)
        for b in bodies:
            self.assertEqual(b['extent'], 14)
            self.assertEqual(b['const_va'], hx(TYPEID_CONST))
            self.assertEqual(b['const_value'], TYPEID_VALUE)
        self.assertEqual(self.payload['type_id_constant'],
                         {'address': hx(TYPEID_CONST),
                          'value': TYPEID_VALUE})

    def test_description_bodies_share_one_string(self):
        bodies = [v['description']
                  for v in self.payload['extended_vtables']]
        self.assertEqual(len({b['str_va'] for b in bodies}), 13)
        for b in bodies:
            self.assertEqual(b['length'], len(DESC_TEXT))
            self.assertEqual(b['text'], DESC_TEXT.decode())

    def test_provide_bodies_are_single_ret(self):
        bodies = [v['provide'] for v in self.payload['extended_vtables']]
        self.assertEqual(len({b['body'] for b in bodies}), 13)
        for b in bodies:
            self.assertEqual(b['extent'], 1)

    def test_forwarders(self):
        fwd = self.payload['forwarders']
        self.assertEqual(fwd['source'], {'body': hx(FWD_SOURCE),
                                         'extent': 41,
                                         'call_disp': '0x30'})
        self.assertEqual(fwd['cause'], {'body': hx(FWD_CAUSE),
                                        'extent': 41,
                                        'call_disp': '0x48'})

    def test_wrapper_discriminator(self):
        disc = self.payload['discriminator']
        self.assertEqual(disc['wrapper_vtable'], hx(WRAPPER_VTABLE))
        self.assertEqual(disc['shared_body'], hx(WRAPPER_BODY))
        self.assertEqual(disc['delegates_via'], '0x30')
        self.assertEqual(disc['never_via'], '0x48')

    def test_census_counts(self):
        cen = self.payload['census']
        self.assertEqual(cen['sane_vtables'], 108)
        self.assertEqual(cen['both_none'], 29)
        self.assertEqual(cen['shared_body'], 13)
        self.assertIn(hx(WRAPPER_VTABLE), cen['shared_bases'])

    def test_mutation_of_type_id_constant_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze(self.mutated(TYPEID_CONST, 0x00))

    def test_mutation_of_description_string_is_rejected(self):
        first = self.payload['extended_vtables'][0]['description']
        with self.assertRaises(ValueError):
            analyze(self.mutated(int(first['str_va'], 16), ord('X')))

    def test_mutation_of_provide_body_is_rejected(self):
        first = self.payload['extended_vtables'][0]['provide']
        with self.assertRaises(ValueError):
            analyze(self.mutated(int(first['body'], 16), 0x90))

    def test_mutation_of_wrapper_call_is_rejected(self):
        # the `call *0x30(%rax)` displacement byte inside the
        # wrapper body: flipping it to 0x48 must break the pin
        call_disp_va = WRAPPER_BODY + 0x30
        with self.assertRaises(ValueError):
            analyze(self.mutated(call_disp_va, 0x48))


if __name__ == '__main__':
    unittest.main()
