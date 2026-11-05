import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from builder_wrapper_identities_static import (OWNERS, PACKET, PINS,
                                               SHA, SIZE, SLOTS,
                                               TARGET, analyze,
                                               generate,
                                               location_records,
                                               relocations,
                                               run_pins, slot_records,
                                               string_records,
                                               wrapper_a_semantics,
                                               wrapper_b_semantics)
from elf_index import sections


def payload(path):
    return json.loads(Path(path).read_text())


class BuilderWrapperIdentitiesStaticTest(unittest.TestCase):
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
        cls.regenerated = generate(TARGET, tempfile.mkdtemp())

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

    def test_native_regeneration_matches_retained_packet(self):
        self.assertEqual(self.regenerated, self.retained)
        self.assertEqual(self.payload, self.retained)
        regen_dir = Path(tempfile.mkdtemp())
        generate(TARGET, regen_dir)
        names = ['frames.txt'] + [f'{role}.objdump.txt'
                                  for role in OWNERS]
        for name in names:
            self.assertEqual((regen_dir / name).read_bytes(),
                             (PACKET / name).read_bytes(), name)

    def test_thirteen_owners(self):
        self.assertEqual(len(self.payload['owners']), 13)
        roles = {o['role'] for o in self.payload['owners']}
        self.assertEqual(roles, set(OWNERS))

    def test_wrapper_a_identity_locations(self):
        locs = {(l['file'], l['line'], l['col'])
                for l in self.payload['locations']['wrapper_a']}
        self.assertIn(('base/src/lu.rs', 55, 40), locs)
        self.assertIn(('base/src/lu.rs', 58, 76), locs)
        self.assertIn(('base/src/lu.rs', 60, 13), locs)

    def test_wrapper_b_identity_locations(self):
        locs = {(l['file'], l['line'], l['col'])
                for l in self.payload['locations']['wrapper_b']}
        self.assertEqual(
         {x for x in locs if x[0] == 'node/src/utils.rs'},
         {('node/src/utils.rs', 66, 70), ('node/src/utils.rs', 66, 79)})

    def test_builder_slot_census_is_exactly_three_sites(self):
        census = self.payload['builder_slot_census']
        self.assertEqual(census['call_sites'],
                         ['0x15d7026', '0x15d70c2', '0x2ae16f2'])

    def test_each_wrapper_has_only_its_adapter_as_caller(self):
        census = self.payload['reference_census']
        self.assertEqual(census['wrapper_a']['rel32_callers'],
                         [{'site': '0x155fa46',
                           'in_body': '0x155fa10'}])
        self.assertEqual(census['wrapper_b']['rel32_callers'],
                         [{'site': '0x2cd83a2',
                           'in_body': '0x2cd8370'}])
        self.assertEqual(census['adapter_a']['rel32_callers'], [])
        self.assertEqual(census['adapter_b']['rel32_callers'], [])

    def test_wrapper_a_two_arms_two_kinds(self):
        arms = self.payload['wrapper_a']['build_sites']
        self.assertEqual([a['cfg_ctor_kind_argument'] for a in arms],
                         [1, 0])
        errs = self.payload['wrapper_a']['error_sites']
        self.assertEqual([e['location'] for e in errs],
                         ['base/src/lu.rs:55:40',
                          'base/src/lu.rs:58:76'])
        for e in errs:
            self.assertIn('tokio_run', e['message'])

    def test_wrapper_b_single_build_unwrap(self):
        wb = self.payload['wrapper_b']
        self.assertEqual(wb['build_site']['cfg_ctor_kind_argument'], 1)
        self.assertEqual(wb['error_site']['location'],
                         'node/src/utils.rs:66:70')
        self.assertIn('unwrap', wb['error_site']['message'])

    def test_reach_chains(self):
        chain = self.payload['reach_chains']
        self.assertIn('0x6400548', chain['wrapper_a_reach'])
        self.assertIn('edi = 0', chain['wrapper_a_reach'])
        self.assertIn('__libc_start_main', chain['wrapper_b_reach'])
        self.assertIn('0x2cd83a2', chain['wrapper_b_reach'])

    def test_slots(self):
        slots = {s['slot']: s for s in self.payload['slots']}
        self.assertEqual(slots['0x64e1760']['target'], '0x5cf9600')
        self.assertEqual(slots['0x64df508']['symbol'], 'memcpy')
        self.assertEqual(slots['0x64df458']['symbol'],
                         '__libc_start_main')
        self.assertEqual(len(self.payload['slots']), len(SLOTS))

    def test_mutation_wrapper_a_builder_slot_call(self):
        data = self.mutated(0x15d7026, 0, 0x90)
        with self.assertRaises(ValueError):
            wrapper_a_semantics(data)

    def test_mutation_wrapper_a_u16_store(self):
        data = self.mutated(0x15d700c, 9, 0x02)
        with self.assertRaises(ValueError):
            wrapper_a_semantics(data)

    def test_mutation_wrapper_b_unwrap_location(self):
        data = self.mutated(0x2ae17f1, 3, 0x00)
        with self.assertRaises(ValueError):
            wrapper_b_semantics(data)

    def test_mutation_lu_location_line(self):
        # Location struct 0x6401510 line field at +0x10.
        data = self.mutated(0x6401510, 0x10, 0x38)
        with self.assertRaises(ValueError):
            location_records(data, relocations(data),
                             {0x6401510: ('base/src/lu.rs', 55, 40)})

    def test_mutation_expect_message(self):
        data = self.mutated(0x469c40, 0, ord('X'))
        with self.assertRaises(ValueError):
            string_records(data)

    def test_mutation_builder_slot_relocation(self):
        data = bytearray(self.data)
        sec = next(s for s in sections(self.data)
                   if s['name'] == '.rela.dyn')
        import struct as _st
        hit = None
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            r_offset, _, _ = _st.unpack_from('<QQq', self.data, off)
            if r_offset == 0x64e1760:
                hit = off
                break
        self.assertIsNotNone(hit)
        data[hit + 16] ^= 0x01  # addend low byte
        with self.assertRaises(ValueError):
            slot_records(bytes(data), relocations(bytes(data)))

    def test_mutation_start_main_pointer(self):
        data = self.mutated(0x1419318, 3, 0x00)
        with self.assertRaises(ValueError):
            run_pins(data, 'entry_start')


if __name__ == '__main__':
    unittest.main()
