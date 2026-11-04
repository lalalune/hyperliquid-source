import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from limit_writers_static import (OWNERS, PACKET, SHA, SIZE,
                                  TARGET, analyze, generate)
from elf_index import sections


def payload(path):
    return json.loads(Path(path).read_text())


class LimitWritersStaticTest(unittest.TestCase):
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

    def mutated(self, va, delta=0):
        data = bytearray(self.data)
        offset = self.offset_of(va)
        data[offset + delta] ^= 0xFF
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
        for name in ('frames.txt', 'record_helper_b.objdump.txt'):
            self.assertEqual((regen_dir / name).read_bytes(),
                             (PACKET / name).read_bytes(), name)

    def test_five_owners(self):
        self.assertEqual(len(self.payload['owners']), 5)
        roles = {o['role'] for o in self.payload['owners']}
        self.assertEqual(roles, set(OWNERS))

    def test_bulk_limit_is_byte_selected(self):
        text = self.payload['bulk_limit_value']
        self.assertIn('1000', text)
        self.assertIn('4000000000', text)
        for role in ('bulk_a', 'bulk_b'):
            d = self.payload['dispatchers'][role]
            self.assertIn('entry rsi', d['object'], role)
        self.assertEqual(
            self.payload['dispatchers']['bulk_a']['limit_field'],
            '+0x220')
        self.assertEqual(
            self.payload['dispatchers']['bulk_b']['limit_field'],
            '+0xc40')

    def test_twin_limit_formula(self):
        text = self.payload['twin_limit_value']
        for needle in ('120', '10000', '1000000000', '10000000'):
            self.assertIn(needle, text)
        for role in ('twin_a', 'twin_b'):
            d = self.payload['dispatchers'][role]
            self.assertEqual(d['case_values']['tag_2'], 120, role)
            self.assertEqual(d['case_values']['tag_1'], 10000,
                             role)
        self.assertEqual(
            self.payload['dispatchers']['twin_a']['limit_field'],
            '+0x180')
        self.assertEqual(
            self.payload['dispatchers']['twin_b']['limit_field'],
            '+0xa60')

    def test_caller_census(self):
        census = self.payload['call_census']
        self.assertEqual(
            len(census['top_bulk_a']['direct_calls']), 2)
        self.assertEqual(
            len(census['top_twin_a']['direct_calls']), 2)
        self.assertEqual(
            len(census['top_bulk_b']['direct_calls']), 1)
        self.assertEqual(
            len(census['top_twin_b']['direct_calls']), 2)
        for name, rec in census.items():
            self.assertEqual(rec['lea_references'], [], name)

    def test_record_helper_b_never_stores_first_qword(self):
        rec = self.payload['record_helper_b']
        self.assertNotIn('+0x0', rec['stores'])
        self.assertIn('no store to +0x0', rec['first_qword'])

    def test_tail_slots(self):
        self.assertEqual(len(self.payload['tail_slots']), 8)

    def test_counterfactual_final_store_bulk_a(self):
        with self.assertRaises(ValueError):
            analyze(self.mutated(0x2b6874d, 3))

    def test_counterfactual_bulk_selection(self):
        with self.assertRaises(ValueError):
            analyze(self.mutated(0x2b686fc, 1))

    def test_counterfactual_twin_case_constant(self):
        with self.assertRaises(ValueError):
            analyze(self.mutated(0x2b6a82e, 2))

    def test_counterfactual_twin_limit_load(self):
        with self.assertRaises(ValueError):
            analyze(self.mutated(0x5a6b881, 3))

    def test_counterfactual_tail_slot(self):
        with self.assertRaises(ValueError):
            analyze(self.mutated(0x604ac4 + 40, 0))


if __name__ == '__main__':
    unittest.main()
