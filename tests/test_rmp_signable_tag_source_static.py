import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import rmp_signable_tag_source_static as tagsrc
from elf_index import sections

GENERATED = ('frames.txt', 'ga_a1.objdump.txt', 'ga_a2.objdump.txt',
             'ga_a3.objdump.txt', 'ga_a4.objdump.txt', 'ga_a5.objdump.txt',
             'ga_a5_thunk.objdump.txt', 'ga_a5_feeder.objdump.txt',
             'gb_b1.objdump.txt', 'gb_b2.objdump.txt', 'gb_b3.objdump.txt',
             'gb_b4.objdump.txt', 'gb_b5.objdump.txt', 'gb_b6.objdump.txt',
             'gb_b7.objdump.txt', 'records.json')


def materialized():
    target = ROOT / 'artifacts/node/115/hl-node'
    return (target.exists() and target.stat().st_size == tagsrc.TARGET_SIZE
            and hashlib.sha256(target.read_bytes()).hexdigest() == tagsrc.TARGET_SHA256)


def va_offset(data, va):
    for sec in sections(data):
        if sec['type'] != 8 and sec['address'] <= va < sec['address'] + sec['size']:
            return sec['offset'] + va - sec['address']
    raise AssertionError(f'unmapped {va:#x}')


class RmpSignableTagSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not materialized():
            raise unittest.SkipTest('materialized node115 required')
        cls.data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
        cls.packet = ROOT / 'research/work-items/RE-005-node115-rmp-signable-tag-source'
        cls.records = json.loads((cls.packet / 'records.json').read_text())
        cls.result = tagsrc.analyze(cls.data)

    def test_native_regeneration_matches_the_retained_packet(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'packet'
            tagsrc.generate(ROOT / 'artifacts/node/115/hl-node', out)
            for name in GENERATED:
                self.assertEqual((out / name).read_bytes(), (self.packet / name).read_bytes(), name)

    def test_caller_census(self):
        census = self.records['caller_census']
        tc = census['top_caller']
        self.assertEqual([s['site'] for s in tc],
                         ['0x35c5834', '0x35c9e56', '0x3719afa', '0x3b87de3', '0x4301da7'])
        self.assertEqual([s['owner'] for s in tc],
                         ['ga_a1', 'ga_a2', 'ga_a3', 'ga_a4', 'ga_a5'])
        self.assertEqual([(s['site'], s['owner']) for s in census['ga_a1']],
                         [('0x35ca00e', 'ga_a2'), ('0x3b87f9f', 'ga_a4')])
        self.assertEqual([(s['site'], s['owner_start']) for s in census['ga_a2']],
                         [('0x371d31f', '0x371d280'), ('0x371f41b', '0x371f380')])
        self.assertEqual([(s['site'], s['owner_start']) for s in census['ga_a4']],
                         [('0x3b91432', '0x3b913e0')])
        self.assertEqual(census['ga_a3'], [])
        self.assertEqual([(s['site'], s['kind'], s['owner']) for s in census['ga_a5']],
                         [('0x3d9d167', 'jump', 'ga_a5_thunk')])
        self.assertEqual([(s['site'], s['owner']) for s in census['ga_a5_feeder']],
                         [('0x3ec1c0c', None)])
        self.assertEqual(census['grand_b_caller'], [])
        slot = census['grand_b_caller_slot_references']
        self.assertEqual(len(slot), 12)
        self.assertTrue(all(s['kind'] == 'call' for s in slot))
        by_owner = {}
        for s in slot:
            by_owner[s['owner']] = by_owner.get(s['owner'], 0) + 1
        self.assertEqual(by_owner, {'gb_b1': 1, 'gb_b2': 3, 'gb_b3': 3, 'gb_b4': 2,
                                    'gb_b5': 1, 'gb_b6': 1, 'gb_b7': 1})
        owners = {o['role']: o for o in self.records['owners']}
        self.assertEqual(owners['gb_b2']['bytes'], 11142)
        self.assertEqual(owners['gb_b2']['sha256'],
                         '90ae09003ca680bd4b5f32fec22ee1f7146cc1f67b758f8e2f2ac880545b730b')
        self.assertEqual(owners['ga_a5_feeder']['bytes'], 411)
        self.assertEqual(owners['ga_a5_feeder']['sha256'],
                         'd0c81e4baa052a3ad566b29dbdeca133a834059382dbdb8e00374d2da73f9465')
        self.assertEqual(owners['ga_a5_thunk']['bytes'], 12)
        for role, o in owners.items():
            start, end = int(o['start'], 16), int(o['end'], 16)
            body = tagsrc.read(self.data, start, end - start)
            self.assertEqual(hashlib.sha256(body).hexdigest(), o['sha256'], role)
        table = self.records['wrapper_table_entries']
        self.assertEqual(table['gb_b5']['eight_byte_vas'], ['0x14c218'])
        self.assertEqual(table['gb_b6']['eight_byte_vas'], ['0x14c260'])
        self.assertEqual(table['gb_b7']['eight_byte_vas'], ['0x14c200'])
        self.assertEqual(table['ga_a3']['eight_byte_vas'], [])

    def test_tag_provenance(self):
        ga = self.records['grand_a_tag_provenance']
        self.assertIn('[record +0x28]', ga['ga_a1']['container'])
        self.assertIn('[record +0x60]', ga['ga_a2']['container'])
        self.assertIn('0x37135c8', ga['ga_a5']['writer'])
        self.assertEqual(tagsrc.tag_byte(3), 0x61)
        for tag in (0, 1, 2, 4, 5, 255):
            self.assertEqual(tagsrc.tag_byte(tag), 0x62)
        rule = self.records['serializer_tag_rule']
        self.assertEqual(rule['byte_if_equal'], '0x61')
        self.assertEqual(rule['byte_otherwise'], '0x62')
        gb = self.records['grand_b_tag_provenance']
        self.assertEqual(gb['gb_b5']['call_sites'], ['0x5a70c9e'])
        self.assertIn('0xc4', gb['gb_b5']['record'])
        self.assertIn('0xbd5', gb['gb_b4']['tag_source'])
        self.assertIn('+0x1e8', gb['gb_b2']['tag_source'])

    def mutated(self, va, delta=1):
        data = bytearray(self.data)
        off = va_offset(self.data, va)
        data[off] ^= delta
        return bytes(data)

    def test_counterfactual_ga_a1_container_base_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            tagsrc.analyze(self.mutated(0x35c580d))

    def test_counterfactual_ga_a5_field_copy_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            tagsrc.analyze(self.mutated(0x4301d31))

    def test_counterfactual_feeder_tag_store_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            tagsrc.analyze(self.mutated(0x371359b))

    def test_counterfactual_gb_b5_tag_store_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            tagsrc.analyze(self.mutated(0x5a70c8e))

    def test_counterfactual_gb_b2_object_tag_store_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            tagsrc.analyze(self.mutated(0x2ae44ce))

    def test_counterfactual_gb_b4_tag_load_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            tagsrc.analyze(self.mutated(0x2e09b01))

    def test_counterfactual_gb_b1_pointer_store_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            tagsrc.analyze(self.mutated(0x294af5a))

    def test_counterfactual_slot_displacement_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin|slot'):
            tagsrc.analyze(self.mutated(0x5a70ca0))

    def test_counterfactual_caller_displacement_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'census|byte pin'):
            tagsrc.analyze(self.mutated(0x35c9e57))

    def test_wrong_public_identity_is_rejected_before_output_creation(self):
        with tempfile.TemporaryDirectory() as td:
            wrong = Path(td) / 'wrong'
            wrong.write_bytes(b'not the pinned node')
            out = Path(td) / 'packet'
            with self.assertRaisesRegex(ValueError, 'expected pinned node115'):
                tagsrc.generate(wrong, out)
            self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
