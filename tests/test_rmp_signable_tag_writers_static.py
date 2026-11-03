import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import rmp_signable_tag_writers_static as writers
from elf_index import sections

GENERATED = ('frames.txt', 'record_constructor.objdump.txt',
             'chain_class_writer.objdump.txt', 'spec_builder.objdump.txt',
             'buffer_converter.objdump.txt', 'b2_tls_caller.objdump.txt',
             'b2_b3_caller.objdump.txt', 'b4_caller_stager.objdump.txt',
             'records.json')


def materialized():
    target = ROOT / 'artifacts/node/115/hl-node'
    return (target.exists() and target.stat().st_size == writers.TARGET_SIZE
            and hashlib.sha256(target.read_bytes()).hexdigest() == writers.TARGET_SHA256)


def va_offset(data, va):
    for sec in sections(data):
        if sec['type'] != 8 and sec['address'] <= va < sec['address'] + sec['size']:
            return sec['offset'] + va - sec['address']
    raise AssertionError(f'unmapped {va:#x}')


class RmpSignableTagWritersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not materialized():
            raise unittest.SkipTest('materialized node115 required')
        cls.data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
        cls.packet = ROOT / 'research/work-items/RE-005-node115-rmp-signable-tag-writers'
        cls.records = json.loads((cls.packet / 'records.json').read_text())
        cls.result = writers.analyze(cls.data)

    def test_native_regeneration_matches_the_retained_packet(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'packet'
            writers.generate(ROOT / 'artifacts/node/115/hl-node', out)
            for name in GENERATED:
                self.assertEqual((out / name).read_bytes(), (self.packet / name).read_bytes(), name)

    def test_owners(self):
        owners = {o['role']: o for o in self.records['owners']}
        self.assertEqual(owners['chain_class_writer']['bytes'], 598)
        self.assertEqual(owners['chain_class_writer']['sha256'],
                         'e69561afd60a4ae323867f1eb25f2a6997c85c488524e15bf0ca9f9fed100e92')
        self.assertEqual(owners['record_constructor']['bytes'], 444)
        self.assertEqual(owners['b4_caller_stager']['bytes'], 5091)
        for role, o in owners.items():
            start, end = int(o['start'], 16), int(o['end'], 16)
            body = writers.read(self.data, start, end - start)
            self.assertEqual(hashlib.sha256(body).hexdigest(), o['sha256'], role)

    def test_slot_bindings(self):
        b = self.records['slot_bindings']
        self.assertEqual(b['0x64e73c8']['target'], '0x564cce0')
        self.assertEqual(b['0x64e73c0']['target'], '0x564d700')
        self.assertEqual(b['0x64e1d08']['target'], '0x163a4b0')
        self.assertEqual(b['0x64df508']['target'], 'memcpy')

    def test_caller_census(self):
        census = self.records['caller_census']
        self.assertEqual([(s['site'], s['owner']) for s in census['b2']],
                         [('0x2ae1a47', 'b2_b3_caller'), ('0x2b40577', 'b2_tls_caller')])
        self.assertEqual([(s['site'], s['owner']) for s in census['b3']],
                         [('0x2ae1eeb', 'b2_b3_caller')])
        self.assertEqual([(s['site'], s['owner']) for s in census['b4']],
                         [('0x2af80c5', 'b4_caller_stager')])
        self.assertEqual([(s['site'], s['owner']) for s in census['conv']],
                         [('0x2cde533', 'gb_b3')])
        self.assertEqual(census['caller_z'], [])
        slots = self.records['slot_census']
        self.assertEqual([(s['site'], s['owner']) for s in slots['chain_class_writer']],
                         [('0x2ae437a', 'gb_b2'), ('0x2b7b73f', 'buffer_converter')])
        self.assertEqual([(s['site'], s['owner']) for s in slots['spec_builder']],
                         [('0x2ae42f5', 'gb_b2'), ('0x2b7b6ac', 'buffer_converter')])
        self.assertEqual(len(slots['record_constructor']), 16)

    def test_chain_classification(self):
        c = self.records['chain_classification']
        self.assertEqual(c['classes'], {'Local': 0, 'Sandbox': 1, 'Testnet': 2, 'Mainnet': 3})
        self.assertEqual(c['field_name'], 'chain')
        self.assertEqual(c['byte_store'], '0x564ceb5')
        self.assertIn('unwrap', c['unmatched_name'])

    def test_trails(self):
        t1 = self.records['trail1_staging_dword']
        self.assertIn('0x564ceb5', t1['writer'])
        self.assertIn('0x163a4db', t1['zeroing_store'])
        self.assertIn('0x2ae447f', t1['b2_staging_store'])
        t2 = self.records['trail2_bd5_byte']
        self.assertEqual(t2['z_d50b0000_occurrences'], 0)
        self.assertEqual(t2['b4_d50b0000_occurrences'], 3)
        self.assertIn('0x2af784b', t2['staging_memcpy'])
        self.assertIn('0xbd8', t2['staging_memcpy'])

    def mutated(self, va, delta=1):
        data = bytearray(self.data)
        off = va_offset(self.data, va)
        data[off] ^= delta
        return bytes(data)

    def test_counterfactual_constructor_zeroing_store_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            writers.analyze(self.mutated(0x163a4db + 3))

    def test_counterfactual_apply_byte_store_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            writers.analyze(self.mutated(0x564ceb5 + 1))

    def test_counterfactual_mainnet_immediate_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            writers.analyze(self.mutated(0x564cd5d + 1))

    def test_counterfactual_chain_name_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'chain field name'):
            writers.analyze(self.mutated(0x92a7be))

    def test_counterfactual_staging_memcpy_length_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            writers.analyze(self.mutated(0x2af7840 + 1))

    def test_counterfactual_b4_bd5_load_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            writers.analyze(self.mutated(0x2e09b01 + 4))

    def test_counterfactual_z_bd5_occurrence_is_load_bearing(self):
        data = bytearray(self.data)
        off = va_offset(self.data, 0x2af8a00)
        data[off:off + 4] = bytes.fromhex('d50b0000')
        with self.assertRaisesRegex(ValueError, '0xbd5'):
            writers.analyze(bytes(data))

    def test_counterfactual_apply_slot_binding_is_load_bearing(self):
        data = bytearray(self.data)
        for off, _typ, _add, add_off, _sym in writers.relocations(self.data):
            if off == 0x64e73c8:
                data[add_off] ^= 1
        with self.assertRaisesRegex(ValueError, 'binding'):
            writers.analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
