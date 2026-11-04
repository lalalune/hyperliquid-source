import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import rmp_signable_caller_tags_static as tags
from elf_index import sections

ARM_DISCRIMINANTS = ['0x87', '0x91', '0xa3', '0xa8', '0xae', '0xb6', '0xb7', '0xb8',
                     '0xb9', '0xba', '0xbb', '0xbc', '0xc3', '0xc4', '0xc5', '0xcb',
                     '0xcf', '0xd1', '0xd2', '0xd3', '0xdb']


def materialized():
    target = ROOT / 'artifacts/node/115/hl-node'
    return (target.exists() and target.stat().st_size == tags.TARGET_SIZE
            and hashlib.sha256(target.read_bytes()).hexdigest() == tags.TARGET_SHA256)


def va_offset(data, va):
    for sec in sections(data):
        if sec['type'] != 8 and sec['address'] <= va < sec['address'] + sec['size']:
            return sec['offset'] + va - sec['address']
    raise AssertionError(f'unmapped {va:#x}')


class RmpSignableCallerTagsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not materialized():
            raise unittest.SkipTest('materialized node115 required')
        cls.data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
        cls.packet = ROOT / 'research/work-items/RE-005-node115-rmp-signable-caller-tags'
        cls.records = json.loads((cls.packet / 'records.json').read_text())
        cls.result = tags.analyze(cls.data)

    def test_native_regeneration_matches_the_retained_packet(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'packet'
            tags.generate(ROOT / 'artifacts/node/115/hl-node', out)
            for name in ('frames.txt', 'serializer.objdump.txt', 'caller_a.objdump.txt',
                         'caller_b.objdump.txt', 'grand_a.objdump.txt',
                         'grand_b.objdump.txt', 'records.json'):
                self.assertEqual((out / name).read_bytes(), (self.packet / name).read_bytes(), name)

    def test_caller_chain_census(self):
        sites = self.records['caller_call_sites']
        self.assertEqual([s['site'] for s in sites['caller_a']], ['0x36c208b'])
        self.assertEqual(sites['caller_a'][0]['owner'], 'grand_a')
        self.assertEqual([s['site'] for s in sites['caller_b']], ['0x36c5388'])
        self.assertEqual(sites['caller_b'][0]['owner'], 'grand_b')
        owners = {o['role']: o for o in self.records['owners']}
        self.assertEqual(owners['caller_a']['sha256'],
                         'd334db07754d3444527141f0c43ec5316b25cef9dac35cfdb48a6728d6052127')
        self.assertEqual(owners['caller_b']['sha256'],
                         '98513eb74d9449bf469425940d4ae673921f4494e34133e938a9f4f37f324582')
        self.assertEqual(owners['grand_a']['bytes'], 3913)
        self.assertEqual(owners['grand_b']['bytes'], 806)

    def test_tag_provenance(self):
        for role, pad_entries in (('grand_a', 70), ('grand_b', 71)):
            disp = self.records['dispatchers'][role]
            self.assertEqual(disp['table_entries'], 92)
            self.assertEqual(disp['direct_pad']['table_entries'], pad_entries)
            self.assertEqual(disp['arms']['count'], 21)
            self.assertEqual(disp['arms']['discriminants'], ARM_DISCRIMINANTS)
        gate = self.records['dispatchers']['grand_a']['equality_gate']
        self.assertEqual(gate['discriminant'], '0xd7')
        self.assertEqual(tags.tag_byte(3), 0x61)
        for tag in (0, 1, 2, 4, 5, 255):
            self.assertEqual(tags.tag_byte(tag), 0x62)
        rule = self.records['serializer_tag_rule']
        self.assertEqual(rule['byte_if_equal'], '0x61')
        self.assertEqual(rule['byte_otherwise'], '0x62')

    def test_arm_tag_capture_is_uniform(self):
        for role in ('grand_a', 'grand_b'):
            start, end = tags.GRANDS[role]['range']
            body = tags.read(self.data, start, end - start)
            self.assertEqual(len(tags.arm_heads(body, start)), 21)

    def mutated(self, va, delta=1):
        data = bytearray(self.data)
        off = va_offset(self.data, va)
        data[off] ^= delta
        return bytes(data)

    def test_counterfactual_pad_truncation_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            tags.analyze(self.mutated(0x36c2085))

    def test_counterfactual_fallback_tag_restore_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            tags.analyze(self.mutated(0x36c2938))

    def test_counterfactual_arm_capture_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'arm head'):
            tags.analyze(self.mutated(0x36c20ab))

    def test_counterfactual_caller_prefix_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            tags.analyze(self.mutated(0x36aae0a))

    def test_counterfactual_table_entry_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'jump table|equality gate'):
            tags.analyze(self.mutated(0x79a9f0 + 4 * 0x51))

    def test_wrong_public_identity_is_rejected_before_output_creation(self):
        with tempfile.TemporaryDirectory() as td:
            wrong = Path(td) / 'wrong'
            wrong.write_bytes(b'not the pinned node')
            out = Path(td) / 'packet'
            with self.assertRaisesRegex(ValueError, 'expected pinned node115'):
                tags.generate(wrong, out)
            self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
