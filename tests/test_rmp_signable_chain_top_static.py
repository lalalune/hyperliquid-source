import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import rmp_signable_chain_top_static as top
from elf_index import sections

GENERATED = ('frames.txt', 'serializer.objdump.txt', 'caller_a.objdump.txt',
             'caller_b.objdump.txt', 'grand_a.objdump.txt', 'grand_b.objdump.txt',
             'top.objdump.txt', 'top_caller.objdump.txt',
             'grand_b_caller.objdump.txt', 'records.json')


def materialized():
    target = ROOT / 'artifacts/node/115/hl-node'
    return (target.exists() and target.stat().st_size == top.TARGET_SIZE
            and hashlib.sha256(target.read_bytes()).hexdigest() == top.TARGET_SHA256)


def va_offset(data, va):
    for sec in sections(data):
        if sec['type'] != 8 and sec['address'] <= va < sec['address'] + sec['size']:
            return sec['offset'] + va - sec['address']
    raise AssertionError(f'unmapped {va:#x}')


class RmpSignableChainTopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not materialized():
            raise unittest.SkipTest('materialized node115 required')
        cls.data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
        cls.packet = ROOT / 'research/work-items/RE-005-node115-rmp-signable-chain-top'
        cls.records = json.loads((cls.packet / 'records.json').read_text())
        cls.result = top.analyze(cls.data)

    def test_native_regeneration_matches_the_retained_packet(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'packet'
            top.generate(ROOT / 'artifacts/node/115/hl-node', out)
            for name in GENERATED:
                self.assertEqual((out / name).read_bytes(), (self.packet / name).read_bytes(), name)

    def test_chain_top_census(self):
        sites = self.records['grand_a_call_sites']
        self.assertEqual([s['site'] for s in sites], ['0x37133b3'])
        self.assertEqual(sites[0]['kind'], 'call')
        self.assertEqual(sites[0]['owner'], 'top')
        refs = self.records['grand_b_references']
        self.assertEqual(refs['direct_call_sites'], [])
        self.assertEqual(refs['direct_jump_sites'], [])
        self.assertEqual(refs['rip_relative_references'], [])
        self.assertEqual(len(refs['relocations']), 1)
        self.assertEqual(refs['relocations'][0]['slot'], '0x64e8ed0')
        self.assertEqual(refs['relocations'][0]['type_name'], 'R_X86_64_RELATIVE')
        self.assertEqual(refs['relocations'][0]['addend'], '0x36c5350')
        self.assertEqual([s['site'] for s in refs['slot_references']], ['0x38d9e07'])
        self.assertEqual(refs['slot_references'][0]['owner'], 'grand_b_caller')
        self.assertEqual(refs['raw_occurrences']['eight_byte_file_offsets'], ['0x151258'])
        self.assertEqual(refs['raw_occurrences']['four_byte_file_offsets'], ['0x151258'])
        top_sites = self.records['top_call_sites']
        self.assertEqual([s['site'] for s in top_sites], ['0x3ebdd9e'])
        self.assertEqual(top_sites[0]['owner'], 'top_caller')
        owners = {o['role']: o for o in self.records['owners']}
        self.assertEqual(owners['top']['bytes'], 547)
        self.assertEqual(owners['top']['sha256'],
                         '823b4167a13a0cdd666fb07f12958004b36e0a3505083ff7a3550bcc425d743c')
        self.assertEqual(owners['grand_b_caller']['bytes'], 636)
        self.assertEqual(owners['grand_b_caller']['sha256'],
                         'ce1931ed60cdd5707c385cc7341cf8ae64ae6f1f6baed83abb69116e6c1e156b')
        for role in ('top', 'top_caller', 'grand_b_caller'):
            o = owners[role]
            start, end = int(o['start'], 16), int(o['end'], 16)
            body = top.read(self.data, start, end - start)
            self.assertEqual(hashlib.sha256(body).hexdigest(), o['sha256'], role)
        boundary = self.records['boundary_callers']
        self.assertEqual(len(boundary['top_caller']['direct_call_sites']), 5)
        self.assertEqual(boundary['grand_b_caller']['direct_call_sites'], [])
        self.assertEqual(len(boundary['grand_b_caller']['slot_references']), 12)

    def test_tag_provenance(self):
        prov = self.records['top_tag_provenance']
        self.assertEqual(prov['call_site'], '0x37133b3')
        self.assertEqual(prov['owner'], 'top')
        gb = self.records['grand_b_tag_provenance']
        self.assertEqual(gb['call_site'], '0x38d9e07')
        self.assertEqual(gb['slot'], '0x64e8ed0')
        self.assertEqual(top.tag_byte(3), 0x61)
        for tag in (0, 1, 2, 4, 5, 255):
            self.assertEqual(top.tag_byte(tag), 0x62)
        rule = self.records['serializer_tag_rule']
        self.assertEqual(rule['byte_if_equal'], '0x61')
        self.assertEqual(rule['byte_otherwise'], '0x62')

    def mutated(self, va, delta=1):
        data = bytearray(self.data)
        off = va_offset(self.data, va)
        data[off] ^= delta
        return bytes(data)

    def test_counterfactual_top_tag_load_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            top.analyze(self.mutated(0x371336c))

    def test_counterfactual_top_tag_pointer_field_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            top.analyze(self.mutated(0x371332c))

    def test_counterfactual_grand_b_tag_capture_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            top.analyze(self.mutated(0x38d9c77))

    def test_counterfactual_grand_b_tag_store_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            top.analyze(self.mutated(0x38d9cc5))

    def test_counterfactual_indirect_call_displacement_is_load_bearing(self):
        with self.assertRaisesRegex(ValueError, 'byte pin|slot'):
            top.analyze(self.mutated(0x38d9e0a))

    def test_counterfactual_grand_b_relocation_is_load_bearing(self):
        data = bytearray(self.data)
        data[0x151258] ^= 1
        with self.assertRaisesRegex(ValueError, 'relocation'):
            top.analyze(bytes(data))

    def test_wrong_public_identity_is_rejected_before_output_creation(self):
        with tempfile.TemporaryDirectory() as td:
            wrong = Path(td) / 'wrong'
            wrong.write_bytes(b'not the pinned node')
            out = Path(td) / 'packet'
            with self.assertRaisesRegex(ValueError, 'expected pinned node115'):
                top.generate(wrong, out)
            self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
