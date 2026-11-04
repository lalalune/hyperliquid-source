import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from artifacts import ROOT  # noqa: E402
import key_consumers_static as kc  # noqa: E402

TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
MATERIALISED = (TARGET.exists() and not TARGET.read_bytes()[:64]
                .startswith(b'version https://git-lfs.github.com'))


def load():
    return TARGET.read_bytes()


@unittest.skipUnless(MATERIALISED, 'node artifact not materialised')
class KeyConsumersPacketTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = load()
        cls.records = kc.analyze(cls.data)

    def test_artifact_and_owners(self):
        r = self.records['owners']
        self.assertEqual(self.records['artifact']['size'], 105896032)
        self.assertEqual(r['gate_c']['end'], '0x2cbbbdf')
        self.assertEqual(
            r['gate_c']['sha256'],
            '62835f8a447ea034c30a4fa0663abad74226444817882c469f'
            '883d7d92e4a8d0')
        self.assertEqual(r['gate_a']['bytes'], 22372)
        self.assertEqual(r['key_lookup']['bytes'], 1541)
        self.assertEqual(r['cmp_helper']['bytes'], 247)
        self.assertEqual(self.records['exported_bodies'],
                         ['builder_c', 'lookup_d', 'key_lookup',
                          'cmp_helper'])

    def test_gate_callers(self):
        c = self.records['gate_call_census']
        self.assertEqual(c['gate_c'], ['0x2cde6f4', '0x2cdf58b'])
        self.assertEqual(c['gate_a'], ['0x2ae4627', '0x2ae548c'])
        self.assertEqual(c['rela_addends_naming_gates'], [])

    def test_key_slot_sites(self):
        c = self.records['key_slot_census']
        self.assertEqual(c['callee'], '0x150ad00')
        self.assertEqual(c['rip_relative_call_sites'],
                         ['0x2ae4580', '0x2aeb2f7', '0x2cb6907',
                          '0x2cde645'])

    def test_gate_census_key_slots(self):
        g = self.records['gate_census']['gate_c']
        self.assertEqual(g['stores']['rbx']['0x88'],
                         ['0x2cb6798', '0x2cb6bdf'])
        self.assertEqual(g['stores']['rbx']['0x78'],
                         ['0x2cb6849', '0x2cb6bd6'])
        self.assertEqual(g['loads']['rbx']['0x78'],
                         ['0x2cb68f6', '0x2cbb0ba'])
        self.assertEqual(g['loads']['rbx']['0x88'], ['0x2cb6827'])
        a = self.records['gate_census']['gate_a']
        self.assertEqual(a['stores']['rbx']['0x78'],
                         ['0x2aeb239', '0x2aeb5b6'])
        self.assertEqual(a['loads']['rbx']['0x80'],
                         ['0x2aeb2ea', '0x2aefb29'])

    def test_shaper_census_and_absence(self):
        s = self.records['shaper_census']
        self.assertTrue(
            self.records['shaper_emb_key_offsets_untouched'])
        self.assertEqual(s['lvl3_c']['loads']['r13']['0xa0'],
                         ['0x2cde564'])
        self.assertEqual(s['lvl3_c']['stores']['r13']['0xa8'],
                         ['0x2cde58a'])
        self.assertEqual(s['lvl4_a']['stores']['rbx']['0x290'],
                         ['0x2ae460b', '0x2ae5470'])
        self.assertEqual(s['lvl4_a']['loads']['rbx']['0x88'],
                         ['0x2ae6c96'])

    def test_lookup_dispatch(self):
        lk = self.records['key_lookup']
        self.assertEqual(lk['argument_bracket_accesses'], {})
        self.assertEqual(lk['jump_table']['entries']['0x0'],
                         '0x150b209')
        self.assertEqual(lk['jump_table']['entries']['0x3'],
                         '0x150adb7')
        self.assertEqual(lk['tag_reference_fields'],
                         {'0x1': '0xd0', '0x2': '0xb8',
                          '0x3': '0xa0'})
        self.assertEqual(lk['direct_calls']['0x150b110'],
                         '0x14c2b50')

    def test_helper(self):
        h = self.records['cmp_helper']
        self.assertEqual(h['direct_calls']['0x14c2c18'],
                         '0x154c4e0')
        self.assertEqual(
            h['rip_targets']['0x14c2b79'],
            {'kind': 'call', 'target': '0x64dffe0'})

    def test_globals_and_strings(self):
        g = self.records['globals']
        self.assertEqual(g['key_global']['reference_fields']
                         ['0xd0'], '0x0')
        self.assertEqual(g['crit_global']['qwords']['0x10'],
                         '0xe')
        s = self.records['strings']
        self.assertEqual(s['hl_node_gate_c']['value'], 'hl-node')
        self.assertEqual(s['hl_node_gate_a']['va'], '0x605ccd')
        self.assertEqual(s['crit_message']['prefix'],
                         'crit msg initialization not applied')

    def test_canonical_regeneration(self):
        expected = json.loads(
            (kc.OUT / 'records.json').read_text())
        self.assertEqual(self.records, expected)
        for role in kc.EXPORTED:
            self.assertEqual(
                (kc.OUT / f'{role}.objdump.txt').read_text(),
                kc.exports(self.data, role))
        self.assertEqual(
            (kc.OUT / 'frames.txt').read_text(),
            ''.join(kc.frame_lines(self.data)))

    def test_gate_merge_store_mutation_fails(self):
        data = bytearray(self.data)
        off, _ = kc.read(0x2CB6849, bytes(data), 4)
        data[off] ^= 0x01
        with self.assertRaises(ValueError):
            kc.analyze(bytes(data))

    def test_jump_table_mutation_fails(self):
        data = bytearray(self.data)
        off, _ = kc.read(0x465704, bytes(data), 4)
        data[off] ^= 0x01
        with self.assertRaises(ValueError):
            kc.analyze(bytes(data))

    def test_key_string_mutation_fails(self):
        data = bytearray(self.data)
        off, _ = kc.read(0x60F0B2, bytes(data), 1)
        data[off] = ord('x')
        with self.assertRaises(ValueError):
            kc.analyze(bytes(data))

    def test_key_slot_relocation_mutation_fails(self):
        data = bytearray(self.data)
        raw = bytes(data)
        for section in kc.sections(raw):
            if section['name'] != '.rela.dyn':
                continue
            for i in range(section['offset'],
                           section['offset'] + section['size'], 24):
                off, _, _ = struct.unpack_from('<QQq', raw, i)
                if off == kc.KEY_SLOT:
                    struct.pack_into('<q', data, i + 16, 0x150AD01)
        with self.assertRaises(ValueError):
            kc.analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
