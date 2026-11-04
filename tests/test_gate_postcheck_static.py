import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from artifacts import ROOT  # noqa: E402
import gate_postcheck_static as gp  # noqa: E402

TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
MATERIALISED = (TARGET.exists() and not TARGET.read_bytes()[:64]
                .startswith(b'version https://git-lfs.github.com'))


def load():
    return TARGET.read_bytes()


@unittest.skipUnless(MATERIALISED, 'node artifact not materialised')
class GatePostcheckPacketTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = load()
        cls.records = gp.analyze(cls.data)

    def test_artifact_and_owners(self):
        r = self.records['owners']
        self.assertEqual(self.records['artifact']['size'], 105896032)
        self.assertEqual(r['gate_c']['end'], '0x2cbbbdf')
        self.assertEqual(
            r['gate_c']['sha256'],
            '62835f8a447ea034c30a4fa0663abad74226444817882c469f'
            '883d7d92e4a8d0')
        self.assertEqual(r['gate_a']['bytes'], 22372)
        self.assertEqual(r['checker_a']['bytes'], 955)
        self.assertEqual(r['checker_b']['bytes'], 832)
        self.assertEqual(r['drop_pair']['bytes'], 136)
        self.assertEqual(r['drop_ad0']['bytes'], 471)
        self.assertEqual(r['builder_11c']['bytes'], 1820)
        self.assertEqual(r['phase90_call']['bytes'], 1136)
        self.assertEqual(self.records['exported_bodies'],
                         ['checker_a', 'checker_b', 'drop_pair',
                          'drop_ad0', 'builder_11c', 'phase90_call'])

    def test_jump_tables(self):
        t = self.records['tables']
        self.assertEqual(t['gate_c']['entry']['entries'],
                         {'0x0': '0x2cb656e', '0x1': '0x2cb9f1d',
                          '0x2': '0x2cb9f10', '0x3': '0x2cb67dd',
                          '0x4': '0x2cb6b40'})
        self.assertEqual(
            t['gate_c']['sub_120']['entries']['0x3'], '0x2cbb481')
        self.assertEqual(
            t['gate_c']['sub_120']['entries']['0x4'], '0x2cbb708')
        self.assertEqual(
            t['gate_a']['sub_120']['entries']['0x3'], '0x2aefee7')
        self.assertEqual(
            t['gate_a']['sub_120']['entries']['0x4'], '0x2af016e')
        self.assertEqual(len(t['gate_c']['sub_ad0']['entries']), 32)
        self.assertEqual(len(t['gate_a']['sub_ad0']['entries']), 28)
        self.assertEqual(len(t['gate_c']['sub_d0']['entries']), 9)

    def test_exit_funnel(self):
        f = self.records['funnel']
        self.assertEqual(f['gate_c']['ret'], '0x2cbb7e8')
        entries = {(e['site'], e['target'])
                   for e in f['gate_c']['entries']}
        self.assertEqual(entries, {
            ('0x2cbb497', '0x2cbb7c3'), ('0x2cbb71e', '0x2cbb7c7'),
            ('0x2cb8034', '0x2cbb7d4'), ('0x2cb99a7', '0x2cbb7d4'),
            ('0x2cbb7c5', '0x2cbb7c9')})
        self.assertEqual(f['gate_c']['shared_tail_entries'],
                         [{'site': '0x2cb9937',
                           'target': '0x2cb802d', 'kind': 'jmp'}])
        self.assertEqual(f['gate_a']['ret'], '0x2af024e')
        entries_a = {(e['site'], e['target'])
                     for e in f['gate_a']['entries']}
        self.assertEqual(entries_a, {
            ('0x2aefefd', '0x2af0229'), ('0x2af0184', '0x2af022d'),
            ('0x2aeca14', '0x2af023a'), ('0x2aee477', '0x2af023a'),
            ('0x2af022b', '0x2af022f')})
        self.assertNotIn('shared_tail_entries', f['gate_a'])

    def test_late_pair_loads_are_unique(self):
        g = self.records['gate_census']['gate_c']
        self.assertEqual(g['loads']['rbx']['0x78'],
                         ['0x2cb68f6', '0x2cbb0ba'])
        self.assertEqual(g['loads']['rbx']['0x80'],
                         ['0x2cb68fa', '0x2cbb0c3'])
        self.assertEqual(g['leas']['rbx']['0x90'],
                         ['0x2cb6b4e', '0x2cb715f'])
        a = self.records['gate_census']['gate_a']
        self.assertEqual(a['loads']['rbx']['0x78'],
                         ['0x2aeb2e6', '0x2aefb11'])
        self.assertEqual(a['loads']['rbx']['0x80'],
                         ['0x2aeb2ea', '0x2aefb29'])

    def test_postcheck_calls(self):
        c = self.records['postcheck_calls']
        self.assertEqual(c['gate_c']['0x2cb69b2'], '0x2d47710')
        self.assertEqual(c['gate_c']['0x2cb6ac0'], '0x26e11f0')
        self.assertEqual(c['gate_c']['0x2cb6bad'], '0x2c901a0')
        self.assertEqual(c['gate_c']['0x2cbb490'], '0x2c7fa40')
        self.assertEqual(c['gate_c']['0x2cbb717'], '0x2c7f360')
        self.assertEqual(c['gate_c']['0x2cbb76d'], '0x2ca0790')
        self.assertEqual(c['gate_a']['0x2af01d3'], '0x2abc7e0')

    def test_slots_and_strings(self):
        s = self.records['slots']
        self.assertEqual(s['alloc_slot']['callee'], '0x6355830')
        self.assertEqual(s['dealloc_slot']['callee'], '0x635de30')
        self.assertEqual(s['copy_slot']['symbol'], 'memcpy')
        self.assertEqual(s['state_slot']['addend'], '0x64f06c0')
        self.assertEqual(s['state_slot']['relocation_type'], 8)
        st = self.records['strings']
        self.assertEqual(st['naive_dt_panic']['section'], '.rodata')
        self.assertEqual(st['naive_dt_panic']['value'],
                         'Local time out of range for `NaiveDateTime`')
        self.assertEqual(
            st['display_panic']['value'],
            'a Display implementation returned an error unexpectedly')

    def test_canonical_regeneration(self):
        expected = json.loads((gp.OUT / 'records.json').read_text())
        self.assertEqual(self.records, expected)
        for role in gp.EXPORTED:
            self.assertEqual(
                (gp.OUT / f'{role}.objdump.txt').read_text(),
                gp.exports(self.data, role))
        self.assertEqual((gp.OUT / 'frames.txt').read_text(),
                         ''.join(gp.frame_lines(self.data)))

    def test_funnel_pin_mutation_fails(self):
        data = bytearray(self.data)
        off, _ = gp.read(0x2CBB717, bytes(data), 4)
        data[off] ^= 0x01
        with self.assertRaises(ValueError):
            gp.analyze(bytes(data))

    def test_table_entry_mutation_fails(self):
        data = bytearray(self.data)
        off, _ = gp.read(0x60BBFC + 3 * 4, bytes(data), 4)
        data[off] ^= 0x01
        with self.assertRaises(ValueError):
            gp.analyze(bytes(data))

    def test_late_load_mutation_fails(self):
        data = bytearray(self.data)
        off, _ = gp.read(0x2CBB0BA, bytes(data), 4)
        data[off] ^= 0xFF
        with self.assertRaises(ValueError):
            gp.analyze(bytes(data))

    def test_string_mutation_fails(self):
        data = bytearray(self.data)
        off, _ = gp.read(0x465AB7, bytes(data), 1)
        data[off] = ord('X')
        with self.assertRaises(ValueError):
            gp.analyze(bytes(data))

    def test_state_slot_relocation_mutation_fails(self):
        data = bytearray(self.data)
        raw = bytes(data)
        for section in gp.sections(raw):
            if section['name'] != '.rela.dyn':
                continue
            for i in range(section['offset'],
                           section['offset'] + section['size'], 24):
                off, _, _ = struct.unpack_from('<QQq', raw, i)
                if off == gp.STATE_SLOT:
                    struct.pack_into('<q', data, i + 16, 0x64F06C1)
        with self.assertRaises(ValueError):
            gp.analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
