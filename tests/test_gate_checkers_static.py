import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from artifacts import ROOT  # noqa: E402
import gate_checkers_static as gc  # noqa: E402

TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
MATERIALISED = (TARGET.exists() and not TARGET.read_bytes()[:64]
                .startswith(b'version https://git-lfs.github.com'))


def load():
    return TARGET.read_bytes()


@unittest.skipUnless(MATERIALISED, 'node artifact not materialised')
class GateCheckersPacketTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = load()
        cls.records = gc.analyze(cls.data)

    def test_artifact_and_owners(self):
        r = self.records['owners']
        self.assertEqual(self.records['artifact']['size'],
                         105896032)
        self.assertEqual(r['checker_a']['bytes'], 955)
        self.assertEqual(r['checker_b']['bytes'], 832)
        self.assertEqual(r['checker_a_clone']['bytes'], 955)
        self.assertEqual(r['checker_b_clone']['bytes'], 832)
        self.assertEqual(r['builder_a']['bytes'], 409)
        self.assertEqual(r['predicate_a']['bytes'], 703)
        self.assertEqual(r['keyhash_b']['bytes'], 742)
        self.assertEqual(r['lookup_b']['bytes'], 327)
        self.assertEqual(r['method_b']['bytes'], 377)
        self.assertEqual(r['helper_b720']['bytes'], 227)
        self.assertEqual(r['helper_b720_clone']['bytes'], 227)
        self.assertEqual(r['drop_pair']['bytes'], 136)
        self.assertEqual(r['drop_pair_a']['bytes'], 136)
        self.assertEqual(
            r['checker_a']['sha256'],
            'ff59e02e9d3e078985ba6e3b58d8f64f3a6ed5171f2120d314'
            'cbb5a3c744daed')
        self.assertEqual(
            r['checker_b']['sha256'],
            'c2dd071311e360249b28d2cacda998b6727b2e1d57a74ebde9'
            '65c96325b6c6fa')
        self.assertEqual(self.records['exported_bodies'],
                         list(gc.EXPORTED))

    def test_tables_and_clone_offsets(self):
        t = self.records['tables']
        self.assertEqual(
            t['checker_a']['state_90']['entries'],
            {'0x0': '0x2c7f38e', '0x1': '0x2c7f664',
             '0x2': '0x2c7f657', '0x3': '0x2c7f3ad'})
        self.assertEqual(
            t['checker_b']['substate_90']['entries']['0x3'],
            '0x2c7fb72')
        for clone, orig in gc.CLONE_OF.items():
            for name in t[orig]:
                self.assertEqual(t[clone][name]['offsets'],
                                 t[orig][name]['offsets'])

    def test_clone_streams_equal(self):
        eq = self.records['clone_equivalence']
        for key, entry in eq.items():
            self.assertTrue(entry['equal'], key)
            self.assertGreater(entry['normalised_lines'], 50)

    def test_slots_and_vtable(self):
        s = self.records['slots']
        self.assertEqual(s['0x64e13a0']['addend'], '0x5cf2150')
        self.assertEqual(s['0x64e0858']['addend'], '0x5cf2d30')
        self.assertEqual(s['0x64dfe80']['addend'], '0x5cdb250')
        self.assertEqual(s['0x64df508']['symbol'], 'memcpy')
        self.assertEqual(s['vtable_b']['entries']['0x18'],
                         '0x2b15630')
        self.assertEqual(s['vtable_b']['entries']['0x20'],
                         '0x2b19230')
        self.assertEqual(
            s['lu_statics']['0x644dc28']['packed'], '0x50000004b')

    def test_call_pins(self):
        c = self.records['pins']['calls']
        self.assertEqual(c['0x2cbb490'], '0x2c7fa40')
        self.assertEqual(c['0x2cbb717'], '0x2c7f360')
        self.assertEqual(c['0x2cb9923'], '0x2c7f360')
        self.assertEqual(self.records['pins']['r14_f64']['value'],
                         86400000000.0)

    def test_gate_census_key_stores(self):
        g = self.records['gate_census']['gate_c']
        self.assertEqual(g['0x150']['stores'], ['0x2cbb6f9'])
        self.assertEqual(g['0x1e0']['stores'], ['0x2cbb701'])
        self.assertNotIn('stores', g['0x1d8'])
        self.assertEqual(g['0x130']['stores'], ['0x2cbb610'])
        self.assertEqual(g['0x128']['stores'],
                         ['0x2cb7245', '0x2cbb552'])

    def test_strings(self):
        st = self.records['strings']
        self.assertEqual(st['lu_rs']['value'], 'base/src/lu.rs')
        self.assertEqual(st['async_wait_inner']['value'],
                         'async_wait_inner')
        self.assertEqual(st['joinhandle_panic']['value'],
                         'JoinHandle polled after completion')
        self.assertEqual(st['gate_doubles']['0x458d50'], 1e9)
        self.assertEqual(st['gate_doubles']['0x459568'], 600.0)

    def test_canonical_regeneration(self):
        expected = json.loads((gc.OUT / 'records.json').read_text())
        self.assertEqual(self.records, expected)
        for role in gc.EXPORTED:
            self.assertEqual(
                (gc.OUT / f'{role}.objdump.txt').read_text(),
                gc.exports(self.data, role))
        self.assertEqual((gc.OUT / 'frames.txt').read_text(),
                         ''.join(gc.frame_lines(self.data)))

    def test_call_pin_mutation_fails(self):
        data = bytearray(self.data)
        off, _ = gc.read(0x2CBB717, bytes(data), 4)
        data[off] ^= 0x01
        with self.assertRaises(ValueError):
            gc.analyze(bytes(data))

    def test_table_entry_mutation_fails(self):
        data = bytearray(self.data)
        off, _ = gc.read(0x60AF90 + 3 * 4, bytes(data), 4)
        data[off] ^= 0x01
        with self.assertRaises(ValueError):
            gc.analyze(bytes(data))

    def test_converging_store_mutation_fails(self):
        data = bytearray(self.data)
        off, _ = gc.read(0x2CBB701, bytes(data), 4)
        data[off] ^= 0xFF
        with self.assertRaises(ValueError):
            gc.analyze(bytes(data))

    def test_string_mutation_fails(self):
        data = bytearray(self.data)
        off, _ = gc.read(0x451330, bytes(data), 1)
        data[off] = ord('X')
        with self.assertRaises(ValueError):
            gc.analyze(bytes(data))

    def test_slot_relocation_mutation_fails(self):
        data = bytearray(self.data)
        raw = bytes(data)
        for section in gc.sections(raw):
            if section['name'] != '.rela.dyn':
                continue
            for i in range(section['offset'],
                           section['offset'] + section['size'], 24):
                off, _, _ = struct.unpack_from('<QQq', raw, i)
                if off == 0x64E13A0:
                    struct.pack_into('<q', data, i + 16, 0x5CF2151)
        with self.assertRaises(ValueError):
            gc.analyze(bytes(data))


if __name__ == '__main__':
    unittest.main()
