import hashlib
import json
import re
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import chain_origin_writers_static as pkt

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-005-node115-chain-origin-writers'
ARTIFACT = ROOT / 'artifacts/node/115/hl-node'


def mutated(offset, chunk):
    data = bytearray(ARTIFACT.read_bytes())
    data[offset:offset + len(chunk)] = chunk
    return bytes(data)


def file_offset(va):
    return va - 0x1000


def data_file_offset(data, va):
    for sec in pkt.sections(data):
        if sec['type'] != 8 and sec['address'] <= va < sec['address'] + sec['size']:
            return sec['offset'] + va - sec['address']
    raise AssertionError(f'unmapped {va:#x}')


class ChainOriginWritersTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = ARTIFACT.read_bytes()
        cls.records = pkt.analyze(cls.data)

    def test_artifact_identity(self):
        self.assertEqual(len(self.data), pkt.TARGET_SIZE)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(),
                         pkt.TARGET_SHA256)

    def test_regeneration_byte_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'packet'
            pkt.generate(str(ARTIFACT), out)
            for name in ('records.json', 'frames.txt',
                         'value_producer_disassembly.txt',
                         'value_producer_core_disassembly.txt',
                         'field_getter_disassembly.txt',
                         'tls_registry_disassembly.txt',
                         'chain_class_writer_disassembly.txt',
                         'spec_builder_disassembly.txt'):
                fresh, retained = (out / name).read_bytes(), (PACKET / name).read_bytes()
                # Normalize only the filename GNU embeds in its header.
                normalize = lambda raw: re.sub(
                    rb'^.*hl-node:\s+file format', b'hl-node:     file format',
                    raw, flags=re.M)
                self.assertEqual(normalize(fresh), normalize(retained), name)

    def test_owners_and_references(self):
        owners = {o['role']: o for o in self.records['owners']}
        self.assertEqual(
            {r: (o['start'], o['bytes']) for r, o in owners.items()},
            {'value_producer': ('0x165de90', 282),
             'value_producer_core': ('0x165dfb0', 1379),
             'field_getter': ('0x4e4ca30', 375),
             'tls_registry': ('0x1668ce0', 60)})
        refs = {o['role']: o for o in self.records['reference_bodies']}
        self.assertEqual(refs['gb_b2']['sha256'],
                         '90ae09003ca680bd4b5f32fec22ee1f7146cc1f67b758f8e2f2ac880545b730b')
        self.assertEqual(refs['chain_class_writer']['sha256'],
                         'e69561afd60a4ae323867f1eb25f2a6997c85c488524e15bf0ca9f9fed100e92')
        self.assertEqual(refs['spec_builder']['sha256'],
                         'd80ed0188335a8ce1b4587d9248f8010c61b066fb162a5129e90f968905fe7bf')
        self.assertEqual(refs['b4_caller_stager']['sha256'],
                         '427127960a40d09aaf71aa648cfdece33894eb95f6eca673582da4997ff0d2d0')

    def test_trail1_wiring(self):
        slot_calls = self.records['slot_call_census']
        self.assertEqual([s['site'] for s in slot_calls['value_producer']],
                         ['0x2ae430b', '0x2b7b6b8'])
        direct = self.records['direct_call_census']
        self.assertEqual(direct['value_producer'], [])
        self.assertEqual([s['site'] for s in direct['value_producer_core']],
                         ['0x165decc'])
        self.assertEqual([s['site'] for s in direct['tls_registry']],
                         ['0x165e388'])

    def test_core_store_and_getter_censuses(self):
        self.assertEqual(
            [(s['site'], s['disp']) for s in self.records['core_spec_copy_stores']],
            [('0x165e212', '0x38'), ('0x165e216', '0x40'), ('0x165e21a', '0x48')])
        self.assertEqual(self.records['getter_store_census'], [])

    def test_trail2_censuses(self):
        direct = self.records['direct_call_census']
        self.assertEqual(direct['b4_caller_stager'], [])
        zref = self.records['z_reference_census']
        self.assertEqual(zref['rela'],
                         [{'addend': '0x2af77f0', 'rela_type': 8,
                           'slot': '0x6447268'}])
        self.assertEqual(zref['rip_relative']['0x2af77f0'], [])
        self.assertEqual(zref['rip_relative']['0x6447260'], [])
        self.assertEqual(zref['rip_relative']['0x6447268'], [])
        self.assertEqual(zref['location_lea_sites'],
                         ['0x2acf71a', '0x2acf743', '0x2acf755', '0x2acf767',
                          '0x2ad370a', '0x2ad3733', '0x2ad3745', '0x2ad3769'])
        reg = self.records['registration_census']
        self.assertEqual(reg['count'], 447)
        self.assertEqual(
            [(r['record'], r['fn'], r['line'], r['col'])
             for r in reg['lu_rs_records']],
            [('0x64012f8', '0x15d5b00', 159, 64),
             ('0x6401400', '0x15d8530', 247, 13),
             ('0x6401438', '0x15c0bc0', 242, 12),
             ('0x64014b8', '0x15d6e00', 220, 26),
             ('0x64471b0', '0x2a92960', 75, 5),
             ('0x6447260', '0x2af77f0', 24, 16)])

    def test_location_sites_are_instruction_starts(self):
        # Decode the two lu.rs FDE exports and confirm every lea site in
        # the census is a native instruction start there.
        text = pkt.executable(
            'objdump',
            ['-d', '-M', 'intel', '--insn-width=16',
             '--start-address=0x2accee0', '--stop-address=0x2ad0db0',
             str(ARTIFACT)])
        body = pkt.read(self.data, 0x2accee0, 0x2ad0db0 - 0x2accee0)
        insns = pkt.decode_export(text, 0x2accee0, 0x2ad0db0, body)
        starts = set(insns)
        for site in (0x2acf71a, 0x2acf743, 0x2acf755, 0x2acf767):
            self.assertIn(site, starts)
        text = pkt.executable(
            'objdump',
            ['-d', '-M', 'intel', '--insn-width=16',
             '--start-address=0x2ad0db0', '--stop-address=0x2ad4db7',
             str(ARTIFACT)])
        body = pkt.read(self.data, 0x2ad0db0, 0x2ad4db7 - 0x2ad0db0)
        insns = pkt.decode_export(text, 0x2ad0db0, 0x2ad4db7, body)
        starts = set(insns)
        for site in (0x2ad370a, 0x2ad3733, 0x2ad3745, 0x2ad3769):
            self.assertIn(site, starts)

    def test_mutated_worker_call_rejected(self):
        off = file_offset(0x165e26b) + 1
        chunk = struct.pack('<i', 0x12345678)
        with self.assertRaisesRegex(ValueError,
                                    'byte pin failed for call the registry worker'):
            pkt.analyze(mutated(off, chunk))

    def test_mutated_builder_call_rejected(self):
        off = file_offset(0x165e3cc) + 1
        chunk = struct.pack('<i', 0x12345678)
        with self.assertRaisesRegex(ValueError,
                                    'byte pin failed for call the merge builder'):
            pkt.analyze(mutated(off, chunk))

    def test_mutated_producer_slot_binding_rejected(self):
        # Find the .rela.dyn addend of the producer slot and corrupt it.
        rels = pkt.relocations(self.data)
        entry = next(r for r in rels if r['slot'] == 0x64e1da8)
        chunk = struct.pack('<q', 0x165de91)
        with self.assertRaisesRegex(ValueError,
                                    'value_producer slot binding changed'):
            pkt.analyze(mutated(entry['addend_file_offset'], chunk))

    def test_mutated_b2_producer_call_rejected(self):
        # The converter's producer-slot call site is not byte-pinned in
        # this packet, so corrupting its displacement is caught by the
        # slot-call census itself.
        off = file_offset(0x2b7b6b8) + 2
        chunk = struct.pack('<i', 0x12345678)
        with self.assertRaisesRegex(ValueError,
                                    'value_producer slot call census changed'):
            pkt.analyze(mutated(off, chunk))

    def test_mutated_core_store_rejected(self):
        off = file_offset(0x165e212) + 3
        with self.assertRaisesRegex(ValueError,
                                    'byte pin failed for spec_copy'):
            pkt.analyze(mutated(off, b'\x39'))

    def test_mutated_registration_fn_rejected(self):
        rels = pkt.relocations(self.data)
        entry = next(r for r in rels if r['slot'] == 0x6447268)
        chunk = struct.pack('<q', 0x2af77f1)
        with self.assertRaisesRegex((ValueError, KeyError),
                                    'registration|Z relocation'):
            pkt.analyze(mutated(entry['addend_file_offset'], chunk))

    def test_mutated_registration_count_rejected(self):
        # Corrupt the head word of another registration record.
        off = data_file_offset(self.data, 0x64012f8)
        with self.assertRaisesRegex(ValueError,
                                    'registration pattern census changed|lu.rs'):
            pkt.analyze(mutated(off, struct.pack('<Q', 9)))

    def test_mutated_getter_bcmp_binding_rejected(self):
        rels = pkt.relocations(self.data)
        entry = next(r for r in rels if r['slot'] == 0x64df9f8)
        sym_off = None
        secs = pkt.sections(self.data)
        rela = next(s for s in secs if s['name'] == '.rela.plt')
        # Corrupt the relocation type so it is no longer a jump slot.
        type_off = entry['addend_file_offset'] - 8
        chunk = struct.pack('<Q', 8)
        with self.assertRaisesRegex(ValueError, 'bcmp slot binding changed'):
            pkt.analyze(mutated(type_off, chunk))

    def test_mutated_boundary_rejected(self):
        off = file_offset(0x1630c90)
        with self.assertRaisesRegex(ValueError,
                                    'boundary registry_worker body hash changed'):
            pkt.analyze(mutated(off, b'\xff'))


if __name__ == '__main__':
    unittest.main()
