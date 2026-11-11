from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT_DIR), str(ROOT_DIR / 'tools')]

import packet_cell_layouts_x4x5_static as subject
from artifacts import ROOT

TARGET = ROOT_DIR / 'artifacts/node/115/hl-node'
DATA = TARGET.read_bytes() if TARGET.exists() else b''
MATERIALISED = (
    len(DATA) == subject.TARGET_SIZE
    and hashlib.sha256(DATA).hexdigest() == subject.TARGET_SHA256)

PACKET = (Path(ROOT) / 'research/work-items/'
          'RE-005-node115-x4-x5-cell-layouts')


def canonical(payload):
    return json.dumps(payload, indent=1, sort_keys=True) + '\n'


@unittest.skipUnless(
    MATERIALISED,
    'the node 115 ELF artifact is not materialised')
class PacketCellLayoutsX4X5StaticTest(unittest.TestCase):

    def setUp(self):
        self.data = TARGET.read_bytes()
        self.payload = subject.analyze(self.data)

    def test_regeneration_matches_packet(self):
        packet = PACKET / 'records.json'
        self.assertTrue(packet.is_file())
        self.assertEqual(packet.read_text(), canonical(self.payload))

    def test_manifest_matches_packet_files(self):
        lines = []
        for path in sorted(PACKET.iterdir()):
            if path.is_file() and path.name != 'MANIFEST.sha256':
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                lines.append(f'{digest}  {path.name}\n')
        self.assertEqual((PACKET / 'MANIFEST.sha256').read_text(),
                         ''.join(lines))

    def test_owners_are_pinned(self):
        owners = self.payload['owners']
        self.assertEqual(len(owners), 14)
        spot = {
            'dispatcher_x4': ('0x5cd9b30', '0x5cd9cd7', 423,
                              '939b0f395bedfc84d55c5f6a2de8b19f39bc'
                              '64089ce0cf3c25efe284478f51ae'),
            'dispatcher_x5': ('0x5cf7710', '0x5cf78e7', 471,
                              '313eb6afb9fb15a3d11f14e20b1bd68e89d8'
                              'be9ad571026469e43fd35aa0bbd2'),
            'cell_glue_x5': ('0x5ce8390', '0x5ce84c4', 308,
                             '47595306d82fbac24e1c7ec4c42550d1177e'
                             'faa130783bc81ba7c27b79dc8af9'),
            'join_x5': ('0x5cf7550', '0x5cf76ae', 350,
                        '12fbb6bdf25c91d5912271bcae41e6422635dd8'
                        'ca655bb0233e985ad9b685c03'),
        }
        for role, (start, end, size, digest) in spot.items():
            self.assertEqual(owners[role]['start'], start)
            self.assertEqual(owners[role]['end'], end)
            self.assertEqual(owners[role]['bytes'], size)
            self.assertEqual(owners[role]['sha256'], digest)
        self.assertFalse(self.payload['captured_code_executed'])

    def test_tables(self):
        tables = {t['family']: t for t in self.payload['tables']}
        self.assertEqual(tables['X4']['base'], '0x64c5330')
        self.assertEqual(tables['X4']['size'], '0x30')
        self.assertEqual(tables['X4']['method'], '0x5cd9b30')
        self.assertEqual(tables['X5']['base'], '0x64c6ac0')
        self.assertEqual(tables['X5']['size'], '0x48')
        self.assertEqual(tables['X5']['method'], '0x5cf7710')

    def test_slots(self):
        slots = self.payload['slots']
        self.assertEqual(slots['x4_cell_drop']['target'], '0x5cd86e0')
        self.assertEqual(slots['x5_cell_drop']['target'], '0x5ce8390')
        self.assertEqual(slots['x4_context_release']['target'],
                         '0x5cd88d0')
        self.assertEqual(slots['x5_context_release']['target'],
                         '0x5ce8660')

    def test_finish_store_audit(self):
        audit = self.payload['finish_store_audit']
        for role, sites in (('dispatcher_x4',
                             ('0x5cd9be7', '0x5cd9c4b')),
                            ('dispatcher_x5',
                             ('0x5cf77f9', '0x5cf7860'))):
            stores = audit[role]['stores']
            self.assertEqual(len(stores), 6)
            self.assertEqual({s['site'] for s in stores
                              if s['disp'] == '0x18'}, set(sites))
            for store in stores:
                self.assertEqual(store['base'], 'rbp')
            by_disp = {}
            for store in stores:
                by_disp.setdefault(store['disp'], set()).add(
                    (store['kind'], store['src']))
            self.assertEqual(by_disp['0x18'], {('imm', 1)})
            self.assertEqual(by_disp['0x20'], {('reg', 'r14')})
            self.assertEqual(by_disp['0x28'], {('reg', 'r15')})

    def test_layout_answer(self):
        fields = {f['offset']: f['name']
                  for f in self.payload['answer']['fields']}
        self.assertEqual(fields, {
            '0x00': 'strong_count', '0x08': 'weak_count',
            '0x10': 'context_pointer', '0x18': 'state',
            '0x20': 'data', '0x28': 'vtable'})

    def test_mutation_of_finish_store_disp_is_rejected(self):
        # dispatcher_x4 fall-through data store: disp byte 0x20.
        data = bytearray(self.data)
        off, _ = subject.read(0x5cd9bef, bytes(data), 4)
        data[off + 3] ^= 0x01
        with self.assertRaises(ValueError):
            subject.check_pins(bytes(data))

    def test_mutation_of_spawn_state_store_is_rejected(self):
        # spawn_x5 cell-image state := 0 store immediate.
        data = bytearray(self.data)
        off, _ = subject.read(0x5cf705d, bytes(data), 12)
        data[off + 11] ^= 0x01
        with self.assertRaises(ValueError):
            subject.check_pins(bytes(data))

    def test_mutation_of_join_state_test_is_rejected(self):
        # join_x5 state testb displacement byte (0x18).
        data = bytearray(self.data)
        off, _ = subject.read(0x5cf75b3, bytes(data), 4)
        data[off + 2] ^= 0x01
        with self.assertRaises(ValueError):
            subject.check_pins(bytes(data))

    def test_mutation_of_table_size_is_rejected(self):
        # X5 entry size word (0x48) in .rodata.
        data = bytearray(self.data)
        off, _ = subject.read(0x64c6ac0 + 8, bytes(data), 8)
        data[off] ^= 0x01
        with self.assertRaises(ValueError):
            subject.tables(bytes(data))

    def test_mutation_of_owner_body_is_rejected(self):
        data = bytearray(self.data)
        off, _ = subject.read(0x5ce8390, bytes(data), 16)
        data[off] ^= 0x01
        with self.assertRaises(ValueError):
            subject.owners(bytes(data))


if __name__ == '__main__':
    unittest.main()
