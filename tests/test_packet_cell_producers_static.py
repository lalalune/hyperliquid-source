from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT_DIR), str(ROOT_DIR / 'tools')]

import packet_cell_producers_static as subject
from artifacts import ROOT

TARGET = ROOT_DIR / 'artifacts/node/115/hl-node'
DATA = TARGET.read_bytes() if TARGET.exists() else b''
MATERIALISED = (
    len(DATA) == subject.TARGET_SIZE
    and hashlib.sha256(DATA).hexdigest() == subject.TARGET_SHA256)


def canonical(payload):
    return json.dumps(payload, indent=1, sort_keys=True) + '\n'


@unittest.skipUnless(
    MATERIALISED,
    'the node 115 ELF artifact is not materialised')
class PacketCellProducersStaticTest(unittest.TestCase):

    def setUp(self):
        self.data = TARGET.read_bytes()
        self.payload = subject.analyze(self.data)

    def test_regeneration_matches_packet(self):
        packet = Path(ROOT) / (
            'research/work-items/'
            'RE-005-node115-packet-cell-producers/records.json')
        self.assertTrue(packet.is_file())
        self.assertEqual(packet.read_text(), canonical(self.payload))

    def test_owners_are_pinned(self):
        owners = self.payload['owners']
        self.assertEqual(len(owners), 23)
        spot = {
            'dispatcher_v4': ('0x15b8fd0', '0x15b91c2', 498,
                              '20cd3ac9bdc80df92482568c93f647e74cf44'
                              '02f9b8b9c8f917d8f7ba32dd0d9'),
            'spawn_v4': ('0x15b80e0', '0x15b8804', 1828,
                         '967d4b0bb72e2e86245bc092d3d850f2324631a'
                         'daf5482ac4df09804e3f152b8'),
            'thread_start': ('0x5ca44a0', '0x5ca469d', 509,
                             '65e3438cb7b950aa4b885b7c271b6a8bcbd45'
                             '74519dee0f3f336360fabb21276'),
        }
        for role, (start, end, size, digest) in spot.items():
            self.assertEqual(owners[role]['start'], start)
            self.assertEqual(owners[role]['end'], end)
            self.assertEqual(owners[role]['bytes'], size)
            self.assertEqual(owners[role]['sha256'], digest)
        self.assertFalse(self.payload['captured_code_executed'])

    def test_idiom_census(self):
        census = self.payload['idiom_census']
        self.assertEqual(census['count'], 13)
        by_body = {b['body']: b for b in census['bodies']}
        finish = [b for b in census['bodies']
                  if b['class'] == 'dispatcher_finish']
        stack = [b for b in census['bodies']
                 if b['class'] == 'stack_construction']
        self.assertEqual(len(finish), 11)
        self.assertEqual({b['body'] for b in stack},
                         {'0x2e8fd30', '0x3b54430'})
        for body in stack:
            self.assertEqual(body['base_register'], 'rsp')
        v4 = by_body['0x15b8fd0']
        self.assertEqual(v4['role'], 'dispatcher_v4')
        self.assertEqual(v4['family'], 'L')
        self.assertEqual(v4['sites'], {'state': '0x15b9141',
                                       'data': '0x15b9149',
                                       'vtable': '0x15b914d'})
        # The same-cell family shares the cell Arc drop glue slot.
        for body in ('0x15b8cd0', '0x15b8e40', '0x15b91d0',
                     '0x15b8fd0', '0x2dd4f10', '0x561f970',
                     '0x561fed0', '0x5620120', '0x5bc3350'):
            self.assertIn('0x64dfe60',
                          by_body[body]['slots_referenced'])

    def test_tables_and_slots(self):
        tables = {t['base']: t for t in self.payload['tables']}
        self.assertEqual(len(tables), 11)
        v4 = tables['0x6400530']
        self.assertEqual(v4['dispatcher'], 'dispatcher_v4')
        self.assertEqual(v4['drop'], '0x15bb300')
        self.assertEqual(v4['size'], '0x58')
        self.assertEqual(v4['align'], '0x8')
        self.assertEqual(v4['method'], '0x15b8fd0')
        slots = self.payload['slots']
        self.assertEqual(slots['cell_arc_drop'],
                         {'slot': '0x64dfe60', 'type': 8,
                          'target': '0x5bc2a80'})
        self.assertEqual(slots['catch_pair'],
                         {'slot': '0x64dfe88', 'type': 8,
                          'target': '0x5bb19f0'})
        self.assertEqual(slots['thread_create'],
                         {'slot': '0x64e1580', 'type': 8,
                          'target': '0x5c87b50'})
        self.assertEqual(slots['x4_cell_drop']['target'], '0x5cd86e0')
        self.assertEqual(slots['x5_cell_drop']['target'], '0x5ce8390')

    def test_lea_and_call_census(self):
        lea = self.payload['lea_census']
        self.assertEqual(len(lea), 11)
        for sites in lea.values():
            self.assertEqual(len(sites), 1)
        self.assertEqual(lea['0x6400530'],
                         [{'site': '0x15b8436', 'body': '0x15b80e0'}])
        calls = self.payload['call_census']
        self.assertEqual(calls['dispatcher_v4'], [])
        self.assertEqual(calls['thread_start'], [])
        self.assertEqual(calls['spawn_v4'],
                         [{'site': '0x150b98c', 'body': '0x150b310'}])
        self.assertEqual(
            {entry['site'] for entry in calls['cell_payload_drop']},
            {'0x5bc2a92', '0x5bc3b0f'})

    def test_r15_audit(self):
        audit = self.payload['r15_audit']
        self.assertEqual(
            audit['dispatcher_r15_writes'],
            [{'site': '0x15b918e', 'insn': 'mov    %rdx,%r15'}])
        self.assertEqual(audit['dispatcher_r15_stores_to_0x28'],
                         ['0x15b90e6', '0x15b914d'])
        stores = {(s['site'], s['disp'], s['src'])
                  for s in self.payload['dispatcher_audit']['stores']}
        self.assertIn(('0x15b90da', '0x18', 1), stores)
        self.assertIn(('0x15b90e2', '0x20', 'r14'), stores)
        self.assertIn(('0x15b90e6', '0x28', 'r15'), stores)

    def test_answer_records(self):
        answer = self.payload['answer']
        self.assertIn('dispatcher itself', answer['producers'])
        self.assertIn('0x6400530', answer['r15_origin'])
        self.assertIn('NULL', answer['payload_shapes'])

    def test_byte_mutations_break_the_claims(self):
        cases = [
            (0x15B8436, 3),   # spawn_v4's lea of the entry base
            (0x15B918E, 1),   # dispatcher_v4's catch-path r15 write
            (0x15B90E6, 2),   # dispatcher_v4's finish vtable store
            (0x5CA45A6, 2),   # thread_start's package +0x10 load
        ]
        offset_base = 0x1000
        for va, skip in cases:
            mutated = bytearray(self.data)
            mutated[va - offset_base + skip] ^= 1
            with self.assertRaises(ValueError, msg=hex(va)):
                subject.analyze(bytes(mutated))


if __name__ == '__main__':
    unittest.main()
