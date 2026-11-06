from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT_DIR), str(ROOT_DIR / 'tools')]

import thread_handle_internals_static as subject
from artifacts import ROOT

TARGET = ROOT_DIR / 'artifacts/node/115/hl-node'
DATA = TARGET.read_bytes() if TARGET.exists() else b''
MATERIALISED = (
    len(DATA) == subject.TARGET_SIZE
    and hashlib.sha256(DATA).hexdigest() == subject.TARGET_SHA256)

PACKET = (Path(ROOT) / 'research/work-items/'
          'RE-005-node115-thread-handle-internals')


def canonical(payload):
    return json.dumps(payload, indent=1, sort_keys=True) + '\n'


@unittest.skipUnless(
    MATERIALISED,
    'the node 115 ELF artifact is not materialised')
class ThreadHandleInternalsStaticTest(unittest.TestCase):

    _payload = None

    def setUp(self):
        self.data = TARGET.read_bytes()
        # analyze() re-scans the whole binary; compute it once
        # per class and share the payload across tests.
        cls = type(self)
        if cls._payload is None:
            cls._payload = subject.analyze(self.data)
        self.payload = cls._payload

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
        self.assertEqual(len(owners), 6)
        spot = {
            'main_thread_ctor': (
                '0x5c9d1f0', '0x5c9d323', 307,
                'a7c468881fcbfe7c35224608b3e1fb3dc99ee78'
                'dc8ef16ed8fbf42b54bb5d56c'),
            'scoped_region_ctor': (
                '0x5c82fd0', '0x5c8312c', 348,
                '478d76e4fffc052e077d3dab44488e68e8b83f'
                '4f31dffd2ee5265a1fdb0d7133'),
            'spawn_thread_ctor': (
                '0x5613a70', '0x56141ee', 1918,
                'b477d0af755bbbda9ee410ad49499a02237628d'
                '3b2e78dfa4e2ec73ce566cff4'),
            'thread_field_drop': (
                '0x5c98b40', '0x5c98b89', 73,
                '7ca6f244918e5003e12f248d655375601a436ae'
                '72776897c6aad46457a258c15'),
            'name_validator': (
                '0x5ca5760', '0x5ca58c3', 355,
                'dbb953f930491a31d1471558dac0105e2a94fb3'
                '484fe281ae620a0d5086213ef'),
            'thread_id_panic_shim': (
                '0x5ca4480', '0x5ca449d', 29,
                '1ce593480e9e70545ee1fca277e82db931ad3c7'
                'ecc2e1d5a33f5cd17808e4d13'),
        }
        for role, (start, end, size, digest) in spot.items():
            self.assertEqual(owners[role]['start'], start)
            self.assertEqual(owners[role]['end'], end)
            self.assertEqual(owners[role]['bytes'], size)
            self.assertEqual(owners[role]['sha256'], digest)

    def test_layout_is_closed(self):
        layout = self.payload['layout']
        self.assertEqual(layout['allocation']['size'], '0x30')
        fields = {f['name']: f for f in layout['fields']}
        self.assertEqual(fields['strong count']['offset'], '0x00')
        self.assertEqual(fields['weak count']['offset'], '0x08')
        self.assertEqual(fields['thread id']['offset'], '0x10')
        self.assertEqual(fields['name buffer pointer']['offset'],
                         '0x18')
        self.assertEqual(fields['name buffer length']['offset'],
                         '0x20')
        self.assertEqual(fields['parker state word']['offset'],
                         '0x28')
        self.assertEqual(fields['parker state word']['size'], 4)
        # nothing beyond the parker word but tail padding
        self.assertEqual(fields['tail padding']['offset'], '0x2c')
        self.assertEqual(fields['tail padding']['size'], 4)

    def test_construction_census(self):
        census = self.payload['construction_census']
        self.assertEqual(census['malloc_slot_call_sites'], 17)
        self.assertEqual(len(census['size_0x30_sites']), 16)
        self.assertEqual(census['named_variant'], 14)
        self.assertEqual(census['unnamed_variant'], 2)
        owners = sorted(r['owner'] for r in census['size_0x30_sites'])
        self.assertEqual(
            owners,
            [hex(s) for s in sorted(
                list(subject.SPAWN_STARTS)
                + [subject.MAIN_CTOR, subject.SCOPED_CTOR])])
        unnamed = sorted(r['owner'] for r in census['size_0x30_sites']
                         if r['variant'] == 'unnamed')
        self.assertEqual(unnamed, sorted([hex(subject.MAIN_CTOR),
                                          hex(subject.SCOPED_CTOR)]))

    def test_glue_census(self):
        census = self.payload['glue_census']
        self.assertEqual(census['call_sites'], 108)
        self.assertEqual(census['distinct_owners'], 77)
        self.assertEqual(census['target'], '0x5c98b40')

    def test_id_shim_census(self):
        census = self.payload['id_shim_census']
        self.assertEqual(census['count'], 22)
        owners = {r['owner'] for r in census['direct_callers']}
        for want in (subject.MAIN_CTOR, subject.SCOPED_CTOR,
                     subject.SPAWN_CTOR):
            self.assertIn(hex(want), owners)
        self.assertEqual(census['id_message']['va'], '0x94a088')
        self.assertEqual(census['name_message']['va'], '0x94a1ad')
        self.assertEqual(census['name_message']['len'], 47)

    def test_slots_and_locations(self):
        slots = self.payload['slots']
        self.assertEqual(slots['malloc']['symbol'], 'malloc')
        self.assertEqual(slots['free']['symbol'], 'free')
        self.assertEqual(slots['thread_field_drop']['target'],
                         '0x5c98b40')
        self.assertEqual(slots['name_validator']['target'],
                         '0x5ca5760')
        locs = self.payload['locations']
        self.assertEqual((locs['current_rs']['line'],
                          locs['current_rs']['col']), (315, 9))
        self.assertEqual((locs['id_rs']['line'],
                          locs['id_rs']['col']), (38, 13))
        self.assertEqual((locs['thread_rs']['line'],
                          locs['thread_rs']['col']), (24, 40))
        self.assertTrue(locs['thread_rs']['file'].endswith(
            'library/std/src/thread/thread.rs'))

    def test_mutation_breaks_analysis(self):
        # flipping a byte of the main constructor's store block
        # must change the derived payload (pins are pinned)
        elf = subject.Elf(self.data)
        off = elf.va2off(0x5c9d260)
        mutated = bytearray(self.data)
        mutated[off] ^= 0xff
        with self.assertRaises(AssertionError):
            subject.analyze(bytes(mutated))


if __name__ == '__main__':
    unittest.main()
