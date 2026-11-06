from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT_DIR), str(ROOT_DIR / 'tools')]

import packet_cell_context_static as subject
from artifacts import ROOT

TARGET = ROOT_DIR / 'artifacts/node/115/hl-node'
DATA = TARGET.read_bytes() if TARGET.exists() else b''
MATERIALISED = (
    len(DATA) == subject.TARGET_SIZE
    and hashlib.sha256(DATA).hexdigest() == subject.TARGET_SHA256)

PACKET = (Path(ROOT) / 'research/work-items/'
          'RE-005-node115-packet-cell-context')


def canonical(payload):
    return json.dumps(payload, indent=1, sort_keys=True) + '\n'


@unittest.skipUnless(
    MATERIALISED,
    'the node 115 ELF artifact is not materialised')
class PacketCellContextStaticTest(unittest.TestCase):

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
        self.assertEqual(len(owners), 18)
        spot = {
            'spawn_a': ('0x15b80e0', '0x15b8804', 1828,
                        '967d4b0bb72e2e86245bc092d3d850f2324631a'
                        'daf5482ac4df09804e3f152b8'),
            'context_release_a': ('0x5bc24b0', '0x5bc251f', 111,
                                  '9f81ff6a58706bb981ed5dad414257'
                                  'dd5107d35299d0f06258c088a17f72f30e'),
            'scope_panic_stub': ('0x5c82d40', '0x5c82d65', 37,
                                 '8e56d981e4d3963755c766b4afc64f760'
                                 '1e92faa51e0d3be992cc5df698ba8cc'),
            'scope_decrement': ('0x5c82d00', '0x5c82d3b', 59,
                                'c0e94d3d28434c43010bfb30b7db80e3eb'
                                'e8d8151133fe5a875795ec6a4d68c5'),
        }
        for role, (start, end, size, digest) in spot.items():
            self.assertEqual(owners[role]['start'], start)
            self.assertEqual(owners[role]['end'], end)
            self.assertEqual(owners[role]['bytes'], size)
            self.assertEqual(owners[role]['sha256'], digest)
        self.assertFalse(self.payload['captured_code_executed'])

    def test_context_layout(self):
        layout = {row['offset']: row['name']
                  for row in self.payload['answer']['layout']}
        self.assertEqual(layout, {
            '0x00': 'strong_count',
            '0x08': 'weak_count',
            '0x10': 'main_thread_handle',
            '0x18': 'num_running_threads',
            '0x20': 'a_thread_panicked_flag',
        })

    def test_scoped_location_and_message(self):
        census = self.payload['scoped_location_census']
        self.assertEqual(census['count'], 1)
        record = census['records'][0]
        self.assertEqual(record['record'], '0x64c32f0')
        self.assertTrue(record['file'].endswith(
            'library/std/src/thread/scoped.rs'))
        self.assertEqual((record['line'], record['col']), (60, 9))
        message = self.payload['panic_message']
        self.assertEqual(message['text'],
                         'too many running threads in thread scope')
        self.assertEqual(message['len'], 40)

    def test_slots(self):
        slots = self.payload['slots']
        self.assertEqual(slots['a_context_release']['target'],
                         '0x5bc24b0')
        self.assertEqual(slots['x4_context_release']['target'],
                         '0x5cd88d0')
        self.assertEqual(slots['x5_context_release']['target'],
                         '0x5ce8660')
        self.assertEqual(slots['thread_field_drop']['target'],
                         '0x5c98b40')
        self.assertEqual(slots['scope_decrement']['target'],
                         '0x5c82d00')
        self.assertEqual(slots['futex_syscall']['symbol'],
                         'syscall')

    def test_spawn_census(self):
        census = self.payload['spawn_census']
        self.assertEqual(len(census), 14)
        starts = {row['start'] for row in census}
        for family in ('0x15b80e0', '0x5cd9470', '0x5cf6e80'):
            self.assertIn(family, starts)
        for row in census:
            self.assertTrue(row['inc_site'])
            self.assertTrue(row['stub_call_site'])

    def test_call_site_census_all_null(self):
        census = self.payload['call_site_census']
        self.assertEqual(len(census), 16)
        self.assertTrue(all(row['r9_null'] for row in census))
        by_family = {(row['spawn'], row['site']) for row in census}
        self.assertIn(('0x15b80e0', '0x150b98c'), by_family)
        self.assertIn(('0x5cd9470', '0x5cd5f45'), by_family)
        self.assertIn(('0x5cf6e80', '0x5cf5347'), by_family)
        indirect = self.payload['indirect_reference_census']
        self.assertEqual(indirect, {'slot_calls': 0, 'lea_refs': 0,
                                    'data_ptrs': 0})

    def test_payload_drop_census(self):
        census = self.payload['payload_drop_census']
        self.assertEqual(len(census), 6)
        starts = {row['start'] for row in census}
        self.assertEqual(starts, {
            '0x5bc3bf0', '0x5cda210', '0x5cfc3e0',
            '0x2deb7e0', '0x565bfc0', '0x565c0c0'})
        family = next(r for r in census
                      if r['start'] == '0x5bc3bf0')
        self.assertEqual(family['flag_store'], '0x5bc3c6b')
        self.assertEqual(family['counter_dec'], '0x5bc3c6f')
        self.assertEqual(family['thread_load'], '0x5bc3c76')
        self.assertEqual(family['parker_xchg'], '0x5bc3c7f')

    def test_decrement_census(self):
        census = self.payload['decrement_census']
        self.assertEqual(census['direct_calls'], 0)
        self.assertEqual(census['slot_call_sites'], ['0x5c82d46'])
        self.assertEqual(census['sole_caller'], 'scope_panic_stub')

    def test_caller_locations(self):
        locations = self.payload['caller_locations']
        x4 = {row['file'] for row in locations['caller_x4']}
        self.assertTrue(any(f.endswith(
            'z_vendor/threadpool/src/lib.rs') for f in x4))
        x5 = {row['file'] for row in locations['caller_x5']}
        self.assertTrue(any(f.endswith(
            'tokio/src/runtime/blocking/pool.rs') for f in x5))
        a = {row['file'] for row in locations['caller_a']}
        self.assertTrue(any(f.endswith(
            'library/std/src/thread/functions.rs') for f in a))
        self.assertTrue(any(f.endswith('base/src/lazy_mutex.rs')
                            for f in a))

    def test_mutation_breaks_analysis(self):
        # Flip the increment byte of spawn_a: analysis must
        # refuse the mutated artifact.
        from packet_cell_context_static import read
        offset, _ = read(0x15b835a, self.data, 5)
        mutated = bytearray(self.data)
        mutated[offset] ^= 0xff
        with self.assertRaises(ValueError):
            subject.owners(bytes(mutated))
        # Flip a byte inside the audited xor of caller_a.
        offset, _ = read(0x150b989, self.data, 3)
        mutated = bytearray(self.data)
        mutated[offset] ^= 0xff
        with self.assertRaises(ValueError):
            subject.check_pins(bytes(mutated))


if __name__ == '__main__':
    unittest.main()
