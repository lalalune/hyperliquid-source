from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT_DIR), str(ROOT_DIR / 'tools')]

import scope_instantiation_static as subject
from artifacts import ROOT

TARGET = ROOT_DIR / 'artifacts/node/115/hl-node'
DATA = TARGET.read_bytes() if TARGET.exists() else b''
MATERIALISED = (
    len(DATA) == subject.TARGET_SIZE
    and hashlib.sha256(DATA).hexdigest() == subject.TARGET_SHA256)

PACKET = (Path(ROOT) / 'research/work-items/'
          'RE-005-node115-scope-instantiation')


def canonical(payload):
    return json.dumps(payload, indent=1, sort_keys=True) + '\n'


@unittest.skipUnless(
    MATERIALISED,
    'the node 115 ELF artifact is not materialised')
class ScopeInstantiationStaticTest(unittest.TestCase):

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
        self.assertEqual(len(owners), 2)
        spot = {
            'scope_overflow_stub': (
                '0x5c82d40', '0x5c82d65', 37,
                '8e56d981e4d3963755c766b4afc64f760'
                '1e92faa51e0d3be992cc5df698ba8cc'),
            'scope_decrement': (
                '0x5c82d00', '0x5c82d3b', 59,
                'c0e94d3d28434c43010bfb30b7db80e3eb'
                'e8d8151133fe5a875795ec6a4d68c5'),
        }
        for role, (start, end, size, digest) in spot.items():
            self.assertEqual(owners[role]['start'], start)
            self.assertEqual(owners[role]['end'], end)
            self.assertEqual(owners[role]['bytes'], size)
            self.assertEqual(owners[role]['sha256'], digest)

    def test_scope_exit_panic_string_absent(self):
        census = self.payload['string_census']
        self.assertEqual(
            census['exit_panic_string']['occurrences'], [])
        scoped = census['scoped_substring']['occurrences']
        self.assertEqual(len(scoped), 1)
        self.assertTrue(
            scoped[0]['containing'].endswith(
                'library/std/src/thread/scoped.rs'))

    def test_scoped_location_census_is_singleton(self):
        census = self.payload['location_census']
        self.assertEqual(len(census['records']), 1)
        rec = census['records'][0]
        self.assertEqual(rec['record'], '0x64c32f0')
        self.assertEqual(rec['len'], 80)
        self.assertEqual(rec['line'], 60)
        self.assertEqual(rec['col'], 9)
        # the scan is not blind: it recovers many std .rs
        # Locations overall, just one for scoped.rs
        self.assertGreater(
            census['std_rs_locations_recovered'], 1000)

    def test_stub_callers_are_the_14_spawn_bodies(self):
        census = self.payload['stub_xref_census']
        self.assertEqual(census['count'], 14)
        owners = sorted({s['owner'] for s in census['sites']})
        self.assertEqual(
            owners,
            [hex(s) for s in sorted(subject.SPAWN_STARTS)])

    def test_decrement_entered_only_via_stub_rollback(self):
        census = self.payload['reference_census']
        self.assertEqual(census['decrement_direct_callers'], [])
        self.assertEqual(census['decrement_relocation_slots'],
                         ['0x64ec708'])
        self.assertEqual(census['decrement_slot_call_site'],
                         '0x5c82d46')
        self.assertEqual(census['location_code_refs'],
                         ['0x5c82d53'])
        self.assertEqual(census['message_code_refs'],
                         ['0x5c82d4c'])

    def test_stub_has_no_data_entry(self):
        census = self.payload['data_pointer_census']['stub']
        self.assertEqual(census['relocation_addend_slots'], [])
        self.assertEqual(
            census['literal_occurrences_outside_rela_dyn'], [])

    def test_mutation_breaks_analysis(self):
        # flipping the overflow stub's first byte must change
        # the derived payload (owner hash / pins are pinned)
        elf = subject.Elf(self.data)
        off = elf.va2off(subject.STUB)
        mutated = bytearray(self.data)
        mutated[off] ^= 0xff
        with self.assertRaises(AssertionError):
            subject.analyze(bytes(mutated))


if __name__ == '__main__':
    unittest.main()
