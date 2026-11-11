from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT_DIR), str(ROOT_DIR / 'tools')]

import x4_drain_reachability_static as subject
from artifacts import ROOT

TARGET = ROOT_DIR / 'artifacts/node/115/hl-node'
DATA = TARGET.read_bytes() if TARGET.exists() else b''
MATERIALISED = (
    len(DATA) == subject.TARGET_SIZE
    and hashlib.sha256(DATA).hexdigest() == subject.TARGET_SHA256)

PACKET = (Path(ROOT) / 'research/work-items/'
          'RE-005-node115-x4-drain-reachability')


def canonical(payload):
    return json.dumps(payload, indent=1, sort_keys=True) + '\n'


@unittest.skipUnless(
    MATERIALISED,
    'the node 115 ELF artifact is not materialised')
class X4DrainReachabilityStaticTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data = TARGET.read_bytes()
        cls.payload = subject.analyze(cls.data)

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
        self.assertEqual(len(owners), 7)
        spot = {
            'drain_x4': ('0x5cd8580', '0x5cd860f', 143,
                         '27dde2348fd486d19480e86af2e108d87e5e217bad18'
                         '91359c47d5f57b6ae749'),
            'cell_glue_x4': ('0x5cd86e0', '0x5cd880f', 303,
                             'b00b49cda8cc6f4e875da8f3046d7bd18e270fbec6'
                             'a3235ccbba0e67b376f5ac'),
            'payload_drop_x4': ('0x5cda210', '0x5cda37e', 366,
                                '6cfdb2d06e84078fd1f654681ea6a1d4cc4fb711'
                                'a2fddf7883c66390f668b12e'),
            'preceding_body': ('0x5cd8540', '0x5cd857c', 60,
                               '989276ed8b69cb40d878fa3e9916ee9cf2917ad31'
                               'c9f4578e5aa6be4dfddedab'),
        }
        for role, (start, end, size, digest) in spot.items():
            self.assertEqual(owners[role]['start'], start)
            self.assertEqual(owners[role]['end'], end)
            self.assertEqual(owners[role]['bytes'], size)
            self.assertEqual(owners[role]['sha256'], digest)
        self.assertFalse(self.payload['captured_code_executed'])

    def test_reference_census(self):
        census = self.payload['reference_census']
        for role, site, body in (
                ('drain_x4', '0x5cd87df', 'cell_glue_x4'),
                ('drain_x5', '0x5ce8494', 'cell_glue_x5')):
            rec = census[role]
            self.assertEqual(len(rec['direct_branches']), 1)
            hit = rec['direct_branches'][0]
            self.assertEqual(hit['site'], site)
            self.assertEqual(hit['kind'], 'call')
            self.assertEqual(hit['containing_body'], body)
            self.assertEqual(rec['pointer_occurrences'], [])
            self.assertEqual(rec['immediate32_occurrences'], [])
            self.assertEqual(rec['relocation_addends'], [])
            self.assertEqual(rec['rip_relative'], [])
        fall = census['fallthrough']
        self.assertTrue(fall['excluded'])
        self.assertEqual(fall['int3_fill'],
                         {'start': '0x5cd857c', 'end': '0x5cd8580'})

    def test_lsda_mappings(self):
        lsda = self.payload['lsda_tables']
        glue = {(e['start'], e['end']): e
                for e in lsda['cell_glue_x4']['entries']}
        entry = glue[('0x5cd86ef', '0x5cd86f7')]
        self.assertEqual(entry['landing_pad'], '0x5cd87c1')
        self.assertEqual(entry['action'], 0)
        drain_entry = glue[('0x5cd87df', '0x5cd87e4')]
        self.assertEqual(drain_entry['landing_pad'], '0x5cd8809')
        self.assertEqual(drain_entry['action'], 1)
        pd = {(e['start'], e['end']): e
              for e in lsda['payload_drop_x4']['entries']}
        drop = pd[('0x5cda245', '0x5cda24a')]
        self.assertEqual(drop['landing_pad'], '0x5cda2db')
        self.assertEqual(drop['action'], 5)

    def test_unwind_audit(self):
        audit = self.payload['unwind_audit']
        for fam in ('x4', 'x5'):
            rec = audit[fam]
            self.assertEqual(rec['state_word_on_glue_pad_entry'], 0)
            self.assertIsNotNone(
                rec['payload_pre_store_calls']['drop_call_pad'])
            self.assertEqual(
                rec['payload_pre_store_calls']['drop_call_action'], 5)
            self.assertIsNone(
                rec['payload_pre_store_calls']['dealloc_call_pad'])
            self.assertIsNone(rec['payload_panic_tail_jmp']['pad'])
            self.assertTrue(
                rec['payload_panic_tail_jmp']['after_state_store'])
        x4 = audit['x4']
        self.assertEqual(x4['glue_payload_call'], '0x5cd86f2')
        self.assertEqual(x4['glue_pad_for_payload_call'], '0x5cd87c1')
        self.assertEqual(x4['drain_call_site'], '0x5cd87df')
        self.assertEqual(x4['drain_call_within_pad'],
                         {'pad_start': '0x5cd87c1',
                          'pad_end': '0x5cd87e4'})
        self.assertEqual(x4['payload_pre_store_calls']['drop_call'],
                         '0x5cda248')
        self.assertEqual(x4['payload_pre_store_calls']['drop_call_pad'],
                         '0x5cda2db')
        self.assertEqual(x4['payload_state_stores'],
                         {'normal_path': '0x5cda276',
                          'in_payload_pad': '0x5cda30a'})
        self.assertEqual(x4['payload_pad_calls_before_state_store'],
                         ['0x5cda304'])

    def test_slots(self):
        slots = self.payload['slots']
        self.assertEqual(slots['x4_context_release']['target'],
                         '0x5cd88d0')
        self.assertEqual(slots['x5_context_release']['target'],
                         '0x5ce8660')
        self.assertEqual(slots['dealloc']['slot'], '0x64df4a0')
        self.assertEqual(slots['catch_pair']['slot'], '0x64dfe88')

    def test_mutation_of_drain_call_target_is_rejected(self):
        # low byte of the rel32 in the glue pad's call to drain_x4
        data = bytearray(self.data)
        off, _ = subject.read(0x5cd87df, bytes(data), 5)
        data[off + 1] ^= 0x01
        with self.assertRaises(ValueError):
            subject.reference_census(bytes(data))

    def test_mutation_of_pad_state_store_is_rejected(self):
        # immediate byte of the payload pad's state := 0 store
        data = bytearray(self.data)
        off, _ = subject.read(0x5cda30a, bytes(data), 8)
        data[off + 7] ^= 0x01
        with self.assertRaises(ValueError):
            subject.check_pins(bytes(data))

    def test_mutation_of_lsda_landing_pad_is_rejected(self):
        # first byte of the uleb landing-pad offset of the first
        # call-site entry in cell_glue_x4's LSDA (0xe1 at LSDA+7)
        data = bytearray(self.data)
        off, _ = subject.read(0x402224 + 7, bytes(data), 1)
        data[off] ^= 0x01
        with self.assertRaises(ValueError):
            subject.lsda_tables(bytes(data))

    def test_mutation_of_owner_body_is_rejected(self):
        data = bytearray(self.data)
        off, _ = subject.read(0x5cd8580, bytes(data), 16)
        data[off] ^= 0x01
        with self.assertRaises(ValueError):
            subject.owners(bytes(data))


if __name__ == '__main__':
    unittest.main()
