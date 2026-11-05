#!/usr/bin/env python3
"""Verify the grow-family panic-closure packet end to end.

The packet's claims are checked four ways: the artifact is the pinned
node #115 binary; analyze() re-derives every pinned fact from the raw
bytes; one-byte counterfactuals against a branch displacement, a call
displacement, a slot addend, an LSDA byte and the panic message each
make analyze() fail; and generate() reproduces the committed evidence
byte for byte, including the 20,000-case behavioural differential.
"""
import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from elf_index import sections  # noqa: E402
from grow_family_panic_static import (  # noqa: E402
    ROOT, SHA, TARGET, analyze, behavioral, generate)

ITEM = ROOT / 'research/work-items/RE-015-node115-grow-family-panic-closure'


def offset_of(data, va):
    for section in sections(data):
        if section['type'] != 8 and \
                section['address'] <= va < \
                section['address'] + section['size']:
            return section['offset'] + va - section['address']
    raise ValueError(hex(va))


def mutated(data, va, xor=0x01):
    blob = bytearray(data)
    blob[offset_of(data, va)] ^= xor
    return bytes(blob)


class GrowFamilyPanicStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = TARGET.read_bytes()
        cls.records = analyze(cls.data)

    def test_artifact_sha(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), SHA)

    def test_family_boundary(self):
        bodies = self.records['bodies']
        for role in ('variant_grow', 'hash_a', 'hash_b', 'map_grow',
                     'sibling_grow', 'sibling_hasher', 'absorb'):
            self.assertIn(role, bodies)
        # Exactly three cluster sites load the panic message.
        self.assertEqual(self.records['panic_message']['cluster_lea_sites'],
                         ['0x4743316', '0x474395b', '0x4743f8f'])
        # The three grows are address-taken only by their own
        # relocation records; nothing else in the family is taken.
        census = self.records['address_census']
        for va in ('0x4742aa0', '0x4743350', '0x4743990'):
            self.assertEqual(len(census[va]), 1)
            self.assertEqual(census[va][0][0], '.rela.dyn')
        for va in ('0x4744330', '0x4744490', '0x4744600', '0x4744980'):
            self.assertEqual(census[va], [])
        self.assertTrue(all(count == 0 for count in
                            self.records['imm64_census'].values()))
        # The neighbouring map body touches nothing in the family.
        for contact in self.records['neighbour_contact'].values():
            self.assertEqual(contact['direct_calls_to_family'], [])
            self.assertEqual(contact['family_slot_calls'], [])

    def test_variant_failure_wiring(self):
        self.assertEqual(self.records['variant_failure_branches'], {
            '0x4743370': '0x474348a', '0x4743413': '0x474348a',
            '0x4743457': '0x474348a', '0x474348d': '0x474395b',
            '0x47438ee': '0x4743974'})
        slots = self.records['variant_slot_calls']
        self.assertEqual(len(slots), 6)
        self.assertEqual(self.records['variant_direct_calls'],
                         {'0x474358e': '0x4744600', '0x4743700': '0x4744600'})
        self.assertIsNone(self.records['bodies']['variant_grow']['lsda'])

    def test_coverage(self):
        coverage = self.records['coverage']
        self.assertEqual(coverage['caller_c'],
                         {'0x474ba7e': '0x474bcb4', '0x474bc91': '0x474bcb4'})
        self.assertEqual(coverage['variant_caller_padded'],
                         {'0x4747b5d': '0x4747b79'})
        self.assertEqual(coverage['hash_a_caller_1'], {'0x4749f0a': None})
        self.assertEqual(coverage['hash_a_caller_2'], {'0x474a0fa': None})
        sweep = self.records['cluster_lsda_sweep']
        self.assertEqual(sweep['fdes_with_lsda'], 56)
        self.assertEqual(sweep['entries'], 270)
        self.assertEqual(sweep['pads_outside_own_body'], 0)

    def test_counterfactuals_fail(self):
        # A branch displacement in the variant's failure wiring.
        with self.assertRaises(Exception):
            analyze(mutated(self.data, 0x4743373))
        # A direct-call displacement (variant -> hash B).
        with self.assertRaises(Exception):
            analyze(mutated(self.data, 0x474358f))
        # A byte of the caller-C LSDA blob.
        with self.assertRaises(Exception):
            analyze(mutated(self.data, 0x34cb18 + 12))
        # A byte of the panic message itself.
        with self.assertRaises(Exception):
            analyze(mutated(self.data, 0x49bd80))
        # A byte inside hash B's body.
        with self.assertRaises(Exception):
            analyze(mutated(self.data, 0x4744600 + 40))
        # The variant home slot's relocation addend.
        rela = next(s for s in sections(self.data)
                    if s['name'] == '.rela.dyn')
        addend_off = None
        for i in range(rela['size'] // 24):
            off = rela['offset'] + i * 24
            if struct.unpack_from('<Q', self.data, off)[0] == 0x64eaf80:
                addend_off = off + 16
        self.assertIsNotNone(addend_off)
        blob = bytearray(self.data)
        blob[addend_off] ^= 0x01
        with self.assertRaises(Exception):
            analyze(bytes(blob))

    def test_behavioral_differential(self):
        result = behavioral(self.data)
        self.assertEqual(result['cases'], 20000)
        self.assertTrue(result['streams_equal'])
        self.assertEqual(len(set(result['outputs_sha256'].values())), 1)
        committed = json.loads((ITEM / 'behavior.json').read_text())
        self.assertEqual(result, committed)

    def test_generate_round_trip(self):
        committed = {name: (ITEM / name).read_bytes() for name in
                     ('records.json', 'classification.json',
                      'behavior.json', 'frames.txt')}
        with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
            generate(tmp)
            for name, want in committed.items():
                self.assertEqual((Path(tmp) / name).read_bytes(), want,
                                 f'{name} did not regenerate byte-equal')
            for path in ITEM.glob('*_objdump.txt'):
                self.assertEqual((Path(tmp) / path.name).read_bytes(),
                                 path.read_bytes(),
                                 f'{path.name} did not regenerate')


if __name__ == '__main__':
    unittest.main()
