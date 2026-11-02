"""Offline controls for the digest-bound user-slot set evidence collector."""
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from tools import book_user_slot_set94 as evidence
from tools.elf_index import sections, unwind_index


class BookUserSlotSet94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(evidence.TARGET.read_bytes())
        cls.secs = sections(cls.data)
        cls.result = evidence.collect(cls.data)

    def test_authenticated_input_and_selected_extents(self):
        self.assertEqual(evidence.check_digest(self.data), evidence.SHA256)
        self.assertEqual([(r[1], r[2]) for r in self.result['functions']],
                         [('0x285db90', '0x285dcef'), ('0x1a788b0', '0x1a79067')])
        self.assertEqual([r[8] for r in self.result['functions']], [351, 1975])
        self.assertEqual(len(self.result['pins']), 28)
        self.assertEqual(len(self.result['branches']), 45)
        self.assertEqual(len(self.result['calls']), 8)
        constants = {row[0]: row[4] for row in self.result['constants']}
        self.assertEqual((constants['node-capacity'], constants['leaf-allocation-bytes'],
                          constants['internal-allocation-bytes'], constants['book-slot-stride']),
                         (11, 104, 200, 248))

    def test_wrong_digest_is_rejected(self):
        altered = bytearray(self.data)
        altered[0] ^= 1
        with self.assertRaises(evidence.EvidenceError):
            evidence.check_digest(altered)
        with self.assertRaises(evidence.EvidenceError):
            evidence.collect(altered)

    def test_each_local_witness_rejects_corruption(self):
        for label, va, raw_hex, _ in evidence.WITNESSES:
            with self.subTest(label=label):
                _, offset = evidence.mapping(self.data, self.secs, va, len(bytes.fromhex(raw_hex)))
                self.data[offset] ^= 1
                try:
                    with self.assertRaises(evidence.EvidenceError):
                        evidence.verify_pins(self.data, self.secs)
                finally:
                    self.data[offset] ^= 1

    def test_every_selected_conditional_byte_is_pinned(self):
        for site in evidence.BRANCH_SITES:
            with self.subTest(site=hex(site)):
                _, off = evidence.mapping(self.data, self.secs, site, 1)
                self.data[off] ^= 1
                try:
                    with self.assertRaises(evidence.EvidenceError):
                        evidence.verify_pins(self.data, self.secs)
                finally:
                    self.data[off] ^= 1

    def test_corrupt_unwind_start_and_fde_extent_are_rejected(self):
        _, entries = unwind_index(self.data)
        start = evidence.FUNCTIONS[1][1]
        entry = next(e for e in entries if e['start'] == start)
        header = next(s for s in self.secs if s['name'] == '.eh_frame_hdr')
        offset = header['offset'] + 12 + entry['index'] * 8
        original = bytes(self.data[offset:offset + 4])
        old_delta = struct.unpack('<i', original)[0]
        self.data[offset:offset + 4] = struct.pack('<i', old_delta + 1)
        try:
            with self.assertRaises((evidence.EvidenceError, ValueError)):
                evidence.selected_fdes(self.data, self.secs)
        finally:
            self.data[offset:offset + 4] = original
        # FDE format uses a signed 4-byte PC range at record offset 12.
        _, offset = evidence.mapping(self.data, self.secs, entry['fde'] + 12, 4)
        original = bytes(self.data[offset:offset + 4])
        old_range = struct.unpack('<i', original)[0]
        self.data[offset:offset + 4] = struct.pack('<i', old_range + 1)
        try:
            with self.assertRaises((evidence.EvidenceError, ValueError)):
                evidence.selected_fdes(self.data, self.secs)
        finally:
            self.data[offset:offset + 4] = original

    def test_invalid_and_nobits_addresses_rejected(self):
        bss = next(s for s in self.secs if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        for va, length in ((-1, 1), (0xffffffffffffffff, 1),
                           (bss['address'], 1), (bss['address'] + bss['size'] - 1, 2)):
            with self.subTest(address=va):
                with self.assertRaises(evidence.EvidenceError):
                    evidence.mapping(self.data, self.secs, va, length)

    def test_split_position_boundaries_and_key_conservation(self):
        params = evidence.split_parameters(self.data, self.secs)
        self.assertEqual(params, (11, 5, 6, 4, 6, 8))
        expected = {0: (4, 'left', 0, 5, 6), 4: (4, 'left', 4, 5, 6),
                    5: (5, 'left', 5, 6, 5), 6: (5, 'right', 0, 5, 6),
                    7: (6, 'right', 0, 6, 5), 11: (6, 'right', 4, 6, 5)}
        for index in range(params[0] + 1):
            case = evidence.project_split(index, params)
            combined = case['left'] + [case['promoted']] + case['right']
            self.assertEqual(combined, sorted(case['old_keys'] + [case['new_key']]))
            self.assertEqual(len(case['left']) + len(case['right']), 11)
            if index in expected:
                self.assertEqual((case['pivot_index'], case['side'], case['local_index'],
                                  len(case['left']), len(case['right'])), expected[index])
        for index in (-1, 12):
            with self.assertRaises(evidence.EvidenceError):
                evidence.project_split(index, params)

    def test_nonfull_and_parent_edge_projections(self):
        params = evidence.split_parameters(self.data, self.secs)
        nonfull = [evidence.project_nonfull(n, i, params)
                   for n in range(params[0]) for i in range(n + 1)]
        self.assertEqual(len(nonfull), 66)
        self.assertIn((10, 0, 10, 80), nonfull)
        self.assertIn((10, 10, 0, 0), nonfull)
        for bad in ((11, 0), (10, 11), (-1, 0)):
            with self.assertRaises(evidence.EvidenceError):
                evidence.project_nonfull(*bad, params)
        for i in range(12):
            _, pivot, side, local, left, right = evidence.project_parent(i, params)
            left = left.split(',')
            right = right.split(',')
            case = evidence.project_split(i, params)
            expected = [f'old-{j}' for j in range(12)]
            expected.insert(i + 1, 'new')
            self.assertEqual(left + right, expected)
            self.assertEqual(len(left), len(case['left']) + 1)
            self.assertEqual(len(right), len(case['right']) + 1)
            self.assertEqual((pivot, side, local),
                             (case['pivot_index'], case['side'], case['local_index']))

    def test_failure_edges_are_bound_to_their_destinations(self):
        self.assertEqual(len(self.result['failures']), 14)
        for _, site, expected in evidence.FAILURE_EDGES:
            _, actual, _ = evidence.decode_branch(self.data, self.secs, site)
            self.assertEqual(actual, expected)

    def test_direct_call_opcode_and_branch_opcode_controls(self):
        site = evidence.DIRECT_CALLS[0][1]
        _, off = evidence.mapping(self.data, self.secs, site, 1)
        self.data[off] ^= 1
        try:
            with self.assertRaises(evidence.EvidenceError):
                evidence.decode_rel(self.data, self.secs, site, 'call5')
        finally:
            self.data[off] ^= 1
        with self.assertRaises(evidence.EvidenceError):
            evidence.decode_branch(self.data, self.secs, evidence.FUNCTIONS[0][1])

    def test_wrapper_mask_does_not_hide_retargeted_operands(self):
        differences, masks, _ = evidence.compare_wrappers(self.data, self.secs)
        self.assertEqual(len(differences), 12)
        self.assertEqual(len(masks), 6)
        for offset, kind, _ in evidence.WRAPPER_REL:
            with self.subTest(kind=kind, offset=offset):
                length = {'rip6': 6, 'call5': 5, 'lea7': 7}[kind]
                va = evidence.FUNCTIONS[0][1] + offset + length - 4
                _, file_offset = evidence.mapping(self.data, self.secs, va, 1)
                self.data[file_offset] ^= 1
                try:
                    with self.assertRaises(evidence.EvidenceError):
                        evidence.compare_wrappers(self.data, self.secs)
                finally:
                    self.data[file_offset] ^= 1
        # Retarget both copies by the same displacement: equality alone would
        # miss this, so the comparator checks the original destination as well.
        saved = []
        for base in (evidence.CONTEXT[0], evidence.FUNCTIONS[0][1]):
            _, file_offset = evidence.mapping(self.data, self.secs, base + 0x12b, 4)
            raw = bytes(self.data[file_offset:file_offset + 4])
            saved.append((file_offset, raw))
            value = struct.unpack('<i', raw)[0]
            self.data[file_offset:file_offset + 4] = struct.pack('<i', value + 1)
        try:
            with self.assertRaises(evidence.EvidenceError):
                evidence.compare_wrappers(self.data, self.secs)
        finally:
            for file_offset, raw in saved:
                self.data[file_offset:file_offset + 4] = raw
        # A changed nonoperand byte must also fail the masked comparison.
        _, file_offset = evidence.mapping(self.data, self.secs, evidence.FUNCTIONS[0][1] + 0x20, 1)
        self.data[file_offset] ^= 1
        try:
            with self.assertRaises(evidence.EvidenceError):
                evidence.compare_wrappers(self.data, self.secs)
        finally:
            self.data[file_offset] ^= 1

    def test_selected_relocations_and_diagnostic_locations(self):
        rows = {row[0]: row for row in self.result['slots']}
        self.assertEqual(rows['0x576dfe0'][-1], 'memcpy')
        self.assertEqual(rows['0x576e0e0'][-1], 'memmove')
        self.assertEqual(len(self.result['diagnostics']), 5)
        self.assertTrue(all(row[5] == 'src/collections/btree/node.rs'
                            for row in self.result['diagnostics']))
        with self.assertRaises(evidence.EvidenceError):
            evidence.get_relocations(self.data, self.secs, {0xffffffffffffffff})
        with self.assertRaises(evidence.EvidenceError):
            evidence.symbol_name(self.data, self.secs, 0xffffffff)

    def test_output_generation_is_repeatable(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            evidence.generate(base / 'a')
            evidence.generate(base / 'b')
            a = {p.name: hashlib.sha256(p.read_bytes()).digest() for p in (base / 'a').iterdir()}
            b = {p.name: hashlib.sha256(p.read_bytes()).digest() for p in (base / 'b').iterdir()}
            self.assertEqual(a, b)
            self.assertEqual(len(a), 14)


if __name__ == '__main__':
    unittest.main()
