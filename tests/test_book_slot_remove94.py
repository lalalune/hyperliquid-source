# SPDX-License-Identifier: MIT
import hashlib
import struct
import unittest
from unittest.mock import patch

from tools import book_slot_remove94 as book
from tools.elf_index import sections


class StaticEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(book.BINARY.read_bytes())

    def mutate(self, va, callback):
        off = book.file_offset(self.data, va, 1)
        original = self.data[off]
        try:
            self.data[off] ^= 1
            callback()
        finally:
            self.data[off] = original

    def test_identity_and_reject_changed_digest(self):
        book.authenticate(self.data)
        self.mutate(book.FUNCTIONS[0][1], lambda: self.assertRaises(book.EvidenceError, book.authenticate, self.data))

    def test_all_selected_fde_ranges_and_body_hashes(self):
        rows = book.functions(self.data)
        self.assertEqual(len(rows), 6)
        for row, expected in zip(rows, book.FUNCTIONS):
            self.assertEqual(row['sha256'], expected[3])
            self.assertEqual(row['size'], expected[2] - expected[1])
        original = book.FUNCTIONS[0]
        invalid = (original[0], original[1], original[2] + 1, original[3])
        with patch.object(book, 'FUNCTIONS', (invalid,)):
            with self.assertRaises(book.EvidenceError):
                book.functions(self.data)
        self.mutate(original[1] + 1, lambda: self.assertRaises(book.EvidenceError, book.functions, self.data))
        frame = next(sec for sec in sections(self.data) if sec['name'] == '.eh_frame')
        fde_address = int(rows[0]['fde_va'], 16)
        # FDE pc-range field is a signed four-byte value following the start.
        off = frame['offset'] + fde_address - frame['address'] + 12
        before = self.data[off]
        try:
            self.data[off] ^= 1
            with self.assertRaises(book.EvidenceError):
                book.functions(self.data)
        finally:
            self.data[off] = before

    def test_each_selected_witness_rejects_corruption(self):
        self.assertEqual(len(book.checked_witnesses(self.data)), len(book.ANCHORS))
        for _, va, _ in book.ANCHORS:
            with self.subTest(va=hex(va)):
                self.mutate(va, lambda: self.assertRaises(book.EvidenceError, book.checked_witnesses, self.data))

    def test_branch_opcode_and_destination_corruption(self):
        for site, opcode, meaning in book.BRANCHES:
            with self.subTest(site=hex(site)):
                book.branch(self.data, site, opcode, meaning)
                self.mutate(site, lambda: self.assertRaises(book.EvidenceError, book.branch, self.data, site, opcode, meaning))
                self.mutate(site + len(bytes.fromhex(opcode)),
                            lambda: self.assertRaises(book.EvidenceError, book.branch, self.data, site, opcode, meaning))

    def test_direct_calls_reject_retargeting(self):
        for site, target in book.CALLS:
            with self.subTest(site=hex(site)):
                book.direct_call(self.data, site, target)
                self.mutate(site + 1, lambda: self.assertRaises(book.EvidenceError, book.direct_call, self.data, site, target))
                with self.assertRaises(book.EvidenceError):
                    book.direct_call(self.data, site, target + 1)

    def test_diagnostics_relocations_and_corruption(self):
        rows = book.diagnostic_records(self.data)
        self.assertEqual(len(rows), len(book.DIAGNOSTICS))
        self.assertTrue(all(row['path_suffix'] == 'src/collections/btree/node.rs' for row in rows))
        for site, _, _, _ in book.DIAGNOSTICS:
            with self.subTest(site=hex(site)):
                self.mutate(site + 3, lambda: self.assertRaises(book.EvidenceError, book.diagnostic_records, self.data))
        with self.assertRaises(book.EvidenceError):
            book.relative_relocations(self.data, {0})
        for address in (int(rows[0]['message_va'], 16), int(rows[0]['location_va'], 16) + 16,
                        int(rows[0]['path_va'], 16)):
            sec = next(s for s in sections(self.data) if s['type'] != 8 and
                       s['address'] <= address < s['address'] + s['size'])
            off = sec['offset'] + address - sec['address']
            original = self.data[off]
            try:
                self.data[off] ^= 1
                with self.assertRaises(book.EvidenceError):
                    book.diagnostic_records(self.data)
            finally:
                self.data[off] = original

    def test_indirect_calls_and_relocation_corruption(self):
        self.assertEqual(len(book.INDIRECT_CALLS), 33)
        for site, target in book.INDIRECT_CALLS:
            with self.subTest(site=hex(site)):
                book.indirect_call(self.data, site, target)
                self.mutate(site + 2, lambda: self.assertRaises(book.EvidenceError, book.indirect_call, self.data, site, target))
        rows = book.slot_relocations(self.data)
        self.assertEqual(len(rows), 6)
        self.assertEqual([x['symbol_name'] for x in rows if x['symbol_name']], ['memcpy', 'memmove'])
        target = book.INDIRECT_CALLS[0][1]
        matching = []
        for sec in sections(self.data):
            if sec['type'] == 4:
                for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
                    if struct.unpack_from('<Q', self.data, off)[0] == target:
                        matching.append(off)
        self.assertEqual(len(matching), 1)
        off = matching[0] + 8
        original = self.data[off]
        try:
            self.data[off] ^= 1
            with self.assertRaises(book.EvidenceError):
                book.slot_relocations(self.data)
        finally:
            self.data[off] = original

    def test_mapping_rejects_unbacked_and_ambiguous_ranges(self):
        with self.assertRaises(book.EvidenceError):
            book.file_offset(self.data, 0, 1)
        with self.assertRaises(book.EvidenceError):
            book.file_offset(self.data, book.FUNCTIONS[0][1], 0)
        bss = next(s for s in sections(self.data) if s['name'] == '.bss')
        with self.assertRaises(book.EvidenceError):
            book.read_data_va(self.data, bss['address'], 1)
        with self.assertRaises(book.EvidenceError):
            book.read_data_va(self.data, 0xffffffffffffffff, 1)

    def test_evidence_constants_and_local_slots(self):
        evidence = book.collect(self.data)
        self.assertEqual(evidence['target_sha256'], hashlib.sha256(self.data).hexdigest())
        self.assertEqual(evidence['decoded_constants']['capacity_exclusive'], 12)
        self.assertEqual(evidence['decoded_constants']['upward_target_count'], 5)
        self.assertEqual([x['slot_va'] for x in evidence['selected_rip_relative_slots']],
                         ['0x576e0e0', '0x576dfe0', '0x576e010'])
        self.assertEqual(len(evidence['calls']), 9)
        self.assertEqual(len(evidence['diagnostics']), 12)
        self.assertEqual(len(evidence['indirect_calls']), 33)


class SyntheticModelTests(unittest.TestCase):
    def test_repair_thresholds_and_sibling_priority(self):
        for current in range(5):
            for side in (False, True):
                for sibling in range(12):
                    with self.subTest(current=current, sibling=sibling, side=side):
                        row = book.repair_decision(current, sibling, side)
                        self.assertEqual(row['combined'], current + sibling + 1)
                        self.assertEqual(row['direction'], 'left' if side else 'right')
                        self.assertEqual(row['operation'], 'merge' if current + sibling + 1 < 12 else 'borrow')
                        if row['operation'] == 'borrow':
                            self.assertEqual(row['borrow_count'], 5 - current)
        for args in [(-1, 5, True), (5, 5, True), (4, 12, True), (4, 7, 1), (4, -1, False)]:
            with self.assertRaises(ValueError):
                book.repair_decision(*args)

    def test_synthetic_scenarios_and_upward_transitions(self):
        cases = {row['name']: row for row in book.scenario_rows()}
        self.assertEqual(len(cases), 15)
        self.assertFalse(cases['empty_miss']['result']['found'])
        self.assertEqual(cases['internal_predecessor']['result']['events'][0]['kind'], 'predecessor')
        self.assertEqual(cases['root_merge']['height_after'], 0)
        self.assertEqual(cases['deep_contract']['height_after'], 1)
        self.assertFalse(cases['deep_miss']['result']['found'])
        self.assertEqual(cases['internal_predecessor_merge']['height_after'], 0)
        self.assertEqual([x['kind'] for x in cases['three_level_contract']['result']['events']],
                         ['merge', 'merge', 'merge', 'root_contract'])
        for side in ('left', 'right'):
            event = cases['leaf_merge_' + side + '_boundary']['result']['events'][0]
            self.assertEqual((event['kind'], event['side'], event['sibling_count']), ('merge', side, 6))
        self.assertEqual([x['kind'] for x in cases['deep_contract']['result']['events']],
                         ['merge', 'merge', 'root_contract'])
        self.assertEqual(cases['leaf_borrow_left']['result']['events'][0]['side'], 'left')
        self.assertEqual(cases['leaf_borrow_right']['result']['events'][0]['side'], 'right')
        for side in ('left', 'right'):
            events = cases['deep_borrow_' + side]['result']['events']
            self.assertEqual([(e['kind'], e['node_height']) for e in events], [('merge', 0), ('borrow', 1)])
            self.assertEqual(events[1]['side'], side)
            self.assertEqual(events[1]['amount'], 1)
        self.assertEqual(cases['deep_merge_root_retained']['height_after'], 2)

    def test_sequential_deletions_conserve_keys_and_reject_repeat(self):
        root = book.Node(2, [book.internal(5), book.internal(5), book.internal(5)])
        size = book.fill_keys(root)
        self.assertEqual(size, 107)
        remaining = set(range(size))
        for i in range(size):
            key = (i * 37) % size
            root, result = book.remove_model(root, key)
            self.assertTrue(result['found'])
            remaining.remove(key)
            self.assertEqual(book.check_tree(root), sorted(remaining))
            root, result = book.remove_model(root, key)
            self.assertFalse(result['found'])
        self.assertEqual(book.flat(root), [])

    def test_invalid_fixtures_and_invalid_keys_are_rejected(self):
        with self.assertRaises(ValueError):
            book.Node(3, [book.Node(5)])
        with self.assertRaises(ValueError):
            book.Node(12)
        root, _ = book.make_fixture('root_merge')
        with self.assertRaises(ValueError):
            book.remove_model(root, -1)
        root.children[0].keys[0] = root.children[1].keys[0]
        with self.assertRaises(ValueError):
            book.check_tree(root)


if __name__ == '__main__':
    unittest.main()
