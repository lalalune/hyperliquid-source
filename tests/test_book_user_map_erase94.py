# SPDX-License-Identifier: MIT
import json
from pathlib import Path
import unittest

from tools import book_user_map_erase94 as subject
from tools.elf_index import sections, unwind_index
from tools.fde_extents import eh_frame_records


class BookUserMapEraseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.BINARY.read_bytes()
        cls.secs, cls.index = unwind_index(cls.data)
        _, cls.fdes = eh_frame_records(cls.data, cls.secs)
        cls.results = subject.extract(cls.data)

    def test_digest_is_verified(self):
        subject.checked_digest(self.data)
        altered = bytearray(self.data)
        altered[0] ^= 1
        with self.assertRaises(subject.EvidenceError):
            subject.checked_digest(altered)

    def test_fdes_have_index_bindings(self):
        selected = subject.bind_fdes(self.fdes, self.index)
        self.assertEqual(set(selected), {x[0] for x in subject.FUNCTIONS})
        self.assertEqual(len(selected), 6)

    def test_reject_extent_corruption(self):
        bad = [dict(row) for row in self.fdes]
        target = subject.FUNCTIONS[0][1]
        next(row for row in bad if row['start'] == target)['end'] += 1
        with self.assertRaises(subject.EvidenceError):
            subject.bind_fdes(bad, self.index)

    def test_reject_unwind_index_corruption(self):
        bad = [dict(row) for row in self.index]
        target = subject.FUNCTIONS[0][1]
        next(row for row in bad if row['start'] == target)['fde'] += 4
        with self.assertRaises(subject.EvidenceError):
            subject.bind_fdes(self.fdes, bad)

    def test_each_body_hash_detects_corruption(self):
        for role, start, end, digest in subject.FUNCTIONS:
            with self.subTest(role=role):
                body = subject.get_bytes(self.data, self.secs, start, end-start)
                subject.check_body(body, digest)
                bad = bytearray(body)
                bad[len(bad)//2] ^= 1
                with self.assertRaises(subject.EvidenceError):
                    subject.check_body(bad, digest)

    def test_each_witness_rejects_changed_byte(self):
        for name, address, expected in subject.WITNESSES:
            with self.subTest(name=name):
                raw = subject.get_bytes(self.data, self.secs, address, len(expected)//2)
                subject.check_bytes(raw, expected)
                for position in range(len(raw)):
                    bad = bytearray(raw)
                    bad[position] ^= 1
                    with self.assertRaises(subject.EvidenceError):
                        subject.check_bytes(bad, expected)

    def test_all_branches_decode_and_reject_changes(self):
        for name, address, expected in subject.BRANCHES:
            with self.subTest(name=name):
                raw = subject.get_bytes(self.data, self.secs, address, len(expected)//2)
                code, target = subject.decode_branch(address, raw)
                self.assertLessEqual(code, 15)
                subject.map_offset(self.secs, target, 1, True)
                for position in (0, len(raw)-1):
                    bad = bytearray(raw)
                    bad[position] ^= 1
                    with self.assertRaises(subject.EvidenceError):
                        subject.check_bytes(bad, expected)
        with self.assertRaises(subject.EvidenceError):
            subject.decode_branch(0, b'\x90\x00')

    def test_direct_call_graph(self):
        observed = {name: subject.decode_call(address, bytes.fromhex(raw)) for name, address, raw in subject.CALLS}
        self.assertEqual(observed['caller_cursor'], 0x42b6040)
        self.assertEqual(observed['cursor_direct_leaf'], 0x42a1bf0)
        self.assertEqual(observed['cursor_predecessor_leaf'], 0x42a1bf0)
        self.assertEqual(observed['leaf_merge'], 0x4283610)
        self.assertEqual(observed['leaf_borrow_left'], 0x4276080)
        self.assertEqual(observed['leaf_borrow_right'], 0x4279bc0)
        self.assertEqual(observed['leaf_ancestor'], 0x41d6110)
        self.assertEqual(observed['leaf_cleanup'], 0x41d5b70)
        self.assertEqual(observed['leaf_cleanup_exit'], 0x5660110)
        with self.assertRaises(subject.EvidenceError):
            subject.decode_call(0, b'\x90\x00\x00\x00\x00')

    def test_all_direct_call_bytes_reject_corruption(self):
        for name, address, expected in subject.CALLS:
            raw = subject.get_bytes(self.data, self.secs, address, 5)
            with self.subTest(name=name):
                self.assertEqual(subject.decode_call(address, raw), subject.decode_call(address, bytes.fromhex(expected)))
                for position in (0, 1, 4):
                    altered = bytearray(raw)
                    altered[position] ^= 1
                    with self.assertRaises(subject.EvidenceError):
                        subject.check_bytes(altered, expected)

    def test_all_indirect_instruction_bytes_reject_corruption(self):
        for name, address, expected in subject.INDIRECT:
            raw = subject.get_bytes(self.data, self.secs, address, len(expected)//2)
            with self.subTest(name=name):
                self.assertEqual(subject.decode_rip(address, raw), subject.decode_rip(address, bytes.fromhex(expected)))
                for position in (0, len(raw)-1):
                    altered = bytearray(raw)
                    altered[position] ^= 1
                    with self.assertRaises(subject.EvidenceError):
                        subject.check_bytes(altered, expected)

    def test_indirect_relocations(self):
        slots = set()
        for _, address, expected in subject.INDIRECT:
            raw = bytes.fromhex(expected)
            slots.add(subject.decode_rip(address, raw))
        rows = subject.relocation_rows(self.data, self.secs, slots)
        self.assertEqual(len(rows), 4)
        names = {row[3] for row in rows}
        self.assertTrue({'memcpy', 'memmove'} <= names)
        with self.assertRaises(subject.EvidenceError):
            subject.decode_rip(0, b'\x90' * 6)
        with self.assertRaises(subject.EvidenceError):
            subject.relocation_rows(self.data, self.secs, {0})

    def test_relocation_addend_corruption_is_rejected(self):
        import struct
        target = 0x576e010
        altered = bytearray(self.data)
        found = False
        for sec in self.secs:
            if sec['type'] != 4:
                continue
            for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
                if struct.unpack_from('<Q', altered, off)[0] == target:
                    altered[off+16] ^= 1
                    found = True
                    break
            if found:
                break
        self.assertTrue(found)
        with self.assertRaises(subject.EvidenceError):
            subject.relocation_rows(altered, self.secs, {target})

    def test_diagnostic_sequences_reject_corruption(self):
        for name, address, expected in subject.DIAGNOSTICS:
            with self.subTest(name=name):
                raw = subject.get_bytes(self.data, self.secs, address, 25)
                subject.check_bytes(raw, expected)
                bad = bytearray(raw)
                bad[10] ^= 1
                with self.assertRaises(subject.EvidenceError):
                    subject.check_bytes(bad, expected)

    def test_diagnostic_location_pointer_corruption(self):
        import struct
        address = subject.DIAGNOSTICS[0][1]
        instruction = subject.get_bytes(self.data, self.secs, address, 25)
        location = address + 14 + struct.unpack_from('<i', instruction, 10)[0]
        offset = subject.map_offset(self.secs, location, 24)
        altered = bytearray(self.data)
        altered[offset] = 1
        with self.assertRaises(subject.EvidenceError):
            subject.diagnostic_rows(altered, self.secs)

    def test_reject_unmapped_and_non_file_backed_addresses(self):
        with self.assertRaises(subject.EvidenceError):
            subject.map_offset(self.secs, 0, 1, True)
        with self.assertRaises(subject.EvidenceError):
            subject.map_offset(self.secs, -1, 1)
        with self.assertRaises(subject.EvidenceError):
            subject.map_offset(self.secs, subject.FUNCTIONS[0][1], 0)
        bss = next(s for s in self.secs if s['type'] == 8 and s['size'])
        with self.assertRaises(subject.EvidenceError):
            subject.map_offset([bss], bss['address'], 1)
        section = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaises(subject.EvidenceError):
            subject.map_offset([section, dict(section)], section['address'], 1, True)

    def test_merge_boundary_for_both_sides(self):
        for side in ('left', 'right'):
            self.assertEqual(subject.repair_decision(4, 6, side, 5, 12), 'merge')
            self.assertEqual(subject.repair_decision(4, 7, side, 5, 12), 'borrow_' + side)
            self.assertEqual(subject.repair_decision(0, 10, side, 5, 12), 'merge')
            self.assertEqual(subject.repair_decision(0, 11, side, 5, 12), 'borrow_' + side)

    def test_leaf_projection_preserves_order_and_associated_values(self):
        for side in ('left', 'right'):
            for donor_count in (5, 6, 7, 11):
                if side == 'left':
                    donor = [(i, i*10) for i in range(donor_count)]
                    sep = (donor_count, donor_count*10)
                    target = [(i, i*10) for i in range(donor_count+1, donor_count+6)]
                else:
                    target = [(i, i*10) for i in range(5)]
                    sep = (5, 50)
                    donor = [(i, i*10) for i in range(6, 6+donor_count)]
                for position in (0, 2, 4):
                    result = subject.project_leaf(target, donor, sep, position, side)
                    if result['action'] == 'merge':
                        ordered = result['merged']
                    elif side == 'left':
                        ordered = result['sibling'] + [result['separator']] + result['target']
                    else:
                        ordered = result['target'] + [result['separator']] + result['sibling']
                    original = sorted(target + donor + [sep])
                    original.remove(target[position])
                    self.assertEqual(ordered, original)
                    self.assertEqual(result['deleted'], target[position])
                    self.assertEqual(result['action'].startswith('borrow'), donor_count >= 7)

    def test_two_level_merge_and_root_contraction(self):
        case = subject.project_two_level(5, 12)
        root = case['after']
        self.assertEqual(case['events'], ['leaf_merge_right', 'ancestor_merge_right', 'root_contract'])
        self.assertEqual(len(root['keys']), 10)
        self.assertEqual(len(root['children']), 11)
        self.assertEqual(len(root['children'][0]), 10)
        sequence = []
        for index, leaf in enumerate(root['children']):
            sequence.extend(leaf)
            if index < len(root['keys']):
                sequence.append(root['keys'][index])
        self.assertEqual(sequence, [(i, 1000+i) for i in range(71) if i != 2])
        self.assertEqual(case['deleted'], (2, 1002))
        with self.assertRaises(subject.EvidenceError):
            subject.project_two_level(4, 12)

    def test_leaf_projection_rejects_corrupted_state(self):
        target = [(i, i) for i in range(7, 12)]
        sibling = [(i, i) for i in range(6)]
        with self.assertRaises(subject.EvidenceError):
            subject.project_leaf(target, sibling, (5, 5), 0, 'left')
        with self.assertRaises(subject.EvidenceError):
            subject.project_leaf(target, sibling, (6, 6), 5, 'left')
        with self.assertRaises(subject.EvidenceError):
            subject.project_leaf(target[:4], sibling, (6, 6), 0, 'left')

    def test_header_counter_decrement_boundaries(self):
        self.assertEqual(subject.project_header_decrement(1), 0)
        self.assertEqual(subject.project_header_decrement(0), (1 << 64)-1)
        self.assertEqual(subject.project_header_decrement((1 << 64)-1), (1 << 64)-2)
        for invalid in (-1, 1 << 64):
            with self.assertRaises(subject.EvidenceError):
                subject.project_header_decrement(invalid)

    def test_reject_invalid_projection_inputs(self):
        for remaining, sibling, side in [(-1, 5, 'left'), (5, 5, 'left'), (4, 12, 'left'), (4, 6, 'bad')]:
            with self.subTest(values=(remaining, sibling, side)):
                with self.assertRaises(subject.EvidenceError):
                    subject.repair_decision(remaining, sibling, side, 5, 12)

    def test_output_matches_retained_evidence(self):
        directory = subject.ROOT / 'research/work-items/RE-006-user-map-erase-repair-94'
        for name, contents in self.results.items():
            with self.subTest(name=name):
                self.assertEqual((directory / name).read_bytes(), contents)

    def test_summary_counts_and_projection(self):
        row = json.loads(self.results['summary.json'])
        self.assertEqual(row['selected_fdes'], 6)
        self.assertEqual(row['selected_body_bytes'], sum(end-start for _,start,end,_ in subject.FUNCTIONS))
        self.assertEqual(row['conditional_branches'], len(subject.BRANCHES))
        self.assertEqual(row['projection_rows'], 120)
        self.assertEqual(row['structural_projection_rows'], 24)
        self.assertEqual(row['two_level_examples'], 1)
        self.assertEqual(row['counter_projection_rows'], 4)
        self.assertEqual(row['merge_exclusive_limit'], 12)


if __name__ == '__main__':
    unittest.main()
