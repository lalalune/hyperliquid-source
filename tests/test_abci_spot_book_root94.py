"""Offline controls for the node-94 spot-book hash-input evidence."""
import hashlib
import mmap
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import abci_spot_book_root94 as subject


class SpotBookEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Missing input is an error, not a skipped test.
        cls.file = subject.TARGET.open('rb')
        cls.data = mmap.mmap(cls.file.fileno(), 0, access=mmap.ACCESS_READ)
        subject.verify_digest(cls.data)
        cls.secs = subject.sections(cls.data)
        cls.frames = subject.check_frames(cls.data, cls.secs)
        cls.pred = {r[0]: int(r[-1], 16) for r in subject.predicate_rows(cls.data, cls.secs)}

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.file.close()

    def private_image(self):
        return mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_COPY)

    def test_target_digest_before_any_output(self):
        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent) / 'result'
            with patch.object(subject, 'SHA256', '0' * 64):
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    subject.extract(self.data, output)
            self.assertFalse(output.exists())

    def test_corrupted_target_digest_rejected(self):
        with self.private_image() as data:
            _, off = subject.location(self.secs, len(data), 0x25681e1, 1, True)
            data[off] ^= 1
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                subject.verify_digest(data)

    def test_all_selected_fdes_and_unmasked_hashes(self):
        self.assertEqual(len(self.frames), 22)
        for start, (end, digest) in subject.FDE_PINS.items():
            frame = self.frames[start]
            self.assertEqual(frame['end'], end)
            raw = subject.read(self.data, self.secs, start, end - start, True)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)

    def test_body_mutation_rejected_by_fde_evidence(self):
        with self.private_image() as data:
            _, off = subject.location(self.secs, len(data), 0x25681e1, 1, True)
            data[off] ^= 1
            with self.assertRaisesRegex(ValueError, 'changed body'):
                subject.check_frames(data, self.secs)

    def test_fde_range_mutation_rejected(self):
        with self.private_image() as data:
            fde = self.frames[0x25681d0]['fde']
            _, off = subject.location(self.secs, len(data), fde + 12, 1)
            data[off] ^= 1
            with self.assertRaises(ValueError):
                subject.check_frames(data, self.secs)

    def test_existing_connector_windows_are_pinned(self):
        subject.check_boundaries(self.data, self.secs)
        with self.private_image() as data:
            _, off = subject.location(self.secs, len(data), 0x2756220, 1, True)
            data[off] ^= 1
            with self.assertRaisesRegex(ValueError, 'boundary'):
                subject.check_boundaries(data, self.secs)

    def test_job_result_guards_and_failure_edge_reject_corruption(self):
        rows = subject.closure_results(self.data, self.secs)
        self.assertEqual([(r[0], int(r[4], 16), int(r[7], 16), int(r[8], 16))
                          for r in rows],
                         [('low', 0x8000000000000004, 0x2818a6c, 0x2818b62),
                          ('shared', 0x8000000000000004, 0x4ae79cc, 0x4ae7ac2)])
        with self.private_image() as data:
            for row in rows:
                start = int(row[1], 16)
                # Opcode, immediate, compare, branch opcode, branch displacement,
                # and successful buffer handoff all have independent witnesses.
                for relative in (0, 10, 18, 21, 23, 27):
                    _, off = subject.location(self.secs, len(data), start + relative, 1, True)
                    data[off] ^= 1
                    try:
                        with self.assertRaises(ValueError, msg=f'result guard {start:#x}+{relative}'):
                            subject.closure_results(data, self.secs)
                    finally:
                        data[off] ^= 1

    def test_synthetic_empty_book_wire_examples(self):
        anchors, rows, level_rows = subject.empty_examples(self.data, self.secs)
        self.assertEqual(len(anchors), 15)
        self.assertEqual(len(rows), 16)
        self.assertEqual(rows[0], (0, 0, 0, 1, '90'))
        self.assertEqual(rows[1], (1, 0, 0, 4, '91929090'))
        self.assertEqual(rows[15], (15, 0, 0, 46, '9f' + '929090' * 15))
        for n, first, second, length, wire in rows:
            self.assertEqual((first, second), (0, 0))
            self.assertEqual(length, 1 + 3 * n)
            self.assertEqual(bytes.fromhex(wire), bytes([0x90 | n]) + bytes.fromhex('929090') * n)
        self.assertEqual(level_rows, [
            (0, '00', 7, '91929192009090'),
            (1, '01', 7, '91929192019090'),
            (127, '7f', 7, '919291927f9090'),
            (128, 'cc80', 8, '91929192cc809090'),
            (255, 'ccff', 8, '91929192ccff9090')])

    def test_empty_model_anchors_and_loop_guards_reject_mutations(self):
        with self.private_image() as data:
            for _, site, expected, _, _ in subject.MODEL_ANCHORS:
                _, off = subject.location(self.secs, len(data), site, len(bytes.fromhex(expected)), True)
                data[off + len(bytes.fromhex(expected)) - 1] ^= 1
                try:
                    with self.assertRaises(ValueError, msg=f'model anchor {site:#x}'):
                        subject.empty_examples(data, self.secs)
                finally:
                    data[off + len(bytes.fromhex(expected)) - 1] ^= 1
            for site in (0x1e5d3dd, 0x1e500e4, 0x1e502c7):
                _, off = subject.location(self.secs, len(data), site, 1, True)
                data[off] ^= 1
                try:
                    with self.assertRaises(ValueError, msg=f'empty guard {site:#x}'):
                        subject.empty_examples(data, self.secs)
                finally:
                    data[off] ^= 1

    def test_synthetic_one_order_decodes_to_independent_shape(self):
        anchors, encoded = subject.one_order_example(self.data, self.secs)
        self.assertEqual(len(anchors), 10)

        # An independent minimal reader for the fixed forms used by this one
        # example. It does not execute the target or call the producer's model.
        def item(pos):
            tag = encoded[pos]
            pos += 1
            if tag <= 0x7f:
                return tag, pos
            if 0x90 <= tag <= 0x9f:
                result = []
                for _ in range(tag & 15):
                    value, pos = item(pos)
                    result.append(value)
                return result, pos
            if 0x80 <= tag <= 0x8f:
                result = {}
                for _ in range(tag & 15):
                    key, pos = item(pos)
                    value, pos = item(pos)
                    self.assertNotIn(key, result)
                    result[key] = value
                return result, pos
            if 0xa0 <= tag <= 0xbf:
                count = tag & 31
            elif tag == 0xd9:
                count, pos = encoded[pos], pos + 1
            elif tag in (0xc0, 0xc2, 0xc3):
                return {0xc0: None, 0xc2: False, 0xc3: True}[tag], pos
            else:
                self.fail(f'unexpected synthetic marker {tag:#x}')
            return encoded[pos:pos + count].decode('ascii'), pos + count

        decoded, end = item(0)
        self.assertEqual(end, len(encoded))
        order = {'is_position_tpsl': False, 'resting_sz': 1, 'orig_sz': 1,
                 'user': '0x' + '00' * 20, 'tif': None,
                 'core': {'s': 'B', 'l': 1}, 'oid': 1}
        self.assertEqual(decoded, [[[[1, [order]]], []]])
        self.assertEqual(list(decoded[0][0][0][1][0]), list(order))

    def test_one_order_model_anchors_reject_corruption(self):
        with self.private_image() as data:
            for _, site, expected, _, _ in subject.ORDER_MODEL_ANCHORS:
                _, off = subject.location(self.secs, len(data), site, len(bytes.fromhex(expected)), True)
                data[off + len(bytes.fromhex(expected)) - 1] ^= 1
                try:
                    with self.assertRaises(ValueError, msg=f'order model anchor {site:#x}'):
                        subject.one_order_example(data, self.secs)
                finally:
                    data[off + len(bytes.fromhex(expected)) - 1] ^= 1

    def test_synthetic_digest_model_known_answers_and_standard_sha3(self):
        _, rate, delimiter, out_size, rounds = subject.hash_parameters(self.data, self.secs)
        self.assertEqual((rate, delimiter, out_size, len(rounds)), (136, 1, 32, 24))
        self.assertEqual(subject.keccak_model(b'', rate, delimiter, out_size, rounds).hex(),
                         'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(subject.keccak_model(b'abc', rate, delimiter, out_size, rounds).hex(),
                         '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45')
        self.assertEqual(subject.keccak_model(bytes.fromhex('90'), rate, delimiter, out_size, rounds).hex(),
                         '632315f5af09a9a7da25ae16c4f8560df2b48d94d524d354b69f35289c56e0ea')
        self.assertEqual(subject.keccak_model(bytes.fromhex('91929090'), rate, delimiter, out_size, rounds).hex(),
                         '059fa9e00a00f3446bde77a696ed362576104466f6a45de5492cdebf4af94507')
        # SHA3 uses the same permutation with a different domain delimiter.
        for length in (0, 1, 31, 135, 136, 137, 271, 272):
            message = bytes(i % 256 for i in range(length))
            with self.subTest(length=length):
                self.assertEqual(subject.keccak_model(message, rate, 6, out_size, rounds),
                                 hashlib.sha3_256(message).digest())
        self.assertNotEqual(subject.keccak_model(b'abc', rate, delimiter, out_size, rounds),
                            hashlib.sha3_256(b'abc').digest())
        for invalid in ((135, 1, 32, rounds), (rate, 0, 32, rounds),
                        (rate, delimiter, rate + 1, rounds), (rate, delimiter, 32, rounds[:-1])):
            with self.assertRaises(ValueError):
                subject.keccak_model(b'', *invalid)

    def test_synthetic_digest_parameters_reject_corruption(self):
        with self.private_image() as data:
            for va in (0x2818ae5 - 5, 0x2818af1, 0x2818b20, 0x4f598f3,
                       0x4f5991d, 0x7d04c8):
                _, off = subject.location(self.secs, len(data), va, 1)
                data[off] ^= 1
                try:
                    with self.assertRaises(ValueError, msg=f'hash parameter {va:#x}'):
                        subject.hash_parameters(data, self.secs)
                finally:
                    data[off] ^= 1

    def test_all_branch_opcodes_and_displacements_reject_corruption(self):
        with self.private_image() as data:
            for _, site, expected, target in subject.BRANCH_PINS:
                owner, raw, dest = subject.branch_at(data, self.secs, site, expected, target)
                self.assertEqual(dest, target)
                self.assertLessEqual(owner, site)
                _, off = subject.location(self.secs, len(data), site, len(raw), True)
                for k in (0, len(raw) - 1):
                    data[off + k] ^= 1
                    try:
                        with self.assertRaises(ValueError, msg=f'branch {site:#x} byte {k}'):
                            subject.branch_at(data, self.secs, site, expected, target)
                    finally:
                        data[off + k] ^= 1

    def test_all_transfers_reject_opcode_and_target_corruption(self):
        with self.private_image() as data:
            for _, site, expected, target in subject.CALL_PINS:
                raw, actual = subject.transfer_at(data, self.secs, site, expected, target)
                self.assertEqual(actual, target)
                _, off = subject.location(self.secs, len(data), site, len(raw), True)
                for k in (0, 1, 4):
                    data[off + k] ^= 1
                    try:
                        with self.assertRaises(ValueError, msg=f'transfer {site:#x} byte {k}'):
                            subject.transfer_at(data, self.secs, site, expected, target)
                    finally:
                        data[off + k] ^= 1

    def test_wrong_transfer_destination_rejected(self):
        _, site, expected, target = subject.CALL_PINS[3]
        with self.assertRaisesRegex(ValueError, 'target'):
            subject.transfer_at(self.data, self.secs, site, expected, target + 1)

    def test_conditional_branches_remain_inside_declared_range(self):
        for _, site, expected, target in subject.BRANCH_PINS:
            start, raw, destination = subject.branch_at(self.data, self.secs, site, expected, target)
            self.assertLess(destination, subject.FDE_PINS[start][0])
            self.assertLessEqual(start, destination)
            self.assertIn(len(raw), (2, 6))

    def test_invalid_address_and_range_are_rejected(self):
        for va, size in ((0, 1), (-1, 1), (1 << 64, 1), (0x1dd94f0, 0)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                subject.location(self.secs, len(self.data), va, size, True)
        text_section = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaises(ValueError):
            subject.location([text_section], len(self.data),
                             text_section['address'] + text_section['size'] - 1, 2, True)

    def test_fileless_and_ambiguous_sections_rejected(self):
        bss = next(s for s in self.secs if s['type'] == 8 and s['size'] > 0)
        with self.assertRaises(ValueError):
            subject.location([bss], len(self.data), bss['address'], 1)
        code = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaises(ValueError):
            subject.location([code, dict(code)], len(self.data), code['address'], 1, True)

    def test_both_lane_names_and_literal_mutations(self):
        rows = subject.side_names(self.data, self.secs)
        self.assertEqual([(r[0], r[-1], r[-3]) for r in rows],
                         [('low', 'SideMap', 7), ('shared', 'SideMap', 7)])
        with self.private_image() as data:
            for row in rows:
                va = int(row[5], 16)
                _, off = subject.location(self.secs, len(data), va, 1)
                data[off] ^= 1
                try:
                    with self.assertRaises(ValueError):
                        subject.side_names(data, self.secs)
                finally:
                    data[off] ^= 1

    def test_exact_field_names_and_offsets(self):
        rows = subject.field_rows(self.data, self.secs)
        self.assertEqual([(r[1], int(r[-1], 16)) for r in rows], [
            ('is_position_tpsl', 0x35), ('resting_sz', 0), ('orig_sz', 8),
            ('user', 0x20), ('tif', 0x34), ('core', 0x18), ('oid', 0x10)])

    def test_generic_core_literals_and_side_choice(self):
        rows = subject.core_name_rows(self.data, self.secs)
        self.assertEqual([(r[0], r[-1]) for r in rows], [
            ('t', 't'), ('S', 'S'), ('r', 'r'), ('R', 'R'), ('d', 'd'),
            ('c', 'c'), ('b', 'b'), ('s', 's'), ('l', 'l'),
            ('side_bit_zero', 'B'), ('side_bit_one', 'A')])
        with self.private_image() as data:
            for row in rows:
                for va in (int(row[1], 16), int(row[3], 16) + 1, int(row[5], 16)):
                    _, off = subject.location(self.secs, len(data), va, 1)
                    data[off] ^= 1
                    try:
                        with self.assertRaises(ValueError, msg=f'core literal witness {va:#x}'):
                            subject.core_name_rows(data, self.secs)
                    finally:
                        data[off] ^= 1

    def test_field_literals_length_and_operands_reject_mutations(self):
        rows = subject.field_rows(self.data, self.secs)
        with self.private_image() as data:
            for row in rows:
                for va in (int(row[6], 16), int(row[4], 16) + 1, int(row[10], 16)):
                    _, off = subject.location(self.secs, len(data), va, 1)
                    data[off] ^= 1
                    try:
                        with self.assertRaises(ValueError, msg=f'field byte {va:#x}'):
                            subject.field_rows(data, self.secs)
                    finally:
                        data[off] ^= 1

    def test_slot_to_record_layout_and_borrowed_core(self):
        rows = subject.layout_rows(self.data, self.secs)
        mapping = {r[0]: (int(r[3], 16), int(r[6], 16), r[7]) for r in rows}
        self.assertEqual(mapping, {
            'sizes': (0xc8, 0, 16), 'oid': (0xd8, 0x10, 8),
            'core_reference': (0x20, 0x18, 8), 'user_first': (0xe0, 0x20, 16),
            'user_last': (0xf0, 0x30, 4), 'tif': (0xf5, 0x34, 1),
            'is_position_tpsl': (0xf4, 0x35, 1)})
        self.assertEqual(self.pred['initial_capacity'] * self.pred['order_record_stride'],
                         self.pred['initial_allocation_bytes'])

    def test_each_layout_instruction_rejects_mutation(self):
        with self.private_image() as data:
            for _, source, src_hex, _, _, destination, dst_hex, _, _ in subject.LAYOUT:
                for va, raw in ((source, src_hex), (destination, dst_hex)):
                    _, off = subject.location(self.secs, len(data), va, len(bytes.fromhex(raw)), True)
                    data[off + len(bytes.fromhex(raw)) - 1] ^= 1
                    try:
                        with self.assertRaises(ValueError):
                            subject.layout_rows(data, self.secs)
                    finally:
                        data[off + len(bytes.fromhex(raw)) - 1] ^= 1

    def test_predicate_constants_come_from_instruction_bytes(self):
        self.assertEqual(self.pred['head_present_tag'], 1)
        self.assertEqual(self.pred['vacant_slot_tag'], 2)
        self.assertEqual(self.pred['slab_slot_stride'], 248)
        self.assertEqual(self.pred['order_record_stride'], 56)
        self.assertEqual(self.pred['side_map_stride'], 48)
        self.assertEqual(1 << self.pred['tree_level_shift'], self.pred['price_level_stride'])
        self.assertEqual(self.pred['price_pair_length'], 2)

    def test_synthetic_head_admission_boundaries(self):
        present = self.pred['head_present_tag']
        vacant = self.pred['vacant_slot_tag']
        def admit(tag, index, count, slot_word):
            return ((tag & 0xffffffff) == present and index < count
                    and (slot_word & 0xffffffff) != vacant)
        cases = [
            (0, 0, 1, 0, False), (present, 0, 0, 0, False),
            (present, 1, 1, 0, False), (present, 0, 1, vacant, False),
            (present, 0, 1, 0, True), (present, 0, 1, 3, True),
            ((1 << 32) | present, 0, 1, 0, True),
            (present, 0, 1, (1 << 32) | vacant, False),
        ]
        for tag, index, count, slot, expected in cases:
            with self.subTest(tag=tag, index=index, count=count, slot=slot):
                self.assertEqual(admit(tag, index, count, slot), expected)

    def test_synthetic_linked_prefix_stops_on_corruption(self):
        # A finite, acyclic arithmetic model of the pinned guards, not execution.
        present, vacant = self.pred['head_present_tag'], self.pred['vacant_slot_tag']
        def prefix(head_tag, head_index, slots):
            if (head_tag & 0xffffffff) != present or head_index >= len(slots):
                return []
            result, index = [], head_index
            while index < len(slots) and (slots[index][0] & 0xffffffff) != vacant:
                if index in result:
                    raise ValueError('fixture must be acyclic')
                result.append(index)
                next_tag, index = slots[index][1:]
                if next_tag == 0:
                    break
            return result
        self.assertEqual(prefix(1, 0, [(0, 1, 1), (0, 0, 0)]), [0, 1])
        self.assertEqual(prefix(1, 0, [(0, 2, 1), (0, 0, 0)]), [0, 1])
        self.assertEqual(prefix(1, 0, [(0, 1, 1), (2, 0, 0)]), [0])
        self.assertEqual(prefix(1, 0, [(0, 1, 2)]), [0])
        self.assertEqual(prefix(0, 0, [(0, 0, 0)]), [])
        self.assertEqual(prefix(1, 1, [(0, 0, 0)]), [])

    def test_core_optional_field_count_and_noncanonical_boundaries(self):
        # Code-derived algebra and separately listed emission predicates; these
        # cases are synthetic inputs and do not execute the captured node.
        prologue = subject.read(self.data, self.secs, 0x23328d9, 0x68, True)
        generic = subject.read(self.data, self.secs, 0x2332028, 0x68, True)
        for witness in (bytes.fromhex('4c8bae88000000'), bytes.fromhex('4c8b26'),
                        bytes.fromhex('0fb6ae90000000'), bytes.fromhex('488b5670'),
                        bytes.fromhex('0fb6b691000000'), bytes.fromhex('498b5748')):
            self.assertIn(witness, prologue)
            self.assertIn(witness, generic)
        subject.check_bytes(self.data, self.secs, 0x23d4205, 'c6043152')
        subject.check_bytes(self.data, self.secs, 0x23d4caa, '41c6040064')
        subject.check_bytes(self.data, self.secs, 0x23d47d3, 'c6040173')
        subject.check_bytes(self.data, self.secs, 0x2332c7d, 'c604316c')

        def arithmetic(t, big_s, r, combined, d, c, b):
            return (2 + int(t != 0) + (big_s & 0xffffffff) + r
                    + (combined & 1) + int(d != 0) + c + (b & 0xffffffff)) & 0xffffffff

        def emitted(t, big_s, r, combined, d, c, b):
            return sum((t != 0, (big_s & 0xff) != 0, r != 0, bool(combined & 1),
                        d != 0, c != 0, (b & 0xff) != 0)) + 2

        for bits in range(128):
            values = [(bits >> i) & 1 for i in range(7)]
            self.assertEqual(arithmetic(*values), emitted(*values), f'mask {bits:#x}')
        self.assertNotEqual(arithmetic(0, 0x100, 0, 0, 0, 0, 0),
                            emitted(0, 0x100, 0, 0, 0, 0, 0))
        self.assertNotEqual(arithmetic(0, 0, 2, 0, 0, 0, 0),
                            emitted(0, 0, 2, 0, 0, 0, 0))
        self.assertNotEqual(arithmetic(0, 0, 0, 0, 0, 0, 0x100),
                            emitted(0, 0, 0, 0, 0, 0, 0x100))

    def test_signed_price_boundaries(self):
        subject.check_bytes(self.data, self.secs, 0x26b0b5b, '48f7d8480f48c5')
        def result(word):
            return abs(word) if word != -(1 << 63) else 1 << 63
        for value, expected in [(-(1 << 63), 1 << 63), (-1, 1), (0, 0),
                                (1, 1), ((1 << 63) - 1, (1 << 63) - 1)]:
            self.assertEqual(result(value), expected)

    def test_exception_tables_and_corrupt_header(self):
        headers = []
        for frame in self.frames.values():
            head, rows = subject.parse_lsda(self.data, self.secs, frame)
            if head:
                headers.append((frame, head, rows))
        self.assertEqual(len(headers), 11)
        frame, head, rows = headers[0]
        self.assertEqual(head['rows'], len(rows))
        with self.private_image() as data:
            data[head['offset']] ^= 1
            with self.assertRaisesRegex(ValueError, 'LSDA'):
                subject.parse_lsda(data, self.secs, frame)

    def test_lsda_landing_for_tree_to_slot_call(self):
        frame = self.frames[0x26b0930]
        _, rows = subject.parse_lsda(self.data, self.secs, frame)
        lookup = 0x26b0b50 + 4
        matches = [row for row in rows if row['begin'] <= lookup < row['end']]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['landing'], 0x26b0be6)
        self.assertEqual(matches[0]['action'], 0)

    def test_raw_twin_comparison_reports_mutation(self):
        base = subject.twin_rows(self.data, self.secs)
        self.assertTrue(base)
        with self.private_image() as data:
            _, off = subject.location(self.secs, len(data), 0x1e5d350, 1, True)
            data[off] ^= 1
            self.assertNotEqual(base, subject.twin_rows(data, self.secs))


if __name__ == '__main__':
    unittest.main()
