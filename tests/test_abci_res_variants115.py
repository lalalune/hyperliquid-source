# SPDX-License-Identifier: MIT
"""Static corruption controls and bounded wire projections for node #115."""
import contextlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
import abci_res_variants115 as subject


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(subject.TARGET.read_bytes())
        subject.verify_digest(cls.data)
        cls.image = subject.Image(cls.data)
        cls.table, cls.rows, cls.branches = subject.map_variants(cls.image)

    @contextlib.contextmanager
    def changed(self, va, replacement):
        offset = self.image.offset(va, len(replacement))
        old = self.data[offset:offset + len(replacement)]
        self.data[offset:offset + len(replacement)] = replacement
        try:
            yield
        finally:
            self.data[offset:offset + len(replacement)] = old

    def flip(self, va):
        return self.changed(va, bytes([self.image.read(va, 1)[0] ^ 1]))

    def test_all_fifteen_table_names_and_targets(self):
        expected = [
            ('order', 0x4e0d3c0), ('cancel', 0x4e0d4c0), ('createVault', 0x4e0dc50),
            ('liquidation', 0x4e0c0b0), ('twapOrder', 0x4e0c240), ('twapCancel', 0x4e0fb90),
            ('trailingStop', 0x4e0c7c0), ('createSubAccount', 0x4e0ef70),
            ('token', 0x4e0dd90), ('spot', 0x4e0dd90), ('validatorVote', 0x4e0f0d0),
            ('governanceProposal', 0x4e0fc50), ('setGlobal', 0x4e0fbf0),
            ('delayed', 0x4e0c110), ('default', None),
        ]
        self.assertEqual(self.table, 0x914e5c)
        self.assertEqual([(row['label'], row['payload_target_va']) for row in self.rows], expected)
        self.assertEqual([r['tag'] for r in self.rows], list(range(15)))
        self.assertEqual([r['container_count'] for r in self.rows], [2] * 14 + [1])
        self.assertEqual(len(self.branches), 90)

    def test_every_table_entry_rejects_corruption(self):
        for tag in range(15):
            with self.subTest(tag=tag), self.flip(self.table + 4 * tag):
                with self.assertRaises(ValueError):
                    subject.map_variants(self.image)

    def test_each_variant_label_is_bound_to_its_bytes(self):
        for row in self.rows:
            with self.subTest(tag=row['tag']), self.flip(row['label_va']):
                with self.assertRaises(ValueError):
                    subject.map_variants(self.image)

    def test_mutated_mode_condition_is_rejected(self):
        branch_va = self.branches[0]['va']
        self.assertEqual(self.image.read(branch_va, 2), b'\x0f\x84')
        with self.flip(branch_va + 1), self.assertRaises(ValueError):
            subject.map_variants(self.image)

    def test_each_selected_variant_branch_rejects_inversion(self):
        for row in self.branches:
            address = row['va'] + (1 if row['bytes'].startswith('0f') else 0)
            with self.subTest(tag=row['tag'], role=row['role']), self.flip(address):
                with self.assertRaises(ValueError):
                    subject.map_variants(self.image)

    def test_failure_destinations_reject_displacement_damage(self):
        for role in ('array_header_failure', 'type_key_failure', 'label_failure'):
            row = next(r for r in self.branches if r['tag'] == 0 and r['role'] == role)
            displacement = row['va'] + (2 if row['bytes'].startswith('0f') else 1)
            with self.subTest(role=role), self.flip(displacement):
                with self.assertRaises(ValueError):
                    subject.map_variants(self.image)

    def test_mutated_map_header_count_is_rejected(self):
        call = self.rows[0]['map_header_call_va']
        with self.flip(call - 4), self.assertRaises(ValueError):
            subject.map_variants(self.image)

    def test_mutated_payload_call_is_rejected(self):
        with self.flip(self.rows[0]['payload_call_va'] + 1), self.assertRaises(ValueError):
            subject.map_variants(self.image)

    def test_mutated_payload_projection_is_rejected(self):
        row = self.rows[0]
        call = row['payload_call_va']
        start = call - len(bytes.fromhex(row['payload_argument_bytes']))
        pos = self.image.read(start, call - start).index(b'\x49\x83\xc7\x08')
        with self.flip(start + pos + 3), self.assertRaises(ValueError):
            subject.map_variants(self.image)

    def test_mutated_type_literal_is_rejected(self):
        with self.flip(0x45a144), self.assertRaises(ValueError):
            subject.map_variants(self.image)

    def test_special_tag_branch_and_delayed_fields(self):
        edge = subject.extract_core(self.image)
        self.assertEqual((edge['kind'], edge['target']), ('jne', 0x59229ee))
        with self.flip(0x59229c2), self.assertRaises(ValueError):
            subject.extract_core(self.image)
        with self.flip(0x4e0c1ad), self.assertRaises(ValueError):
            subject.extract_core(self.image)

    def test_delayed_projection_and_broken_join(self):
        projection = subject.delayed_projection(self.image, self.rows)
        self.assertEqual((projection['delayed_until_offset'], projection['height_offset'],
                          projection['tx_index_offset']), (24, 8, 16))
        self.assertEqual(projection['field_order'], ['delayedUntil', 'id', 'height', 'tx_index'])
        with self.flip(0x4e0c1f0), self.assertRaises(ValueError):
            subject.delayed_projection(self.image, self.rows)

    def test_result_and_delayed_branches_reject_damage(self):
        selected = subject.extra_branches(self.image)
        self.assertEqual(len(selected), 94)
        for addr in (0x5922b63, 0x4e0c1e8, 0x4e0d8a7, 0x52a7d53,
                     0x518a2ef, 0x5301c71, 0x518908c):
            with self.subTest(address=hex(addr)), self.flip(addr + 1):
                with self.assertRaises(ValueError):
                    subject.extra_branches(self.image)

    def test_validator_growth_failure_result_and_corruption(self):
        facts = subject.failure_facts(self.image)
        self.assertEqual((facts['head'], facts['second_word'], facts['third_word']),
                         ('0x8000000000000000', 0, '0x2600000003'))
        self.assertEqual((facts['second_word_offset'], facts['third_word_offset']), (8, 16))
        with self.flip(0x4e0f19f), self.assertRaises(ValueError):
            subject.failure_facts(self.image)
        with self.flip(0x4e0f0e9), self.assertRaises(ValueError):
            subject.failure_facts(self.image)

    def test_status_paths_and_every_order_table_entry(self):
        facts, rows = subject.status_paths(self.image)
        self.assertEqual((facts['order_element_stride'], facts['cancel_element_stride']), (48, 24))
        self.assertEqual((facts['status_pointer_offset'], facts['status_count_offset']), (8, 16))
        self.assertEqual([r['text'] for r in rows],
                         ['filled', 'resting', 'waitingForFill', 'waitingForTrigger', 'error'])
        self.assertEqual(facts['cancel_sentinel'], '0x8000000000000000')
        self.assertEqual(facts['cancel_error_map_marker'], 0x81)
        for tag in range(5):
            with self.subTest(tag=tag), self.flip(0x91d214 + 4 * tag):
                with self.assertRaises(ValueError):
                    subject.status_paths(self.image)
        for row in rows:
            with self.subTest(label=row['text']), self.flip(row['literal_va']):
                with self.assertRaises(ValueError):
                    subject.status_paths(self.image)

    def test_status_paths_reject_stride_label_and_error_damage(self):
        for va in (0x52e33af, 0x52a7dad, 0x459590, 0x91f27c, 0x5301c42,
                   0x5301c60, 0x52e35b4, 0x52a7f85, 0x52a7c37):
            with self.subTest(address=hex(va)), self.flip(va):
                with self.assertRaises(ValueError):
                    subject.status_paths(self.image)

    def test_special_tag_branch_inversion_is_rejected(self):
        with self.flip(0x59229c3), self.assertRaises(ValueError):
            subject.extract_core(self.image)

    def test_formatter_widths_and_slot(self):
        result = subject.width_facts(self.image)
        self.assertEqual([(r['input_size'], r['buffer_size']) for r in result], [(20, 42), (20, 42), (32, 66)])
        self.assertEqual({r['slot_va'] for r in result}, {0x64e4d08})
        with self.flip(0x4e0fcba), self.assertRaises(ValueError):
            subject.width_facts(self.image)

    def test_elf_mappings_reject_outside_nobits_and_ambiguity(self):
        with self.assertRaises(ValueError):
            self.image.read(1 << 62, 1)
        with self.assertRaises(ValueError):
            self.image.offset(-1, 1)
        with self.assertRaises(ValueError):
            self.image.offset(0, 0)
        fake = subject.Image.__new__(subject.Image)
        fake.data = b'abcdefgh'
        sec = {'name': 'synthetic', 'type': 8, 'flags': 2, 'address': 0x100, 'size': 8, 'offset': 0}
        fake.sections = [sec]
        with self.assertRaises(ValueError):
            fake.read(0x100, 1)
        sec['type'] = 1
        fake.sections.append(dict(sec))
        with self.assertRaises(ValueError):
            fake.read(0x100, 1)
        fake.sections.pop()
        self.assertEqual(fake.read(0x100, 8), b'abcdefgh')
        with self.assertRaises(ValueError):
            fake.read(0x107, 2)

    def test_rejects_duplicate_or_truncated_relocation_section(self):
        fake = subject.Image.__new__(subject.Image)
        fake.data = self.data
        fake.sections = [dict(row) for row in self.image.sections]
        section = next(row for row in fake.sections if row['name'] == '.rela.dyn')
        fake.sections.append(dict(section))
        with self.assertRaises(ValueError):
            fake.unique_section('.rela.dyn')
        fake.sections.pop()
        section['size'] -= 1
        with self.assertRaises(ValueError):
            subject.location(fake, 0x64767a8, 0x3c1352f, 123, 37, 0x3c1353b, '4883f801')

    def test_location_cross_release_identity_and_corruption(self):
        loc = subject.location(self.image, 0x64767a8, 0x3c1352f, 123, 37, 0x3c1353b, '4883f801')
        self.assertEqual((loc['path_suffix'], loc['line'], loc['column']), ('l1/src/abci/state.rs', 123, 37))
        with self.flip(0x64767a8 + 16), self.assertRaises(ValueError):
            subject.location(self.image, 0x64767a8, 0x3c1352f, 123, 37, 0x3c1353b, '4883f801')
        with self.assertRaises(ValueError):
            subject.compare_historical(b'incorrect historical artifact')

    def test_selected_fde_extents_and_body_corruption(self):
        rows = subject.extract_functions(self.image)
        self.assertEqual(len(rows), 22)
        self.assertEqual(len({row['start_va'] for row in rows}), 22)
        with self.flip(0x4e0d7a0), self.assertRaises(ValueError):
            subject.extract_functions(self.image)

    def test_wrong_digest_rejected_before_writing(self):
        class FakeTarget:
            def read_bytes(self):
                return b'not the expected artifact'
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'evidence'
            with mock.patch.object(subject, 'TARGET', FakeTarget()), mock.patch.object(
                    sys, 'argv', ['extractor', '--out', str(output)]):
                with self.assertRaises(ValueError):
                    subject.main()
            self.assertFalse(output.exists())
        with self.flip(0x4d8fcd0), self.assertRaises(ValueError):
            subject.verify_digest(self.data)

    def test_relative_instruction_and_branch_bounds(self):
        with self.assertRaises(ValueError):
            subject.rel32(self.image, 0x4d8fcd0)
        with self.assertRaises(ValueError):
            subject.branch(self.image, 0x4d8fcd0)
        with self.assertRaises(ValueError):
            subject.branch(self.image, 1 << 62)


class SyntheticModelTests(unittest.TestCase):
    def test_order_waiting_and_cancel_statuses(self):
        self.assertEqual(subject.encode_subset(0, 0, ()), b'\x92\xa2ok\x92\xa5order\x91\x90')
        self.assertEqual(subject.encode_subset(0, 0, (2, 3)),
                         b'\x92\xa2ok\x92\xa5order\x91\x92\xaewaitingForFill\xb1waitingForTrigger')
        self.assertEqual(subject.encode_subset(0, 1, (None, b'bad')),
                         b'\x92\xa2ok\x92\xa6cancel\x91\x92\xa7success\x81\xa5error\xa3bad')
        self.assertEqual(subject.encode_subset(1, 1, (None,)),
                         b'\x82\xa6status\xa2ok\xa8response\x82\xa4type\xa6cancel'
                         b'\xa4data\x81\xa8statuses\x91\xa7success')
        for tag, value in ((0, (1,)), (0, (2,) * 16), (1, (False,)), (1, (b'x' * 256,))):
            with self.subTest(tag=tag, value=value), self.assertRaises(ValueError):
                subject.encode_subset(0, tag, value)

    def test_default_array_and_named_map(self):
        self.assertEqual(subject.encode_subset(0, 14), b'\x92\xa2ok\x91\xa7default')
        self.assertEqual(subject.encode_subset(1, 14),
                         b'\x82\xa6status\xa2ok\xa8response\x81\xa4type\xa7default')

    def test_error_array_and_named_map(self):
        self.assertEqual(subject.encode_subset(0, 15, b'bad'), b'\x92\xa3err\xa3bad')
        self.assertEqual(subject.encode_subset(1, 15, b'bad'),
                         b'\x82\xa6status\xa3err\xa8response\xa3bad')

    def test_error_string_marker_boundary(self):
        self.assertEqual(subject.encode_subset(0, 15, b'x' * 31), b'\x92\xa3err\xbf' + b'x' * 31)
        self.assertEqual(subject.encode_subset(0, 15, b'x' * 32), b'\x92\xa3err\xd9\x20' + b'x' * 32)
        with self.assertRaises(ValueError):
            subject.encode_subset(0, 15, b'x' * 256)

    def test_spot_and_token_unsigned_boundaries(self):
        self.assertEqual(subject.encode_subset(0, 9, 127), b'\x92\xa2ok\x92\xa4spot\x7f')
        self.assertEqual(subject.encode_subset(1, 8, 0),
                         b'\x82\xa6status\xa2ok\xa8response\x82\xa4type\xa5token\xa4data\x00')
        for value in (-1, 128, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                subject.encode_subset(0, 9, value)

    def test_validator_boolean_and_noncanonical_control(self):
        self.assertEqual(subject.encode_subset(0, 10, 0), b'\x92\xa2ok\x92\xadvalidatorVote\xc2')
        self.assertEqual(subject.encode_subset(0, 10, 1), b'\x92\xa2ok\x92\xadvalidatorVote\xc3')
        with self.assertRaises(ValueError):
            subject.encode_subset(0, 10, 2)

    def test_fixed_width_address_and_hash(self):
        payload = bytes(range(20))
        result = subject.encode_subset(0, 2, payload)
        self.assertEqual(result, b'\x92\xa2ok\x92\xabcreateVault\xd9\x2a0x' + payload.hex().encode())
        result = subject.encode_subset(0, 11, bytes(32))
        self.assertEqual(result, b'\x92\xa2ok\x92\xb2governanceProposal\xd9\x420x' + b'00' * 32)
        with self.assertRaises(ValueError):
            subject.encode_subset(0, 2, bytes(19))
        with self.assertRaises(ValueError):
            subject.encode_subset(0, 11, bytes(33))

    def test_delayed_complete_selected_value(self):
        self.assertEqual(subject.encode_subset(0, 13, (7, 8, 9)),
                         b'\x92\xa2ok\x92\xa7delayed\x92\x07\x92\x08\x09')
        self.assertEqual(subject.encode_subset(1, 13, (7, 8, 9)),
                         b'\x82\xa6status\xa2ok\xa8response\x82\xa4type\xa7delayed'
                         b'\xa4data\x82\xacdelayedUntil\x07\xa2id\x82\xa6height\x08\xa8tx_index\x09')
        for value in ((7, 8), (7, 8, 128), (7, 8, -1), [7, 8, 9]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                subject.encode_subset(1, 13, value)

    def test_model_rejects_unsupported_modes_and_variants(self):
        for mode in (-1, 2, True):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                subject.encode_subset(mode, 14)
        for tag in (-1, 4, 16, 255):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                subject.encode_subset(0, tag)
        with self.assertRaises(ValueError):
            subject.encode_subset(0, 14, 0)


if __name__ == '__main__':
    unittest.main()
