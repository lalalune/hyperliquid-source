"""Negative controls for the static node 115 keyed-result evidence packet."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import abci_keyed_result115 as packet


def synthetic_section(va, data, *, typ=1, flags=4, name='.text'):
    return [{'name': name, 'type': typ, 'flags': flags, 'address': va,
             'offset': 0, 'size': len(data)}]


def sse_equal_20(left, right):
    """Model the selected 16-byte comparison ANDed with a zero-extended dword."""
    if len(left) != 20 or len(right) != 20:
        raise ValueError('twenty-byte inputs required')
    first = [a == b for a, b in zip(left[:16], right[:16])]
    tail = [a == b for a, b in zip(left[16:], right[16:])] + [True] * 12
    return all(a and b for a, b in zip(first, tail))


def flags_add(a, b):
    mask = (1 << 64) - 1
    total = a + b
    carry = total >> 64
    return mask if carry else total & mask


def flags_mul(a, factor):
    mask = (1 << 64) - 1
    product = a * factor
    return mask if product >> 64 else product & mask


class PacketControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = packet.TARGET.read_bytes()
        packet.authenticate(cls.data)
        cls.secs = packet.sections(cls.data)
        cls.relocs = packet.relocations(cls.data, cls.secs)
        cls.results = packet.collect(cls.data)
        cls.rows, cls.values = packet.operand_rows(cls.data, cls.secs)
        cls.descriptors = packet.descriptor_rows(cls.data, cls.secs, cls.relocs)
        cls.starts = {f['role']: f['start'] for f in packet.selected_fdes(cls.data, cls.secs)}
        cls.references = packet.reference_rows(cls.data, cls.secs)
        cls.location = packet.location_row(cls.data, cls.secs, cls.relocs)
        cls.loader_location = packet.location_row(cls.data, cls.secs, cls.relocs,
                                                  loc=0x64767a8, expected_line=123, expected_col=37)

    def test_authenticated_target(self):
        self.assertEqual(packet.authenticate(self.data), packet.TARGET_SHA256)

    def test_wrong_expected_digest_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            packet.authenticate(self.data, '0' * 64)

    def test_changed_actual_target_is_rejected(self):
        changed = bytearray(self.data)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            packet.authenticate(changed)

    def test_corrupted_fde_start_bytes_are_rejected(self):
        fde = next(f for f in packet.selected_fdes(self.data, self.secs)
                   if f['role'] == 'location_handler')
        off = packet.file_offset(self.data, self.secs, fde['fde'] + 8, 4)
        altered = bytearray(self.data)
        altered[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'FDE/header mismatch'):
            packet.selected_fdes(altered, self.secs)

    def test_corrupted_descriptor_relocation_bytes_are_rejected(self):
        altered = bytearray(self.data)
        off = self.relocs[0x6479438][3]
        altered[off + 8] ^= 1
        relocs = packet.relocations(altered, self.secs)
        with self.assertRaisesRegex(ValueError, 'descriptor relocation'):
            packet.descriptor_rows(altered, self.secs, relocs)

    def test_corrupted_location_bytes_are_rejected(self):
        altered = bytearray(self.data)
        off = packet.file_offset(self.data, self.secs, 0x642d310, 24)
        altered[off + 16] ^= 1
        with self.assertRaisesRegex(ValueError, 'Location dimensions'):
            packet.location_row(altered, self.secs, self.relocs)

    def test_corrupted_lsda_header_bytes_are_rejected(self):
        altered = bytearray(self.data)
        fde = {'role': 'location_handler', 'start': 0x22ec9b0, 'end': 0x22ed1ec,
               'lsda': 0x20c01c}
        off = packet.file_offset(self.data, self.secs, fde['lsda'], 1)
        altered[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'LSDA encodings'):
            packet.lsda_rows(altered, self.secs, fde)

    def test_bad_digest_creates_no_output(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bad = root / 'bad'
            bad.write_bytes(b'not the authenticated target')
            out = root / 'evidence'
            with mock.patch.object(packet, 'TARGET', bad):
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    packet.main(['--out', str(out)])
            self.assertFalse(out.exists())

    def test_missing_target_creates_no_output(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'evidence'
            with mock.patch.object(packet, 'TARGET', Path(td) / 'missing'):
                with self.assertRaises(FileNotFoundError):
                    packet.main(['--out', str(out)])
            self.assertFalse(out.exists())

    def test_corrupt_historical_capture_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            packet.compare_historical(b'not the retired capture', self.data)

    def test_every_selected_window_rejects_one_byte_damage(self):
        for scope, label, va, raw_hex in packet.WINDOW_SPECS:
            with self.subTest(scope=scope, label=label):
                original = bytes.fromhex(raw_hex)
                altered = bytearray(original)
                altered[len(altered) // 2] ^= 1
                secs = synthetic_section(va, altered)
                with self.assertRaisesRegex(ValueError, 'changed selected bytes'):
                    packet.require_fixed(altered, secs, va, original)

    def test_every_selected_transfer_rejects_operand_damage(self):
        for label, va, raw_hex in packet.BRANCH_SPECS + packet.CALL_SPECS:
            with self.subTest(label=label):
                original = bytes.fromhex(raw_hex)
                altered = bytearray(original)
                altered[-1] ^= 1
                with self.assertRaises(ValueError):
                    packet.require_fixed(altered, synthetic_section(va, altered), va, original)

    def test_direct_transfer_displacement_is_signed(self):
        form, target = packet.decode_transfer(0x1000, bytes.fromhex('e8f6ffffff'))
        self.assertEqual((form, target), ('rel32_call', 0xffb))

    def test_short_branch_displacement_is_signed(self):
        self.assertEqual(packet.decode_transfer(0x1000, bytes.fromhex('75fe')),
                         ('short_conditional', 0x1000))

    def test_indirect_call_does_not_claim_runtime_binding(self):
        self.assertEqual(packet.decode_transfer(0x1000, bytes.fromhex('ff150a000000')),
                         ('rip_indirect_call_slot', 0x1010))

    def test_register_call_retains_offset(self):
        self.assertEqual(packet.decode_transfer(0x1000, bytes.fromhex('ff5320')),
                         ('register_indirect_call_offset', 0x20))

    def test_bad_transfer_forms_are_rejected(self):
        for raw in (b'', b'\xe8\x00', b'\x90', bytes.fromhex('0f8000'), bytes.fromhex('ff2500000000')):
            with self.subTest(raw=raw.hex()), self.assertRaises(ValueError):
                packet.decode_transfer(0x1000, raw)

    def test_address_at_both_boundaries(self):
        data = b'abcd'
        secs = synthetic_section(0x2000, data)
        self.assertEqual(packet.read_va(data, secs, 0x2000, 1), b'a')
        self.assertEqual(packet.read_va(data, secs, 0x2003, 1), b'd')
        for va, length in ((0x1fff, 1), (0x2004, 1), (0x2003, 2), (0x2000, 0), (-1, 1)):
            with self.subTest(va=va, length=length), self.assertRaises(ValueError):
                packet.read_va(data, secs, va, length)

    def test_nobits_section_is_never_file_backed(self):
        data = b'abcd'
        with self.assertRaises(ValueError):
            packet.read_va(data, synthetic_section(0x2000, data, typ=8), 0x2000, 1)

    def test_overlapping_sections_are_rejected(self):
        data = b'abcd'
        sec = synthetic_section(0x2000, data)[0]
        with self.assertRaises(ValueError):
            packet.read_va(data, [sec, dict(sec)], 0x2000, 1)

    def test_nonexecutable_section_is_rejected_for_code(self):
        data = b'abcd'
        with self.assertRaises(ValueError):
            packet.read_va(data, synthetic_section(0x2000, data, flags=2), 0x2000, 1, executable=True)

    def test_file_truncation_is_rejected(self):
        sec = synthetic_section(0x2000, b'abcd')[0]
        sec['offset'] = 3
        with self.assertRaises(ValueError):
            packet.read_va(b'abcd', [sec], 0x2000, 2)

    def test_duplicate_or_nobits_named_section(self):
        row = synthetic_section(0x2000, b'abcd', name='.rela.dyn')[0]
        for sections in ([row, dict(row)], [dict(row, type=8)], []):
            with self.subTest(sections=sections), self.assertRaises(ValueError):
                packet.section_by_name(sections, '.rela.dyn')

    def test_truncated_relocation_table(self):
        data = b'\0' * 25
        with self.assertRaisesRegex(ValueError, 'truncated'):
            packet.relocations(data, synthetic_section(0, data, name='.rela.dyn'))

    def test_duplicate_relocation_destinations(self):
        data = struct.pack('<QQq', 1, 8, 2) * 2
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            packet.relocations(data, synthetic_section(0, data, name='.rela.dyn'))

    def test_descriptor_rejects_nonrelative_relocation(self):
        bad = dict(self.relocs)
        typ, sym, addend, off = bad[0x6479438]
        bad[0x6479438] = (typ + 1, sym, addend, off)
        with self.assertRaisesRegex(ValueError, 'descriptor relocation'):
            packet.descriptor_rows(self.data, self.secs, bad)

    def test_descriptor_rejects_symbol_index_and_addend_changes(self):
        for change in ('symbol', 'addend', 'missing'):
            bad = dict(self.relocs)
            typ, sym, addend, off = bad[0x6479438]
            if change == 'symbol':
                bad[0x6479438] = (typ, 1, addend, off)
            elif change == 'addend':
                bad[0x6479438] = (typ, sym, addend + 1, off)
            else:
                del bad[0x6479438]
            with self.subTest(change=change), self.assertRaises(ValueError):
                packet.descriptor_rows(self.data, self.secs, bad)

    def test_descriptor_size_corruption_is_rejected(self):
        label, base, expected = packet.DESCRIPTOR_SPECS[1]
        raw = bytearray(packet.read_va(self.data, self.secs, base, 40))
        raw[8] ^= 1
        sec = synthetic_section(base, raw, flags=2)
        with mock.patch.object(packet, 'DESCRIPTOR_SPECS', ((label, base, expected),)):
            with self.assertRaisesRegex(ValueError, 'descriptor mismatch'):
                packet.descriptor_rows(raw, sec, self.relocs)

    def test_location_validated_independently(self):
        row = packet.location_row(self.data, self.secs, self.relocs)
        self.assertEqual((row[5], row[6], row[7]), (460, 78, 'l1/src/abci/state.rs'))

    def test_location_wrong_relocation_or_dimensions(self):
        rel = dict(self.relocs)
        typ, sym, add, off = rel[0x642d310]
        rel[0x642d310] = (typ, 1, add, off)
        with self.assertRaises(ValueError):
            packet.location_row(self.data, self.secs, rel)
        with self.assertRaises(ValueError):
            packet.location_row(self.data, self.secs, self.relocs, expected_line=459)

    def test_selected_fde_header_and_body_negative_controls(self):
        body = b'\x90\x90\xc3'
        secs = synthetic_section(0x1000, body)
        spec = (('sample', 0x1000, 0x1003, hashlib.sha256(body).hexdigest()),)
        row = {'start': 0x1000, 'fde': 0x3000, 'index': 1, 'next_index_upper_bound': 0x1003}
        fde = {'start': 0x1000, 'end': 0x1003, 'fde': 0x3000, 'cie': 0x4000, 'lsda': None}
        with mock.patch.object(packet, 'FDE_SPECS', spec), \
             mock.patch.object(packet, 'unwind_index', return_value=(secs, [row])), \
             mock.patch.object(packet, 'eh_frame_records', return_value=({}, [fde])):
            self.assertEqual(len(packet.selected_fdes(body, secs)), 1)
            with self.assertRaisesRegex(ValueError, 'body mismatch'):
                packet.selected_fdes(b'\x90\x91\xc3', secs)
        for damaged in (dict(fde, start=0x1001), dict(fde, end=0x1002), dict(fde, fde=0x3001)):
            with self.subTest(damaged=damaged), mock.patch.object(packet, 'FDE_SPECS', spec), \
                 mock.patch.object(packet, 'unwind_index', return_value=(secs, [row])), \
                 mock.patch.object(packet, 'eh_frame_records', return_value=({}, [damaged])):
                with self.assertRaises(ValueError):
                    packet.selected_fdes(body, secs)

    def test_fde_cannot_cross_next_index_start(self):
        body = b'\x90\x90\xc3'
        secs = synthetic_section(0x1000, body)
        spec = (('sample', 0x1000, 0x1003, hashlib.sha256(body).hexdigest()),)
        row = {'start': 0x1000, 'fde': 0x3000, 'index': 1, 'next_index_upper_bound': 0x1002}
        fde = {'start': 0x1000, 'end': 0x1003, 'fde': 0x3000, 'cie': 0x4000, 'lsda': None}
        with mock.patch.object(packet, 'FDE_SPECS', spec), \
             mock.patch.object(packet, 'unwind_index', return_value=(secs, [row])), \
             mock.patch.object(packet, 'eh_frame_records', return_value=({}, [fde])):
            with self.assertRaisesRegex(ValueError, 'overlaps'):
                packet.selected_fdes(body, secs)

    def test_lsda_types_and_landing(self):
        fde = {'role': 'sample', 'start': 0x1000, 'end': 0x1010, 'lsda': 0x2000}
        for data in (bytes.fromhex('ffff010400050600'), bytes.fromhex('ff9b06010400050600')):
            sec = synthetic_section(0x2000, data, name='.gcc_except_table')
            row = packet.lsda_rows(data, sec, fde)[0]
            self.assertEqual(row[3:7], ('0x1000', '0x1005', '0x1006', 0))

    def test_lsda_corruption_is_rejected(self):
        fde = {'role': 'sample', 'start': 0x1000, 'end': 0x1010, 'lsda': 0x2000}
        cases = (bytes.fromhex('00ff010400050600'), bytes.fromhex('ffff020400050600'),
                 bytes.fromhex('ffff01040f050600'), bytes.fromhex('ffff010400051000'),
                 bytes.fromhex('ffff017f00050600'), bytes.fromhex('ff9bff'))
        for data in cases:
            with self.subTest(data=data.hex()), self.assertRaises(ValueError):
                packet.lsda_rows(data, synthetic_section(0x2000, data, name='.gcc_except_table'), fde)

    def test_location_handler_lsda_observer_and_cleanup(self):
        text = self.results['unwind-witnesses.tsv'].decode()
        self.assertIn('handler_observer_callback\t0x22ed00f', text)
        self.assertIn('0x22ed1a1', text)
        self.assertIn('nested_replay\t0x2c69744', text)

    def test_fixed_references_match_descriptors(self):
        rows = packet.reference_rows(self.data, self.secs)
        by_label = {row[0]: row[-1] for row in rows}
        self.assertEqual(by_label['context_group_item4_descriptor'], '0x6479420')
        self.assertEqual(by_label['root_value_descriptor'], '0x6493458')
        self.assertEqual(by_label['root_accumulator_descriptor'], '0x6482968')

    def test_corrupted_reference_displacement_is_rejected(self):
        label, va, target = packet.REFERENCE_SPECS[0]
        original = packet.read_va(self.data, self.secs, va, 7, executable=True)
        damaged = bytearray(original)
        damaged[3] ^= 1
        with mock.patch.object(packet, 'REFERENCE_SPECS', ((label, va, target),)):
            with self.assertRaisesRegex(ValueError, 'reference target'):
                packet.reference_rows(damaged, synthetic_section(va, damaged))

    def test_all_joins_pass_and_group_is_index_four(self):
        rows = packet.verify_joins(self.values, self.descriptors, self.starts,
                                   self.references, self.location, self.loader_location)
        self.assertEqual(len(rows), 24)
        self.assertEqual(self.values['root_group_index_bytes'], 4 * 8)

    def test_join_corruptions_fail_closed(self):
        for name in ('root_context_map_offset', 'root_record_stride', 'root_key_in_row',
                     'root_value_accumulator_offset', 'dispatch_tag', 'nested_error_code',
                     'root_group_index_bytes', 'nested_multiplier_shift',
                     'future_load_pointer', 'wrapper_pointer_load', 'wrapper_return_pointer',
                     'parent_task_pointer', 'parent_task_copy_length', 'wrapper_sentinel'):
            bad = dict(self.values)
            bad[name] ^= 1
            with self.subTest(name=name), self.assertRaises(ValueError):
                packet.verify_joins(bad, self.descriptors, self.starts,
                                    self.references, self.location, self.loader_location)

    def test_descriptor_references_and_callback_destinations_are_joined(self):
        for index, row in enumerate(self.references):
            altered = list(self.references)
            changed = list(row)
            changed[4] = hex(int(changed[4], 16) + 1)
            altered[index] = tuple(changed)
            with self.subTest(reference=row[0]), self.assertRaisesRegex(ValueError, 'join failed'):
                packet.verify_joins(self.values, self.descriptors, self.starts,
                                    altered, self.location, self.loader_location)
        for role in ('root_map_visitor', 'root_map_constructor',
                     'root_value_visitor', 'root_value_constructor'):
            altered = dict(self.starts)
            altered[role] += 1
            with self.subTest(callback=role), self.assertRaisesRegex(ValueError, 'join failed'):
                packet.verify_joins(self.values, self.descriptors, altered,
                                    self.references, self.location, self.loader_location)

    def test_materializer_boundary_relocation_corruption_is_rejected(self):
        self.assertEqual(packet.materializer_boundary(self.data, self.secs, self.relocs)[6], '0x3c13610')
        bad = dict(self.relocs)
        typ, symbol, addend, offset = bad[0x64e73a0]
        bad[0x64e73a0] = typ, symbol, addend + 1, offset
        with self.assertRaisesRegex(ValueError, 'materializer boundary'):
            packet.materializer_boundary(self.data, self.secs, bad)

    def test_future_tag_and_parent_copy_bounds(self):
        sentinel = self.values['future_sentinel']
        self.assertEqual((sentinel + 1) ^ self.values['wrapper_sentinel'], 1)
        self.assertNotEqual((sentinel + 4) ^ self.values['wrapper_sentinel'], 1)
        self.assertEqual(self.values['parent_task_pointer'] - self.values['parent_task_base'], 0x320)
        self.assertLessEqual(0x320 + 8, self.values['parent_task_copy_length'])

    def test_each_key_byte_affects_the_selected_sse_comparison(self):
        key = bytes(range(20))
        self.assertTrue(sse_equal_20(key, key))
        for i in range(20):
            for replacement in range(256):
                if replacement == key[i]:
                    continue
                changed = bytearray(key)
                changed[i] = replacement
                with self.subTest(index=i, replacement=replacement):
                    self.assertFalse(sse_equal_20(key, changed))
        for size in (0, 19, 21):
            with self.subTest(size=size), self.assertRaises(ValueError):
                sse_equal_20(key, b'\0' * size)

    def test_16_bit_success_tag_is_not_a_low_byte_test(self):
        tag = self.values['input_tag']
        self.assertEqual(tag, 0x1a2)
        self.assertNotEqual(tag & 0xff, tag)
        for other in (tag - 1, tag + 1, tag & 0xff, tag ^ 0x100):
            self.assertNotEqual(other, tag)

    def test_saturating_multiply_and_add_boundaries(self):
        maximum = (1 << 64) - 1
        for factor in (self.values['expired_multiplier'], 1 << self.values['nested_multiplier_shift']):
            for value in (0, 1, maximum // factor, maximum // factor + 1, maximum):
                result = flags_mul(value, factor)
                self.assertEqual(result, min(maximum, value * factor))
                for old in (0, 1, maximum - 1, maximum):
                    self.assertEqual(flags_add(old, result), min(maximum, old + result))

    def test_root_allocation_boundaries(self):
        values = self.values
        mask = (1 << 64) - 1
        shift = values['root_alloc_shift']
        bound = values['root_alloc_limit']
        largest = bound >> shift
        for count, expected in ((0, True), (1, True), (largest, True),
                                (largest + 1, False), (1 << values['root_overflow_shift'], False),
                                (mask, False)):
            machine = not (count >> values['root_overflow_shift'] or ((count << shift) & mask) > bound)
            self.assertEqual(machine, expected, count)
            self.assertEqual(machine, count * (1 << shift) <= bound, count)

    def test_result_sort_thresholds(self):
        lower = self.values['sort_lower_limit']
        upper = self.values['sort_upper_limit']
        def route(n):
            return 'none' if n < lower else 'small' if n < upper else 'large'
        self.assertEqual([route(n) for n in (0, 1, 2, 20, 21, 22)],
                         ['none', 'none', 'small', 'small', 'large', 'large'])

    def test_root_record_offsets_distinguish_key_and_updated_value(self):
        v = self.values
        stride = v['root_record_stride']
        row = bytearray(stride * 2)
        key = bytes(range(20))
        for index, value in enumerate((17, 0x1122334455667788)):
            start = index * stride
            row[start + v['root_key_in_row']:start + v['root_key_in_row'] + 20] = key
            struct.pack_into('<Q', row, start + v['insert_value_pointer'] + v['handler_accumulator_offset'], value)
        for index, expected in enumerate((17, 0x1122334455667788)):
            start = index * stride
            key_at = start + v['root_key_in_row']
            value_at = key_at + v['root_value_from_key'] + v['root_value_accumulator_offset']
            self.assertEqual(row[key_at:key_at + 20], key)
            self.assertEqual(struct.unpack_from('<Q', row, value_at)[0], expected)
            self.assertNotEqual(value_at, key_at)

    def test_summary_records_only_scoped_counts(self):
        summary = json.loads(self.results['summary.json'])
        self.assertEqual(summary['selected_fdes'], len(packet.FDE_SPECS))
        self.assertEqual(summary['context_windows'], 21)
        self.assertEqual(summary['selected_conditional_branches'], len(packet.BRANCH_SPECS))
        self.assertIn('not a function census', summary['limitations'])


if __name__ == '__main__':
    unittest.main()
