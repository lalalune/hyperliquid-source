"""Static controls for the selected #94 order input path."""
import hashlib
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import order_wire_input_94 as subject


class OrderWireInput94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.secs = subject.sections(cls.data)
        cls.result = subject.extract(cls.data)

    def test_target_digest_and_fdes(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), subject.SHA256)
        self.assertEqual(len(self.result['fdes']), 12)
        by_start = {row['start_va']: row for row in self.result['fdes']}
        self.assertEqual(by_start['0x330e700']['end_va_exclusive'], '0x330e887')
        self.assertEqual(by_start['0x20e08a0']['end_va_exclusive'], '0x20e24e9')
        with self.assertRaises(ValueError):
            subject.verified_bytes(b'corrupted artifact')

    def test_descriptor_and_dispatch(self):
        self.assertEqual(self.result['type_literal'], 'OrderWireSerde')
        self.assertEqual([row['name'] for row in self.result['field_descriptor']][4:8],
                         ['limitPx', 'p', 's', 'sz'])
        self.assertEqual(self.result['map_dispatch_va'][2:4], ['0x20e0bf7', '0x20e0c81'])
        self.assertEqual(self.result['map_dispatch_va'][5], '0x20e0dae')
        self.assertEqual(self.result['order_type_aliases'], ['t', 'orderType'])
        self.assertEqual(self.result['nested_map_dispatch_va'][1], '0x2127420')
        self.assertEqual(self.result['nested_duplicate_field_literal'], 'triggerPx')
        with self.assertRaises(ValueError):
            subject.table_target(self.data, self.secs, 0x3c7400, 9, 9)
        with self.assertRaises(ValueError):
            subject.table_target(self.data, self.secs, 0x3c7400, -1, 9)

    def test_selected_key_instructions(self):
        classify = lambda value: subject.quantity_key(self.data, self.secs, value)
        self.assertEqual(classify(b'p'), 2)
        self.assertEqual(classify(b'limitPx'), 2)
        self.assertEqual(classify(b's'), 3)
        self.assertEqual(classify(b'sz'), 3)
        # Complete one-byte domain; other known field arms are intentionally out of scope.
        for byte in range(256):
            expected = 2 if byte == ord('p') else 3 if byte == ord('s') else None
            self.assertEqual(classify(bytes([byte])), expected)
        # Complete two-byte domain of the selected string classifier arm.
        for n in range(1 << 16):
            value = bytes((n >> 8, n & 255))
            self.assertEqual(classify(value), 3 if value == b'sz' else 7)
        # Every single-position byte corruption of the seven-byte price alias.
        original = b'limitPx'
        for index in range(len(original)):
            for replacement in range(256):
                if replacement != original[index]:
                    value = original[:index] + bytes([replacement]) + original[index + 1:]
                    self.assertEqual(classify(value), 7)
        self.assertIsNone(classify(b''))
        self.assertIsNone(classify(b'limitPx!'))
        with self.assertRaises(ValueError):
            classify('p')

    def test_adapter_full_tag_domains_and_cleanup(self):
        trace = subject.pair_trace
        success = int(self.result['adapter_success_tag'], 16)
        self.assertEqual(success, 390)
        # Each branch depends on one tag; cover all 65,536 possibilities for each.
        for value in range(1 << 16):
            first = trace(value, success, 1, success)
            second = trace(success, value, 1, success)
            self.assertEqual(first, ('success', 2, 0) if value == success else ('first_error', 1, 1))
            self.assertEqual(second, ('success', 2, 0) if value == success else ('second_error', 2, 0))
        self.assertEqual(trace(0, 0, 0, success), ('first_error', 1, 0))
        self.assertEqual(trace(0, 0, (1 << 64) - 1, success), ('first_error', 1, 1))
        for args in ((-1, 0, 0, success), (0, 65536, 0, success),
                     (0, 0, -1, success), (0, 0, 1 << 64, success), (True, 0, 0, success)):
            with self.assertRaises(ValueError):
                trace(*args)

    def test_wrapper_entry_and_counter_boundaries(self):
        trace = subject.wrapper_trace
        top = (1 << 64) - 1
        for present in (False, True):
            for at_end in (False, True):
                for marker in range(256):
                    for count in (0, top - 1, top):
                        if not present or at_end:
                            expected = ('empty', 0, False)
                        elif marker == 0x16:
                            expected = ('empty', 32, False)
                        elif count == top:
                            expected = ('overflow_branch', 32, False)
                        else:
                            expected = ('parse', 32, True)
                        self.assertEqual(trace(present, at_end, marker, count), expected)
        for args in ((1, False, 0, 0), (True, False, 256, 0),
                     (True, False, -1, 0), (True, False, 0, 1 << 64)):
            with self.assertRaises(ValueError):
                trace(*args)

    def test_static_call_targets_and_error_copy(self):
        calls = {row['site_va']: row for row in self.result['calls']}
        self.assertEqual(calls['0x1ee0823']['target_va'], '0x20e08a0')
        self.assertEqual(calls['0x1ee0863']['addend_va'], '0x330e700')
        self.assertEqual(calls['0x330e731']['addend_va'], calls['0x330e752']['addend_va'])
        self.assertEqual(calls['0x2197d17']['addend_va'], calls['0x330e731']['addend_va'])
        branches = {row['label']: row['taken_va'] for row in self.result['conditional_branches']}
        self.assertEqual(branches['first_conversion_error'], '0x330e7b0')
        self.assertEqual(branches['second_conversion_error'], '0x330e80e')
        self.assertEqual(branches['nested_duplicate_value'], '0x2127dff')
        self.assertEqual(len(bytes.fromhex(self.result['identical_error_copy_bytes_hex'])), 73)

    def test_corruption_and_file_mapping_controls(self):
        synthetic_sections = [dict(type=1, flags=4, address=0x1000, offset=0, size=6, name='.text')]
        raw = bytearray(b'\xe8\x01\x00\x00\x00\xcc')
        self.assertEqual(subject.target_rel32(raw, synthetic_sections, 0x1000, 0xe8), 0x1006)
        subject.check_window(raw, synthetic_sections, 0x1000, bytes(raw[:5]))
        raw[0] ^= 1
        with self.assertRaises(ValueError):
            subject.target_rel32(raw, synthetic_sections, 0x1000, 0xe8)
        with self.assertRaises(ValueError):
            subject.check_window(raw, synthetic_sections, 0x1000, b'\xe8\x01\x00\x00\x00')
        with self.assertRaises(ValueError):
            subject.va_bytes(raw, synthetic_sections, 0x1005, 2)
        with self.assertRaises(ValueError):
            subject.va_bytes(raw, [dict(synthetic_sections[0], type=8)], 0x1000, 1)
        with self.assertRaises(ValueError):
            subject.va_bytes(raw, synthetic_sections * 2, 0x1000, 1)
        with self.assertRaises(ValueError):
            subject.indirect_slot(raw, synthetic_sections, 0x1000)
        # Altering a selected jump-table entry is detected without editing the node.
        table = bytearray(subject.read(self.data, self.secs, 0x3cbf1c, 40))
        table[4:8] = struct.pack('<i', 0)
        local_sections = [dict(type=1, flags=2, address=0x3cbf1c,
                               offset=0, size=len(table), name='.rodata')]
        with self.assertRaises(ValueError):
            subject.quantity_key(table, local_sections, b'sz')
        # A real price-key comparison mutation changes the selected arm's result
        # and is rejected by the extractor's exact-byte control.
        length_table = subject.read(self.data, self.secs, 0x3cbf1c, 40)
        code = subject.read(self.data, self.secs, 0x2163f8b, 0xf7)
        fixture = bytearray(length_table + code)
        mappings = [dict(type=1, flags=2, address=0x3cbf1c, offset=0,
                         size=40, name='.rodata'),
                    dict(type=1, flags=4, address=0x2163f8b, offset=40,
                         size=len(code), name='.text')]
        self.assertEqual(subject.quantity_key(fixture, mappings, b'limitPx'), 2)
        fixture[40 + 0x2163fa7 - 0x2163f8b] = ord('L')
        self.assertEqual(subject.quantity_key(fixture, mappings, b'limitPx'), 7)
        self.assertEqual(subject.quantity_key(fixture, mappings, b'LimitPx'), 2)
        price_window = next(bytes.fromhex(w[2]) for w in subject.WINDOWS if w[0] == 'key_price_long')
        with self.assertRaises(ValueError):
            subject.check_window(fixture, mappings, 0x2163fa5, price_window)


if __name__ == '__main__':
    unittest.main()
