"""Controls for the node 94 state-kind evidence extractor and bounded models."""
import hashlib
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import re009_state_kinds94 as evidence


class StateKindEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(evidence.ARTIFACT.read_bytes())
        evidence.checked_digest(cls.data)
        cls.image = evidence.Image(cls.data)
        cls.names = evidence.extract_names(cls.image)
        cls.tables = evidence.extract_tables(cls.image)

    def with_corruption(self, va, callback):
        offset = self.image.offset(va, 1)
        original = self.data[offset]
        try:
            self.data[offset] ^= 1
            with self.assertRaises(ValueError):
                callback(self.image)
        finally:
            self.data[offset] = original

    def test_sha_and_corruption(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), evidence.SHA256)
        offset = self.image.offset(0x28e53a0, 1)
        self.data[offset] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                evidence.checked_digest(self.data)
        finally:
            self.data[offset] ^= 1

    def test_fde_ranges_and_counts(self):
        result = evidence.analyze(bytes(self.data))
        self.assertEqual(len(result['functions']), 16)
        self.assertEqual(len(result['names']), 7)
        for item in result['functions']:
            self.assertGreater(item['length'], 0)
            self.assertEqual(int(item['end_va_exclusive'], 16) - int(item['start_va'], 16), item['length'])
        self.assertEqual(len(result['calls']), 30)
        self.assertEqual(sum(len(row[1]) for row in result['tables'].values()), 82)

    def test_instruction_window_corruption(self):
        self.with_corruption(0x28e53d0, evidence.verify_pins)
        self.with_corruption(0x28d1433, evidence.verify_pins)
        self.with_corruption(0x1bea0e7, evidence.verify_pins)

    def test_dispatch_target_corruption(self):
        self.with_corruption(0x3e8a84 + 32 * 4, evidence.extract_tables)
        self.with_corruption(0x3f59b4, evidence.extract_tables)
        self.with_corruption(0x3f59d0 + 7 * 4, evidence.extract_tables)
        self.with_corruption(0x3f53e4 + 19 * 4, evidence.extract_tables)

    def test_direct_call_corruption(self):
        self.with_corruption(0x1bddae4, evidence.extract_calls)
        self.with_corruption(0x1bddae5, evidence.extract_calls)
        self.with_corruption(0x28e5b92, evidence.extract_calls)

    def test_hex_slot_references_and_corruption(self):
        self.assertEqual(evidence.extract_hex_slot(self.image), ('0x5773120', 8, '0x29ed380'))
        self.with_corruption(0x1e0d198, evidence.extract_hex_slot)
        self.with_corruption(0x1e0d7ba, evidence.extract_hex_slot)

    def test_collector_allocation_model_boundaries(self):
        limit = 0x7ffffffffffffff8 // 16
        self.assertEqual(evidence.model_collector_bytes(0), 0)
        self.assertEqual(evidence.model_collector_bytes(1), 16)
        self.assertEqual(evidence.model_collector_bytes(limit), limit * 16)
        for invalid in (limit + 1, (1 << 60) - 1, 1 << 60, (1 << 64) - 1, -1, 1 << 64):
            with self.assertRaises(ValueError):
                evidence.model_collector_bytes(invalid)

    def test_key_formatter_model(self):
        self.assertEqual(evidence.model_key(bytes(20)), b'0x' + b'0' * 40)
        self.assertEqual(evidence.model_key(bytes(range(20))), b'0x000102030405060708090a0b0c0d0e0f10111213')
        self.assertEqual(evidence.model_key(bytes([255]) * 20), b'0x' + b'f' * 40)
        for bad in (b'', bytes(19), bytes(21), '0' * 20):
            with self.assertRaises(ValueError):
                evidence.model_key(bad)

    def test_name_data_and_length_corruption(self):
        name_ptr = self.names[4][3]
        self.with_corruption(name_ptr, evidence.extract_names)
        self.with_corruption(self.names[0][2] + 8, evidence.extract_names)
        self.with_corruption(0x207490, evidence.extract_names)
        self.with_corruption(0x3f67b5, evidence.extract_names)

    def test_relocation_corruption(self):
        sec = next(x for x in self.image.sections if x['name'] == '.rela.dyn')
        positions = {}
        wanted = {self.names[0][2], 0x5773120}
        for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot = struct.unpack_from('<Q', self.data, pos)[0]
            if slot in wanted:
                positions[slot] = pos
        self.assertEqual(set(positions), wanted)
        for slot, callback in ((self.names[0][2], evidence.extract_names),
                               (0x5773120, evidence.extract_hex_slot)):
            for delta in (8, 16):
                pos = positions[slot] + delta
                original = self.data[pos]
                try:
                    self.data[pos] ^= 1
                    with self.assertRaises(ValueError):
                        callback(self.image)
                finally:
                    self.data[pos] = original

    def test_va_must_be_file_backed_unambiguous_and_in_bounds(self):
        with self.assertRaises(ValueError):
            self.image.read(-1, 1)
        with self.assertRaises(ValueError):
            self.image.read(0xffffffffffffffff, 1)
        with self.assertRaises(ValueError):
            self.image.read(0x28e53a0, -1)
        bss = next(x for x in self.image.sections if x['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaises(ValueError):
            self.image.read(bss['address'], 1)

    def test_name_classifier_labels_and_negative_controls(self):
        for tag, name, _, _, _ in self.names:
            raw = name.encode('ascii')
            self.assertEqual(evidence.classify(raw, self.names), tag)
            self.assertIsNone(evidence.classify(raw[:-1], self.names))
            self.assertIsNone(evidence.classify(raw + b'X', self.names))
            for offset in range(len(raw)):
                damaged = raw[:offset] + bytes([raw[offset] ^ 1]) + raw[offset + 1:]
                self.assertIsNone(evidence.classify(damaged, self.names))
        self.assertIsNone(evidence.classify(b'', self.names))
        self.assertIsNone(evidence.classify(b'perp', self.names))
        with self.assertRaises(TypeError):
            evidence.classify('Perp', self.names)

    def test_reader_branch_matrix(self):
        lead = self.tables['map_reader_lead_5b_through_7b'][1]
        self.assertEqual(len(lead), 33)
        self.assertEqual(lead[0], 0x25fa8a0)
        self.assertEqual(lead[32], 0x25fa9a6)
        quoted = self.tables['quoted_reader_tag_or_error'][1]
        object_case = self.tables['object_reader_tag'][1]
        self.assertEqual(quoted[:4], (0x28e5c34,) * 4)
        self.assertEqual(quoted[4:7], (0x28e5a7a, 0x28e5b6f, 0x28e5b78))
        self.assertEqual(quoted[7], 0x28e5b81)
        self.assertEqual(object_case[:4], (0x28e5b53, 0x28e5bdc, 0x28e5bac, 0x28e5bc4))
        self.assertEqual(object_case[4:], (0x28e5b8f, 0x28e5c00, 0x28e5c1a))

    def test_model_integer_width_boundaries(self):
        cases = ((0, '00'), (127, '7f'), (128, 'cc80'), (255, 'ccff'),
                 (256, 'cd0100'), (65535, 'cdffff'), (65536, 'ce00010000'),
                 (4294967295, 'ceffffffff'), (4294967296, 'cf0000000100000000'),
                 (18446744073709551615, 'cfffffffffffffffff'))
        for tag, name, _, _, length in self.names[:4]:
            prefix = bytes((0x81, 0xa0 + length)) + name.encode('ascii')
            for value, expected in cases:
                self.assertEqual(evidence.model_kind(tag, value, self.names), prefix + bytes.fromhex(expected))
        for tag, name, _, _, length in self.names[4:]:
            self.assertEqual(evidence.model_kind(tag, None, self.names),
                             bytes([0xa0 + length]) + name.encode('ascii'))

    def test_model_rejects_invalid_inputs(self):
        for tag, payload in ((-1, 0), (7, 0), (True, 0), (0, -1), (0, 1 << 64),
                             (0, None), (0, True), (4, 0)):
            with self.assertRaises(ValueError):
                evidence.model_kind(tag, payload, self.names)


if __name__ == '__main__':
    unittest.main()
