import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import lthash_json_bytes94 as subject
from elf_index import sections


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.BINARY.read_bytes()
        cls.secs = sections(cls.data)
        cls.record = subject.collect(cls.data)

    def test_target_identity_and_extents(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), subject.DIGEST)
        self.assertEqual([int(x['start'], 16) for x in self.record['function_extents']], list(subject.FUNCTIONS))
        self.assertTrue(all(int(x['end_exclusive'], 16) > int(x['start'], 16) for x in self.record['function_extents']))

    def test_digest_rejects_changed_image(self):
        modified = bytearray(self.data)
        modified[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.identity(modified)

    def test_actual_table_and_all_byte_decisions(self):
        table = bytes.fromhex(self.record['class_table_hex'])
        self.assertEqual(sum(bool(x) for x in table), 34)
        self.assertEqual([i for i in range(256) if subject.classify_byte(table, i) == 'quote'], [34])
        self.assertEqual([i for i in range(256) if subject.classify_byte(table, i) == 'escape'], [92])
        self.assertTrue(all(subject.classify_byte(table, i) == 'copy' for i in range(32)))
        self.assertEqual(subject.classify_byte(table, 255), 'copy')
        with self.assertRaises(ValueError):
            subject.check_table(bytes([table[0] ^ 1]) + table[1:])
        with self.assertRaises(ValueError):
            subject.classify_byte(table, 256)

    def test_quote_and_escaped_paths_corruption(self):
        for name in ('scanner_dispatch', 'scanner_escape', 'scanner_quote_return', 'context_length_and_copy', 'array_punctuation', 'array_value_result', 'number_entry', 'number_range'):
            va, _ = subject.WINDOWS[name]
            row = next(s for s in self.secs if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
            altered = bytearray(self.data)
            altered[row['offset'] + va - row['address']] ^= 1
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'instruction window mismatch'):
                subject.check_windows(altered, self.secs)

    def test_unescaped_payload_and_limits(self):
        table = bytes.fromhex(self.record['class_table_hex'])
        for length in (2047, 2048, 2049):
            state, payload = subject.scan_plain(table, b'0' * length + b'"')
            self.assertEqual(state, 'quote')
            self.assertEqual(payload, b'0' * length)
            self.assertEqual(len(payload) == 2048, length == 2048)
        self.assertEqual(subject.scan_plain(table, b'00"'), ('quote', b'00'))
        self.assertEqual(subject.scan_plain(table, b'abc'), ('exhausted', b'abc'))
        self.assertEqual(subject.scan_plain(table, b'a\\n"'), ('escape', b'a'))
        self.assertEqual(subject.scan_plain(table, b'\x00"'), ('quote', b'\x00'))

    def test_numeric_result_boundaries(self):
        for tag in (1, 2):
            for n in (0, 1, 255):
                self.assertEqual(subject.admit_number(tag, n), n)
            self.assertIsNone(subject.admit_number(tag, 256))
        for tag in (0, 3, 4):
            self.assertIsNone(subject.admit_number(tag, 1))
        self.assertIsNone(subject.admit_number(1, -1))

    def test_va_and_relocation_controls(self):
        with self.assertRaises(ValueError):
            subject.read_va(self.data, self.secs, 0, -1)
        with self.assertRaises(ValueError):
            subject.read_va(self.data, self.secs, 2**63, 1)
        bss = next(s for s in self.secs if s['name'] == '.bss' and s['type'] == 8 and s['size'])
        with self.assertRaises(ValueError):
            subject.read_va(self.data, self.secs, bss['address'], 1)
        with self.assertRaises(ValueError):
            subject.relative_relocations(self.data, self.secs, {0})
        rela = next(s for s in self.secs if s['name'] == '.rela.dyn')
        entry = next(off for off in range(rela['offset'], rela['offset'] + rela['size'], 24)
                     if struct.unpack_from('<Q', self.data, off)[0] == 0x5775508)
        altered = bytearray(self.data)
        altered[entry + 16] ^= 1
        with self.assertRaisesRegex(ValueError, 'relocation destination'):
            subject.check_relocations(altered, self.secs)
        altered[entry + 8] ^= 1
        with self.assertRaises(ValueError):
            subject.check_relocations(altered, self.secs)


if __name__ == '__main__':
    unittest.main()
