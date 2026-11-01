import hashlib
from pathlib import Path
import unittest

from tools import lattice_json_write94 as subject
from tools.elf_index import sections


class LatticeJsonWriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.BINARY.read_bytes()
        cls.secs = sections(cls.data)
        cls.rec = subject.extract(cls.data)
        cls.pairs = cls.rec['decimal_table_ascii'].encode('ascii')

    def test_byte_decimal_all_inputs(self):
        for value in range(256):
            self.assertEqual(subject.decimal_byte(value, self.pairs, 256), str(value).encode())

    def test_u64_decimal_boundaries_and_dense_small_range(self):
        magic = int(self.rec['chunk_reciprocal'], 16)
        values = list(range(65536)) + [10**n + d for n in range(1, 20) for d in (-1, 0, 1)]
        values += [(1 << 64) - 1, (1 << 63), (1 << 63) - 1]
        state = 1
        for _ in range(10000):
            state = (state * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
            values.append(state)
        for value in values:
            self.assertEqual(subject.decimal_u64(value, self.pairs, magic, 20, 10000), str(value).encode())

    def test_input_and_formatter_negative_controls(self):
        with self.assertRaises(ValueError): subject.checked_digest(self.data, '0' * 64)
        for value in (-1, 256):
            with self.assertRaises(ValueError): subject.decimal_byte(value, self.pairs, 256)
        for value in (-1, 1 << 64):
            with self.assertRaises(ValueError): subject.decimal_u64(value, self.pairs, int(self.rec['chunk_reciprocal'],16), 20, 10000)
        with self.assertRaises(ValueError): subject.decimal_byte(1, self.pairs[:-1], 256)

    def test_selected_edges(self):
        self.assertEqual([row['target'] for row in self.rec['calls']],
                         ['0x3c8c100', '0x3c8c100', '0x3c83850', '0x3bebf60', '0x3c1d4d0'])
        self.assertEqual([x['ascii'] for x in self.rec['fields']], ['n_elements','n_bytes','hash'])
        self.assertEqual(self.rec['hash_input_bytes'], 2048)
        self.assertEqual(len(self.rec['fdes']), 4)
        self.assertEqual(len(self.rec['branches']), 17)
        self.assertEqual(self.rec['branches'][2]['destination'], '0x3bec2d0')

    def test_changed_instruction_and_bad_call_fail(self):
        sec = next(s for s in self.secs if s['name'] == '.text')
        modified = bytearray(self.data)
        off = sec['offset'] + 0x3c8389e - sec['address']
        modified[off] ^= 1
        with self.assertRaises(ValueError): subject.require(modified, self.secs, 0x3c8388f, bytes.fromhex(subject.PINS[0x3c8388f]))
        with self.assertRaises(ValueError): subject.rel32(modified, self.secs, 0x3c8389e)
        with self.assertRaises(ValueError): subject.checked_digest(modified)

    def test_rehashed_body_corruption_is_detected(self):
        modified = bytearray(self.data)
        sec = next(s for s in self.secs if s['name'] == '.text')
        modified[sec['offset'] + 0x3bebf60 - sec['address']] ^= 1
        old = subject.DIGEST
        try:
            subject.DIGEST = hashlib.sha256(modified).hexdigest()
            with self.assertRaisesRegex(ValueError, 'body hash'): subject.extract(modified)
        finally:
            subject.DIGEST = old

    def test_rehashed_table_corruption_is_detected(self):
        modified = bytearray(self.data)
        va = int(self.rec['decimal_table_va'], 16)
        sec = next(s for s in self.secs if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        modified[sec['offset'] + va - sec['address']] ^= 1
        old = subject.DIGEST
        try:
            subject.DIGEST = hashlib.sha256(modified).hexdigest()
            with self.assertRaisesRegex(ValueError, 'decimal table'): subject.extract(modified)
        finally:
            subject.DIGEST = old

    def test_unmapped_and_nobits_are_rejected(self):
        with self.assertRaises(ValueError): subject.at(self.data, self.secs, 0xffffffffffffffff, 1)
        bss = next(s for s in self.secs if s['name'] == '.bss')
        with self.assertRaises(ValueError): subject.at(self.data, self.secs, bss['address'], 1)
        text = next(s for s in self.secs if s['name'] == '.text')
        with self.assertRaises(ValueError): subject.at(self.data, self.secs, text['address'] + text['size'] - 1, 2)


if __name__ == '__main__':
    unittest.main()
