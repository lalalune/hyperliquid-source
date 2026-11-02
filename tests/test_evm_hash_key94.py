import hashlib
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from tools import evm_hash_key94 as t
from tools.elf_index import sections


class HashKeyEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (t.ROOT / 'artifacts/node/94/hl-node').read_bytes()
        cls.secs = sections(cls.data)
        cls.evidence = t.analyze(cls.data)

    def test_selected_edges(self):
        self.assertEqual(t.direct_call(self.data, self.secs, 0x28fa72a), 0x28f7810)
        self.assertEqual(t.direct_call(self.data, self.secs, 0x28f846e), 0x28f7810)
        self.assertEqual(t.branch(self.data, self.secs, 0x28fa708), 0x28fa725)
        self.assertEqual(t.branch(self.data, self.secs, 0x28f8448), 0x28f8469)
        self.assertEqual(len(self.evidence['functions']), 14)
        self.assertEqual([x['offset'] for x in self.evidence['significant_byte_scan']], list(range(31, -1, -1)))

    def test_bad_hash(self):
        with self.assertRaisesRegex(ValueError, 'digest'):
            t.analyze(self.data, '0' * 64)

    def test_rehashed_corrupted_body(self):
        sec = next(s for s in self.secs if s['name'] == '.text')
        off = sec['offset'] + 0x28f7810 - sec['address']
        damaged = bytearray(self.data)
        damaged[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'body'):
            t.analyze(damaged, hashlib.sha256(damaged).hexdigest())

    def test_rehashed_reader_table_corruption(self):
        table = 0x322f18 + 4 * 0xc4
        sec = next(s for s in self.secs if s['type'] != 8 and s['address'] <= table < s['address'] + s['size'])
        damaged = bytearray(self.data)
        damaged[sec['offset'] + table - sec['address']] ^= 1
        with self.assertRaisesRegex(ValueError, 'reader table'):
            t.analyze(damaged, hashlib.sha256(damaged).hexdigest())

    def test_opcode_corruption(self):
        sec = next(s for s in self.secs if s['name'] == '.text')
        off = sec['offset'] + 0x28fa72a - sec['address']
        damaged = bytearray(self.data)
        damaged[off] = 0x90
        with self.assertRaises(ValueError):
            t.direct_call(damaged, self.secs, 0x28fa72a)
        with self.assertRaises(ValueError):
            t.branch(self.data, self.secs, 0x28fa72a)

    def test_unmapped_and_nobits(self):
        with self.assertRaises(ValueError):
            t.va_bytes(self.data, self.secs, 0xffffffffffffffff, 1)
        bss = next(s for s in self.secs if s['name'] == '.bss')
        with self.assertRaises(ValueError):
            t.va_bytes(self.data, self.secs, bss['address'], 1)
        with self.assertRaises(ValueError):
            t.va_bytes(self.data, self.secs, 0x28f7810, 0)

    def test_compact_examples(self):
        self.assertEqual(t.model(bytes(32))['compact_hex'], 'c420' + '00' * 32)
        self.assertEqual(t.model(bytes(range(32)))['compact_hex'],
                         'c4201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100')
        for i in range(32):
            x = bytearray(32)
            x[i] = 1
            result = bytes.fromhex(t.model(x)['compact_hex'])
            self.assertEqual(result[2 + 31 - i], 1)
            self.assertEqual(sum(result[2:]), 1)

    def test_simd_lane_evaluation_and_corruption(self):
        self.assertEqual(self.evidence['simd_input_indices_in_output_order'], list(range(31, -1, -1)))
        bad = bytearray(t.SIMD)
        bad[30] ^= 1
        with self.assertRaisesRegex(ValueError, 'SIMD'):
            t.simd_permutation(bad)

    def test_selected_reader_length_and_roundtrip(self):
        raw = bytes(range(32))
        payload = bytes.fromhex(t.model(raw)['compact_hex'])[2:]
        self.assertEqual(t.reader_payload(payload, 32), raw)
        self.assertEqual(t.read_compact(bytes.fromhex(t.model(raw)['compact_hex'])), raw)
        for frame in (b'', b'\xc4', b'\xc5\x20' + payload):
            with self.assertRaises(ValueError):
                t.read_compact(frame)
        for length in (0, 31, 33):
            with self.assertRaises(ValueError):
                t.reader_payload(payload, length)
        with self.assertRaisesRegex(ValueError, 'truncated'):
            t.reader_payload(payload[:-1], 32)

    def test_static_two_operand_row(self):
        key = bytes(range(32))
        value = bytes(range(32, 64))
        row = t.model_row(key, value)
        self.assertEqual(len(row), 69)
        self.assertEqual(row[:3], b'\x92\xc4\x20')
        self.assertEqual(row[3:35], bytes(range(31, -1, -1)))
        self.assertEqual(row[35:37], b'\xc4\x20')
        self.assertEqual(row[37:], value)
        with self.assertRaises(ValueError):
            t.model_row(key, value[:-1])

    def test_invalid_operand_width(self):
        for n in (0, 31, 33):
            with self.assertRaises(ValueError):
                t.model(bytes(n))


if __name__ == '__main__':
    unittest.main()
