import copy
import hashlib
import json
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import evm_hash_json94 as subject


class EvmHashJsonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.BINARY.read_bytes()
        cls.sections = subject.sections(cls.data)
        cls.record = subject.collect(cls.data)

    def test_identity_and_selected_extents(self):
        self.assertEqual(subject.digest(self.data), subject.DIGEST)
        self.assertEqual(len(self.record['functions']), 20)
        for item in self.record['functions']:
            start, end = int(item['start'], 16), int(item['end_exclusive'], 16)
            self.assertGreater(end, start)
            self.assertEqual(item['sha256'], hashlib.sha256(subject.va_bytes(self.data, self.sections, start, end-start)).hexdigest())

    def test_call_edges_and_branch_destinations(self):
        for site, target in subject.CALLS.items():
            self.assertEqual(subject.rel_call(self.data, self.sections, site), target)
        for site, target in subject.BRANCHES.items():
            self.assertEqual(subject.branch(self.data, self.sections, site), target)
        self.assertEqual(len(self.record['calls']), 21)
        self.assertEqual(len(self.record['branches']), 43)
        for site, (prefix, target) in subject.RIPS.items():
            self.assertEqual(subject.rip_target(self.data, self.sections, site, prefix), target)
        self.assertEqual(len(self.record['rip_references']), 8)
        self.assertEqual([r['offset'] for r in self.record['first_item_byte_scan']], list(range(31, 0, -1)))
        for site in (0x280fe36, 0x2883a06):
            self.assertEqual(subject.indirect_slot(self.data, self.sections, site), 0x57705c0)

    def test_mutated_identity(self):
        data = bytearray(self.data)
        data[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'digest'):
            subject.collect(data)

    def test_mutated_instruction_even_if_identity_check_disabled(self):
        data = bytearray(self.data)
        section = next(s for s in self.sections if s['name'] == '.text')
        offset = section['offset'] + 0x291d193 - section['address']
        data[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction bytes'):
            subject.collect(data, check_digest=False)

    def test_call_and_branch_corruption(self):
        data = bytearray(self.data)
        section = next(s for s in self.sections if s['name'] == '.text')
        def offset(va):
            return section['offset'] + va - section['address']
        data[offset(0x291d40d)] = 0x90
        with self.assertRaises(ValueError):
            subject.rel_call(data, self.sections, 0x291d40d)
        data[offset(0x291d415)] = 0x90
        with self.assertRaises(ValueError):
            subject.branch(data, self.sections, 0x291d415)

    def test_file_backed_ranges_only(self):
        with self.assertRaises(ValueError):
            subject.va_bytes(self.data, self.sections, -1, 1)
        with self.assertRaises(ValueError):
            subject.va_bytes(self.data, self.sections, 0, -1)
        bss = next(s for s in self.sections if s['name'] == '.bss')
        with self.assertRaises(ValueError):
            subject.va_bytes(self.data, self.sections, bss['address'], 1)
        text = next(s for s in self.sections if s['name'] == '.text')
        with self.assertRaises(ValueError):
            subject.va_bytes(self.data, [text], text['address'] + text['size'] - 1, 2)
        with self.assertRaises(ValueError):
            subject.va_bytes(self.data, [text, copy.copy(text)], text['address'], 1)

    def test_alphabet_scalar_nibble_order_and_boundaries(self):
        alphabet = subject.va_bytes(self.data, self.sections, 0x208620, 16)
        for n in range(256):
            pair = bytes((alphabet[n >> 4], alphabet[n & 15]))
            self.assertEqual(pair.decode(), format(n, '02x'))
        self.assertEqual(subject.va_bytes(self.data, self.sections, 0x2030c0, 16), bytes([15]) * 16)
        self.assertEqual(subject.va_bytes(self.data, self.sections, 0x3f6ac3, 3), b'0x0')
        self.assertEqual(subject.va_bytes(self.data, self.sections, 0x3ec542, 3), b'0x0')
        self.assertEqual(subject.branch(self.data, self.sections, 0x28fbfc9), 0x28fc2d5)
        self.assertEqual(self.record['scalar_model']['text'], '0x' + bytes(range(32)).hex())
        self.assertEqual(json.loads(self.record['scalar_model']['row_json_no_whitespace']),
                         ['0x0', '0x' + bytes(range(32)).hex()])

    def test_four_word_model_against_integer_oracle(self):
        limit = 1 << 256
        values = (0, 1, (1 << 64) - 1, 1 << 128, limit - 1)
        for value in values:
            words = tuple((value >> (64 * i)) & ((1 << 64) - 1) for i in range(4))
            for base in (2, 8, 10, 16):
                for digit in (0, base - 1):
                    expected = value * base + digit
                    if expected >= limit:
                        with self.assertRaises(OverflowError):
                            subject.limb_step_model(words, base, digit)
                    else:
                        result = subject.limb_step_model(words, base, digit)
                        reconstructed = sum(word << (64 * i) for i, word in enumerate(result))
                        self.assertEqual(reconstructed, expected)
                with self.assertRaises(ValueError):
                    subject.limb_step_model(words, base, base)

    def test_format_descriptor_values(self):
        first = self.record['format_descriptors']['first']
        later = self.record['format_descriptors']['later']
        self.assertEqual((first['literal'], first['tag']), ('0x', 0xc0))
        self.assertEqual((later['tag'], later['options'], later['quantity']), (0xc3, '0x69000020', 2))

    def test_radix_prefixes_and_limb_overflow_branch(self):
        for site, prefix in ((0x28f7d05, b'0x'), (0x28f7d0c, b'0X'),
                             (0x28f7d18, b'0o'), (0x28f7d1f, b'0O'),
                             (0x28f7d2b, b'0b'), (0x28f7d32, b'0B')):
            instruction = subject.va_bytes(self.data, self.sections, site, 5)
            self.assertEqual(instruction[:3], bytes.fromhex('66813e'))
            self.assertEqual(instruction[3:], prefix)
        self.assertEqual(subject.branch(self.data, self.sections, 0x28f7e38), 0x28f7ef3)
        self.assertEqual(subject.branch(self.data, self.sections, 0x28f7e90), 0x28f7d93)
        self.assertEqual(subject.va_bytes(self.data, self.sections, 0x28f7e49, 3), bytes.fromhex('49f7e0'))
        self.assertEqual(self.record['limb_chain']['multiply_instructions'], 4)
        self.assertEqual(self.record['limb_chain']['carry_instructions'], 4)

    def test_array_byte_count_boundaries(self):
        compare = subject.va_bytes(self.data, self.sections, 0x280ab39, 4)
        extra = subject.va_bytes(self.data, self.sections, 0x280ab5c, 5)
        self.assertEqual(compare[:3], bytes.fromhex('4983fe'))
        self.assertEqual(extra[0], 0xbf)
        limit = compare[3]
        self.assertEqual(limit, 32)
        self.assertEqual(int.from_bytes(extra[1:], 'little'), 33)
        self.assertEqual(subject.branch(self.data, self.sections, 0x280ab26), 0x280abe3)
        self.assertEqual(subject.branch(self.data, self.sections, 0x280ab5a), 0x280ab76)
        for observed, expected in ((31, 'short'), (32, 'exact'), (33, 'extra')):
            actual = 'short' if observed < limit else 'exact' if observed == limit else 'extra'
            self.assertEqual(actual, expected)

    def test_interior_byte_scan_corruption(self):
        data = bytearray(self.data)
        section = next(s for s in self.sections if s['name'] == '.text')
        offset = section['offset'] + 0x28fae56 - section['address']
        data[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'byte scan coverage'):
            subject.collect(data, check_digest=False)

    def test_array_dispatch_corruption(self):
        self.assertEqual(self.record['array_dispatch']['target'], '0x2807f42')
        self.assertEqual(self.record['outer_array_dispatch']['target'], '0x26208a0')
        data = bytearray(self.data)
        ro = next(s for s in self.sections if s['name'] == '.rodata')
        offset = ro['offset'] + 0x3f1db4 - ro['address']
        data[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'array dispatch'):
            subject.collect(data, check_digest=False)

    def test_record_is_stable(self):
        self.assertEqual(self.record, subject.collect(self.data))

if __name__ == '__main__':
    unittest.main()
