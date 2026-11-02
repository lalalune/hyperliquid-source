import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import perpdex_snapshot94 as p


class PerpDexSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = p.BINARY.read_bytes()
        cls.sections = p.sections(cls.data)
        cls.result = p.extract(cls.data)

    def mutate(self, va):
        data = bytearray(self.data)
        _, off = p.va_bytes(data, self.sections, va, 1)
        data[off] ^= 1
        return data

    def test_identity_and_extents(self):
        self.assertEqual(len(self.result['functions']), 6)
        self.assertEqual([x['end_exclusive'] for x in self.result['functions']], ['0x16bfdf5', '0x24d1a8b', '0x17a4564', '0x16d17e7', '0x2443d8b', '0x2443868'])
        with self.assertRaises(ValueError):
            p.authenticate(self.data, '0' * 64)

    def test_field_table_and_calls(self):
        self.assertEqual([f['name'] for f in self.result['field_literals']], ['books', 'funding_tracker', 'twap_tracker', 'perp_to_annotation'])
        self.assertEqual([r['target'] for r in self.result['map_table']['entries']], ['0x17a3ae9', '0x17a3dee', '0x17a3bdb', '0x17a3d04', '0x17a3b55'])
        self.assertEqual(len(self.result['calls']), 4)
        self.assertEqual([x['name'] for x in self.result['writer_fields']], [x['name'] for x in self.result['field_literals']])
        self.assertEqual(len(self.result['branches']), 12)

    def test_modified_branch_rejected_even_with_rehashed_input(self):
        data = self.mutate(0x17a2039)
        with self.assertRaisesRegex(ValueError, 'window mismatch'):
            p.extract(data, hashlib.sha256(data).hexdigest())

    def test_modified_table_rejected_even_with_rehashed_input(self):
        data = self.mutate(0x2cbc58)
        with self.assertRaisesRegex(ValueError, 'table mismatch'):
            p.extract(data, hashlib.sha256(data).hexdigest())

    def test_modified_field_rejected_even_with_rehashed_input(self):
        data = self.mutate(0x3b0c92)
        with self.assertRaisesRegex(ValueError, 'field literal mismatch'):
            p.extract(data, hashlib.sha256(data).hexdigest())

    def test_classifier_exact_names_and_mutations(self):
        rows = self.result['field_classifier']
        tags = {r['field'].encode(): r['tag'] for r in rows}
        self.assertEqual([tags.get(r['field'].encode(), 4) for r in rows], [0, 1, 2, 3])
        for name in tags:
            for i in range(len(name)):
                for bit in (1, 0x80):
                    bad = name[:i] + bytes([name[i] ^ bit]) + name[i+1:]
                    self.assertEqual(tags.get(bad, 4), 4)
            self.assertEqual(tags.get(name + b'X', 4), 4)
            self.assertEqual(tags.get(name[:-1], 4), 4)

    def test_corrupted_key_compare_rejected(self):
        data = self.mutate(0x16d162e)
        with self.assertRaisesRegex(ValueError, 'window mismatch'):
            p.extract(data, hashlib.sha256(data).hexdigest())

    def test_corrupted_writer_gate_rejected(self):
        data = self.mutate(0x2443d0f)
        with self.assertRaisesRegex(ValueError, 'window mismatch'):
            p.extract(data, hashlib.sha256(data).hexdigest())

    def test_bad_address_and_call(self):
        with self.assertRaises(ValueError):
            p.va_bytes(self.data, self.sections, 0xffffffffffff, 8)
        with self.assertRaises(ValueError):
            p.direct_call(self.data, self.sections, 0x17a2036)
        with self.assertRaises(ValueError):
            p.va_bytes(self.data, self.sections, 0, -1)


if __name__ == '__main__':
    unittest.main()
