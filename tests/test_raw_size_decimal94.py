import json
import unittest

from tools import raw_size_decimal94 as subject


class RawSizeDecimal94(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.evidence, cls.vectors = subject.collect(cls.data)
        cls.image = subject.Image(cls.data)
        cls.table = cls.image.read(subject.TABLE, 200)
        cls.magic = cls.evidence['arithmetic']['reciprocal_100']
        cls.reciprocal = int(cls.evidence['arithmetic']['reciprocal_10000'], 16)

    def test_metadata_and_links(self):
        self.assertEqual(len(self.evidence['functions']), 6)
        self.assertEqual([r['key'] for r in self.evidence['field_sites']], ['sz', 'sz', 'order_sz', 'executed_sz', 'executed_sz'])
        self.assertEqual(len(self.evidence['schedule_edges']), 2)
        self.assertEqual(len(self.evidence['digit_branches']), 13)
        self.assertEqual(self.evidence['digit_table']['entries'], 100)

    def test_model_boundaries(self):
        for n in (0, 9, 10, 99, 100, 9999, 10000, 99999999, 100000000,
                  (1 << 63) - 1, 1 << 63, (1 << 64) - 1):
            with self.subTest(n=n):
                self.assertEqual(subject.lifted(n, self.table, self.reciprocal, self.magic), str(n).encode())
        self.assertEqual(self.evidence['model_mismatches'], 0)
        self.assertGreater(self.evidence['model_cases'], 1000)

    def test_reciprocal_control(self):
        self.assertTrue(all((((r >> 2) * self.magic) >> 17) == r // 100 for r in range(10000)))
        self.assertTrue(any((((r >> 2) * (self.magic - 1)) >> 17) != r // 100 for r in range(10000)))
        n = 10000
        self.assertNotEqual((n * (self.reciprocal - 1)) >> 75, n // 10000)

    def test_digest_control(self):
        with self.assertRaises(ValueError):
            subject.digest(b'not the target')

    def test_address_control(self):
        for va, size in ((0, 1), (subject.TABLE, -1), ((1 << 64) - 1, 2)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                self.image.read(va, size)

    def test_corrupted_qualified_instruction(self):
        altered = bytearray(self.data)
        altered[self.image.offset(0x3303d48)] ^= 1
        with self.assertRaises(ValueError):
            subject.Image(altered, authenticate=False).validate()

    def test_corrupted_table(self):
        altered = bytearray(self.data)
        altered[self.image.offset(subject.TABLE)] ^= 1
        with self.assertRaises(ValueError):
            subject.Image(altered, authenticate=False).validate()

    def test_corrupted_key(self):
        altered = bytearray(self.data)
        altered[self.image.offset(0x20b030)] ^= 1
        with self.assertRaises(ValueError):
            subject.Image(altered, authenticate=False).validate()

    def test_range_and_table_controls(self):
        for n in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                subject.lifted(n, self.table, self.reciprocal, self.magic)
        with self.assertRaises(ValueError):
            subject.lifted(100, b'', self.reciprocal, self.magic)
        changed = bytearray(self.table)
        changed[2:4] = b'XX'
        self.assertNotEqual(subject.lifted(10001, changed, self.reciprocal, self.magic), b'10001')

    def test_packet_outputs(self):
        packet = subject.ROOT / 'research/work-items/RE-004-raw-size-decimal-94'
        self.assertEqual(json.loads((packet / 'evidence.json').read_text()), self.evidence)
        self.assertEqual((packet / 'vectors.tsv').read_text(), self.vectors)


if __name__ == '__main__':
    unittest.main()
