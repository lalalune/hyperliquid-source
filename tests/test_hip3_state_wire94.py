import hashlib
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import hip3_state_wire94 as subject


class WireEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.BINARY.read_bytes()
        cls.records = subject.collect(cls.data)
        cls.secs = subject.sections(cls.data)

    def changed(self, va, replacement):
        matches = [s for s in self.secs if s['type'] != 8 and s['address'] <= va < s['address'] + s['size']]
        self.assertEqual(len(matches), 1)
        s = matches[0]
        offset = s['offset'] + va - s['address']
        out = bytearray(self.data)
        out[offset:offset + len(replacement)] = replacement
        return bytes(out)

    def test_identity_and_extents(self):
        self.assertEqual(len(self.records['functions']), 5)
        self.assertEqual(self.records['target_sha256'], subject.DIGEST)
        self.assertEqual(self.records['functions'][1]['end'], '0x1a4bb02')

    def test_fields_and_dispatch(self):
        self.assertEqual([r['name'] for r in self.records['fields']],
                         ['m', 'half_life', 'max_slippage', 'max_n_depositors'])
        self.assertEqual([r['name'] for r in self.records['classifier_names']],
                         [r['name'] for r in self.records['fields']])
        self.assertEqual([r['target'] for r in self.records['reader_tag_dispatch']],
                         ['0x1a4b6fc', '0x1a4b83a', '0x1a4b78c', '0x1a4b7e2', '0x1a4b75b'])
        table = self.records['classifier_length_table']
        self.assertEqual([r['length'] for r in table if r['target'] != '0x16cd0dd'], [1, 9, 12, 16])

    def test_call_edges(self):
        edges = {r['site']: r['target'] for r in self.records['calls']}
        self.assertEqual(edges['0x1a4b1c3'], '0x16ccf80')
        self.assertEqual(edges['0x233e92a'], '0x25a8f80')
        self.assertEqual(edges['0x233e966'], '0x25a9bd0')

    def test_wrong_digest(self):
        with self.assertRaisesRegex(ValueError, 'digest'):
            subject.collect(self.data, '0' * 64)

    def test_mutated_classifier_rejected_even_with_new_digest(self):
        damaged = self.changed(0x16ccf9d, b'X')
        with self.assertRaisesRegex(ValueError, 'function bytes'):
            subject.collect(damaged, hashlib.sha256(damaged).hexdigest())

    def test_mutated_string_rejected_even_with_new_digest(self):
        damaged = self.changed(0x3e001d, b'X')
        with self.assertRaisesRegex(ValueError, 'field layout'):
            subject.collect(damaged, hashlib.sha256(damaged).hexdigest())

    def test_corrupt_dispatch_table(self):
        damaged = self.changed(0x3a8f68, b'\xff\xff\xff\x7f')
        with self.assertRaisesRegex(ValueError, 'dispatch target'):
            subject.collect(damaged, hashlib.sha256(damaged).hexdigest())

    def test_outside_range_and_invalid_opcode(self):
        with self.assertRaises(ValueError):
            subject.at(self.data, self.secs, 0xffffffffffffffff, 1)
        with self.assertRaises(ValueError):
            subject.decode_rel32(self.data, self.secs, 0x1a4b1c3, 0xe9)


if __name__ == '__main__':
    unittest.main()
