import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import apphash_tuples94 as subject


class ByteView:
    def __init__(self, raw):
        self.raw = raw
    def read(self, va, size):
        if va < 0 or va + size > len(self.raw):
            raise ValueError('outside')
        return self.raw[va:va + size]


class AppHashTupleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.view = subject.View(cls.data)
        cls.result = subject.build(cls.data)

    def test_complete_child_order_and_failure(self):
        groups = self.result['groups']
        self.assertEqual([x['count'] for x in groups], [15, 16])
        self.assertEqual([len(x['children']) for x in groups], [14, 15])
        for group in groups:
            self.assertEqual([r['box_offset'] for r in group['children']], list(range(8, group['count'] * 8, 8)))
            self.assertEqual(len({r['error_target'] for r in group['children']}), 1)
        self.assertEqual(self.result['third_group']['count'], 8)
        self.assertEqual([r['box_offset'] for r in self.result['third_group']['children']], [8, 16, 32, 40, 48, 56])

    def test_literals_and_cases(self):
        self.assertEqual([x['literal'] for x in self.result['first_group_enum']], ['Local', 'Sandbox', 'Testnet', 'Mainnet'])
        self.assertEqual([x['literal'] for x in self.result['third_group']['string_cases']], ['disabled', 'reduceOnly', 'enabled'])

    def test_digest_rejects_wrong_input(self):
        with self.assertRaises(ValueError):
            subject.require_identity(self.data[:-1])

    def test_bad_instructions_are_rejected(self):
        with self.assertRaises(ValueError):
            subject.call(ByteView(b'\x90\x00\x00\x00\x00'), 0)
        with self.assertRaises(ValueError):
            subject.branch(ByteView(b'\x74\x00'), 0)
        with self.assertRaises(ValueError):
            subject.check(ByteView(b'\x90'), 0, 'cc')

    def test_relative_displacement(self):
        self.assertEqual(subject.call(ByteView(b'\xe8\xfb\xff\xff\xff'), 0), 0)
        self.assertEqual(subject.branch(ByteView(b'\x75\xfe'), 0), 0)
        self.assertEqual(subject.branch(ByteView(b'\x0f\x85\xfa\xff\xff\xff'), 0), 0)

    def test_unmapped_and_nobits_rejected(self):
        with self.assertRaises(ValueError):
            self.view.read(-1, 1)
        with self.assertRaises(ValueError):
            self.view.read(0xffffffffffffffff, 2)
        nobits = next(s for s in subject.sections(self.data) if s['type'] == 8 and s['name'] == '.bss')
        with self.assertRaises(ValueError):
            self.view.read(nobits['address'], 1)

    def test_code_corruption_rejected_after_identity_bypass(self):
        changed = bytearray(self.data)
        va = 0x1e5e558
        section = next(s for s in self.view.sections if s['address'] <= va < s['address'] + s['size'])
        changed[section['offset'] + va - section['address']] ^= 1
        with self.assertRaises(ValueError):
            subject.analyse(bytes(changed))

    def test_literal_corruption_rejected_after_identity_bypass(self):
        changed = bytearray(self.data)
        va = 0x3dff5e
        section = next(s for s in self.view.sections if s['address'] <= va < s['address'] + s['size'])
        changed[section['offset'] + va - section['address']] ^= 1
        with self.assertRaises(ValueError):
            subject.analyse(bytes(changed))

    def test_field_scanner_rejects_shifted_range(self):
        with self.assertRaises(ValueError):
            subject.child_rows(self.view, 0x1e5e55f, 0x1e5e6cb, 14, 0x1e5e709)


if __name__ == '__main__':
    unittest.main()
