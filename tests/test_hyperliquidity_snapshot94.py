import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from tools import hyperliquidity_snapshot94 as subject


class HyperliquiditySnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.BINARY.read_bytes()
        subject.verify_digest(cls.data)
        cls.image = subject.Image(cls.data)
        cls.record = subject.collect(cls.image)
        cls.names = [x[0] for x in subject.decode_classifier(cls.image.read)]

    def overlay(self, address, replacement):
        def read(va, size):
            actual = bytearray(self.image.read(va, size))
            lo, hi = max(va, address), min(va + size, address + len(replacement))
            if lo < hi:
                actual[lo-va:hi-va] = replacement[lo-address:hi-address]
            return bytes(actual)
        return read

    def test_digest_rejects_wrong_identity(self):
        self.assertEqual(subject.verify_digest(self.data), subject.SHA)
        with self.assertRaises(subject.EvidenceError):
            subject.verify_digest(self.data, '0' * 64)
        damaged = bytearray(b'not the node')
        with self.assertRaises(subject.EvidenceError):
            subject.verify_digest(damaged)

    def test_digest_checked_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'output'
            with self.assertRaises(subject.EvidenceError):
                subject.generate(b'wrong', target)
            self.assertFalse(target.exists())

    def test_file_backed_address_bounds(self):
        with self.assertRaises(subject.EvidenceError):
            self.image.read(0xffffffffffffffff, 1)
        with self.assertRaises(subject.EvidenceError):
            self.image.read(-1, 1)
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        with self.assertRaises(subject.EvidenceError):
            self.image.read(bss['address'], 1)
        text = next(s for s in self.image.sections if s['name'] == '.text')
        with self.assertRaises(subject.EvidenceError):
            self.image.read(text['address'] + text['size'] - 1, 2)

    def test_extents_and_linked_descriptors(self):
        self.assertEqual(len(self.record['functions']), 13)
        rows = {x['name']: x for x in self.record['functions']}
        self.assertEqual((rows['binary_outer_reader']['start'], rows['binary_outer_reader']['end_exclusive']),
                         (0x195b220, 0x195ccd7))
        self.assertEqual([d['text'] for d in self.record['descriptors']],
                         ['struct Hyperliquidity with 2 elements', 'struct Range with 2 elements'])
        self.assertEqual(len(rows['field_classifier']['sha256']), len(hashlib.sha256().hexdigest()))
        with self.assertRaises(subject.EvidenceError):
            self.image.function(0x195b221)

    def test_classifier_exact_keys_and_mutated_byte_domain(self):
        self.assertEqual(self.names, [b'spot_to_range', b'ensure_order_bucket_guard'])
        self.assertEqual(subject.classify(self.names[0], self.names), 0)
        self.assertEqual(subject.classify(self.names[1], self.names), 1)
        total = 0
        for key in self.names:
            for i, original in enumerate(key):
                for value in range(256):
                    if value == original:
                        continue
                    changed = bytearray(key)
                    changed[i] = value
                    self.assertEqual(subject.classify(bytes(changed), self.names), 2)
                    total += 1
            self.assertEqual(subject.classify(key[:-1], self.names), 2)
            self.assertEqual(subject.classify(key + b'!', self.names), 2)
        self.assertEqual(total, 9690)
        self.assertEqual(self.record['classifier_single_byte_rejections'], total)

    def test_classifier_rejects_damaged_opcode_offset_and_comparison(self):
        for va, mutation in [(0x16ce972, b'\x81'), (0x16ce97d, b'\x02'),
                             (0x16ce974, b'X'), (0x16ce963, b'\x0e')]:
            with self.subTest(va=hex(va)):
                with self.assertRaises(subject.EvidenceError):
                    subject.decode_classifier(self.overlay(va, mutation))

    def test_anchor_corruption_rejected(self):
        for va in [0x195b7ad, 0x195bf1a, 0x326373f, 0x264bf59, 0x1c77065]:
            with self.subTest(va=hex(va)):
                old = self.image.read(va, 1)
                with self.assertRaises(subject.EvidenceError):
                    subject.check_anchors(self.overlay(va, bytes([old[0] ^ 1])))

    def test_calls_refuse_modified_opcode_and_resolve_signed_displacements(self):
        for name, site, target in subject.DIRECT_CALLS:
            with self.subTest(name=name):
                self.assertEqual(subject.direct_call(self.image.read, site), target)
        with self.assertRaises(subject.EvidenceError):
            subject.direct_call(self.overlay(0x195b7c2, b'\xe9'), 0x195b7c2)
        with self.assertRaises(subject.EvidenceError):
            subject.slot_call(self.overlay(0x195b7f5, b'\x90'), 0x195b7f5)
        self.assertEqual(subject.slot_call(self.image.read, 0x195b7f5), 0x57725a0)
        self.assertEqual(self.image.relocations()[0x57725a0], 0x32636a0)

    def test_branch_decodes_both_sizes_and_rejects_corruption(self):
        for name, site, cond, target in subject.BRANCHES:
            with self.subTest(name=name):
                row = subject.branch(self.image.read, site)
                self.assertEqual((row['condition'], row['target']), (cond, target))
        with self.assertRaises(subject.EvidenceError):
            subject.branch(self.overlay(0x195b7ef, b'\x90'), 0x195b7ef)
        changed = self.overlay(0x195b7ef + 2, b'\x00')
        self.assertNotEqual(subject.branch(changed, 0x195b7ef)['target'], 0x195b8c5)

    def test_range_and_outer_field_literal_references(self):
        rows = {r['name']: r['text'] for r in self.record['literals']}
        self.assertEqual(rows['range_missing_order_size'], 'order_sz')
        self.assertEqual(rows['range_missing_points'], 'points')
        self.assertEqual(rows['range_duplicate_order_size'], 'order_sz')
        self.assertEqual(rows['range_duplicate_points'], 'points')
        self.assertEqual(len(self.record['templates']), 7)
        with self.assertRaises(subject.EvidenceError):
            subject.lea_target(self.overlay(0x175b17c, b'\x90'), 0x175b17c)

    def test_duplicate_error_bytes_and_default_width(self):
        self.assertEqual([x['text'] for x in self.record['duplicate_diagnostics']],
                         ['duplicate key', 'duplicate key'])
        self.assertEqual(self.record['default_values']['returned_first_word'], 3000)
        self.assertEqual(self.record['default_values']['day_millis_factor'], 86400000)
        self.assertEqual(struct.unpack('<I', self.image.read(0x3263740, 4))[0], 3000)
        self.assertEqual(struct.unpack('<I', self.image.read(0x32636a2, 4))[0], 719528)

    def test_writer_field_mode_and_memory_offsets(self):
        binary = self.image.read
        self.assertEqual(binary(0x32632b0, 4), bytes.fromhex('807a0b00'))
        self.assertEqual(binary(0x3263305, 5), bytes.fromhex('41807e0b01'))
        self.assertEqual(binary(0x3263343, 5), bytes.fromhex('41807e0b01'))
        self.assertEqual(binary(0x3263326, 4), bytes.fromhex('498d7710'))
        self.assertEqual(binary(0x3263369, 3), bytes.fromhex('4c89fe'))

    def test_generator_outputs_exact_file_set(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subject.generate(self.data, root)
            self.assertEqual({p.name for p in root.iterdir()}, {
                'evidence.json', 'functions.tsv', 'anchors.tsv', 'edges.tsv',
                'branches.tsv', 'field-comparisons.tsv', 'classifier-cases.tsv', 'literals.tsv', 'templates.tsv'})


if __name__ == '__main__':
    unittest.main()
