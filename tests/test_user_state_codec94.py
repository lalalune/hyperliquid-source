"""Static corruption controls for the authenticated node 94 user-state codec."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import user_state_codec94 as codec


class CodecEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(codec.BINARY.read_bytes())
        cls.image = codec.Image(cls.data)
        cls.records = codec.generate_records(cls.image)

    def changed(self, va, xor=1):
        """Shallow image copy with an isolated modified buffer and retained parsed metadata."""
        image = copy.copy(self.image)
        image.data = bytearray(self.data)
        image.data[image.offset(va, 1)] ^= xor
        return image

    def test_artifact_and_fde_records(self):
        r = self.records
        self.assertEqual(r['artifact_sha256'], codec.DIGEST)
        self.assertEqual(len(r['functions']), 11)
        self.assertEqual(len(r['fields']), 6)
        self.assertEqual(len(r['calls']), 36)
        self.assertEqual(len(r['classifier_length_tables']), 2)
        for row in r['functions']:
            start = int(row['start_va'], 16)
            end = int(row['end_va_exclusive'], 16)
            self.assertEqual(row['size'], end - start)
            self.assertEqual(hashlib.sha256(self.image.read(start, end-start)).hexdigest(), row['sha256'])

    def test_classifier_boundaries_and_each_changed_byte(self):
        rows = self.records['classifiers']
        expected = {b'user_to_state': 0, b'users_with_positions': 1,
                    b'check_all_users_for_liquidatables': 2,
                    b'asset_to_oi': 3, b'asset_to_oi_szi': 3,
                    b'open_order_tracker': 4, b'ar': 5}
        for name, tag in expected.items():
            self.assertEqual(codec.classify(name, rows), tag)
            self.assertEqual(codec.classify(name[:-1], rows), 6)
            self.assertEqual(codec.classify(name + b'\0', rows), 6)
            for i in range(len(name)):
                altered = name[:i] + bytes([name[i] ^ 1]) + name[i+1:]
                self.assertEqual(codec.classify(altered, rows), 6, (name, i))
        for length in range(35):
            self.assertEqual(codec.classify(b'?' * length, rows), 6)
        self.assertEqual(codec.classify(b'ASSET_TO_OI', rows), 6)
        with self.assertRaises(ValueError):
            codec.classify('ar', rows)

    def test_aliases_share_duplicate_guard(self):
        rows = self.records['classifiers']
        a = codec.classify(b'asset_to_oi', rows)
        b = codec.classify(b'asset_to_oi_szi', rows)
        self.assertEqual((a, b), (3, 3))
        f = self.records['fields'][a]
        self.assertEqual(f['binary_duplicate_branch_va'], '0x1a49c6d')
        self.assertEqual(f['json_duplicate_branch_va'], '0x1d1fde6')
        self.assertEqual(f['name'], 'asset_to_oi_szi')

    def test_field_order_layout_and_headers(self):
        fields = self.records['fields']
        self.assertEqual([x['name'] for x in fields], [
            'user_to_state', 'users_with_positions', 'check_all_users_for_liquidatables',
            'asset_to_oi_szi', 'open_order_tracker', 'ar'])
        self.assertEqual([int(x['input_offset'], 16) for x in fields], [0, 0x60, 0xa8, 0x78, 0x30, 0x90])
        self.assertEqual(self.records['direct_binary_headers'], {
            'map_when_flag_1': '0x86', 'array_when_flag_0': '0x96', 'ar_name_marker': '0xa2'})
        self.assertEqual([r['tag'] for r in self.records['json_required_tests']], [0, 1, 2])
        self.assertEqual([r['tag'] for r in self.records['json_optional_tests']], [3, 4, 5])
        self.assertEqual([r['default_target_va'] for r in self.records['json_optional_tests']],
                         ['0x1d20b77', '0x1d20bc9', '0x1d20c1d'])
        self.assertEqual(len(self.records['writer_branches']), 28)
        json_failures = [x['target_va'] for x in self.records['writer_branches']
                         if x['role'].startswith('JSON')]
        self.assertEqual(json_failures, ['0x230e038'] * 6)
        self.assertEqual(len({r['binary_duplicate_target_va'] for r in fields}), 6)
        self.assertEqual(len({r['json_duplicate_target_va'] for r in fields}), 6)

    def test_bad_digest_is_rejected(self):
        corrupt = bytearray(self.data)
        corrupt[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            codec.Image(corrupt)

    def test_corrupted_code_fails_closed(self):
        for site in (0x2301330, 0x1a49c6d, 0x1d1fde6, 0x230d9d8, 0x23d7324):
            with self.subTest(site=site):
                with self.assertRaisesRegex(ValueError, 'body changed'):
                    self.changed(site).check_functions()

    def test_corrupt_alias_immediate_and_simd_constant(self):
        for site in (0x230139d, 0x23013aa, 0x205830, 0x206c60, 0x207a70, 0x204f20):
            with self.subTest(site=site):
                with self.assertRaises(ValueError):
                    codec.names_and_classifier(self.changed(site), [13, 20, 33, 15, 18, 2])

    def test_corrupt_jump_table_and_branch(self):
        for site in (0x3dc380, 0x3dc400):
            with self.subTest(site=site):
                with self.assertRaises(ValueError):
                    codec.names_and_classifier(self.changed(site), [13, 20, 33, 15, 18, 2])
        with self.assertRaises(ValueError):
            codec.conditional(self.changed(0x1a49c6d), 0x1a49c6d, b'\x0f\x85')
        self.assertNotEqual(codec.conditional(self.changed(0x1a49c6f), 0x1a49c6d, b'\x0f\x85'),
                            codec.conditional(self.image, 0x1a49c6d, b'\x0f\x85'))
        with self.assertRaises(ValueError):
            codec.generate_records(self.changed(0x3a86fc))
        with self.assertRaises(ValueError):
            codec.generate_records(self.changed(0x3b70b4))
        with self.assertRaises(ValueError):
            codec.generate_records(self.changed(0x3b91ea))

    def test_corrupt_layout_and_call_opcode(self):
        for site in (0x230d8a9, 0x230d8c2, 0x230d8df, 0x230d9c9):
            with self.subTest(site=site):
                with self.assertRaises(ValueError):
                    codec.writer_layout(self.changed(site))
        with self.assertRaises(ValueError):
            codec.direct_call(self.changed(0x230d9d8), 0x230d9d8)
        self.assertNotEqual(codec.direct_call(self.changed(0x230d9d9), 0x230d9d8),
                            codec.direct_call(self.image, 0x230d9d8))

    def test_unmapped_nobits_and_section_crossing_rejected(self):
        bss = next(s for s in self.image.secs if s['name'] == '.bss' and s['type'] == 8)
        with self.assertRaises(ValueError):
            self.image.read(bss['address'], 1)
        text = next(s for s in self.image.secs if s['name'] == '.text')
        with self.assertRaises(ValueError):
            self.image.read(text['address'] + text['size'] - 1, 2)
        for va, size in ((0, 1), (-1, 1), (1 << 64, 1), (text['address'], 0)):
            with self.subTest(va=va, size=size):
                with self.assertRaises(ValueError):
                    self.image.read(va, size)

    def test_repeatable_generated_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / 'one', Path(d) / 'two'
            codec.generate(self.image, a)
            codec.generate(self.image, b)
            self.assertEqual(sorted(x.name for x in a.iterdir()), ['fields.tsv', 'records.json'])
            for name in ('fields.tsv', 'records.json'):
                self.assertEqual((a / name).read_bytes(), (b / name).read_bytes())
            self.assertEqual(json.loads((a / 'records.json').read_text()), self.records)


if __name__ == '__main__':
    unittest.main()
