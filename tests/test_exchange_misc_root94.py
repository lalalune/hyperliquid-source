"""Static checks and negative controls for the node 94 ExchangeMisc evidence."""
import hashlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import exchange_misc_root94 as subject


class ExchangeMiscEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.BINARY.read_bytes()
        cls.image = subject.Image(cls.data)
        cls.record = subject.extract(cls.data)

    def corrupt(self, va):
        changed = bytearray(self.data)
        changed[self.image.offset(va, 1)] ^= 1
        return changed

    def test_digest_and_fde_ranges(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), subject.DIGEST)
        self.assertEqual(len(self.record['functions']), 25)
        for row in self.record['functions']:
            start = int(row['start_va'], 16)
            end = int(row['end_va_exclusive'], 16)
            self.assertEqual(end - start, row['size'])
            self.assertEqual(hashlib.sha256(self.image.read(start, end-start, True)).hexdigest(),
                             row['body_sha256'])

    def test_state_hash_capture_context(self):
        c = self.record['hash_capture_context']
        self.assertEqual(c['state_offset'], 0x3a70)
        self.assertEqual(c['job_pointer_offset'], 0x250)
        self.assertEqual(c['vtable_va'], '0x56bded8')
        self.assertEqual((c['vtable_size'], c['vtable_align']), (8, 8))
        self.assertEqual(c['method_thunk_va'], '0x21e3210')
        self.assertEqual(c['closure_body_va'], '0x2815ba0')
        self.assertEqual(c['writer_config_hex'], '00040001')
        self.assertEqual(c['writer_flag_byte'], 0)

    def test_codec_call_chain(self):
        calls = {(int(row['site_va'], 16), int(row['target_va'], 16))
                 for row in self.record['direct_calls']}
        self.assertEqual(len(calls), len(subject.CALLS))
        for edge in [(0x2815bf0, 0x221aa80), (0x221ab14, 0x25e84c0),
                     (0x25e852a, 0x256b9c0), (0x25e8538, 0x1e35e60),
                     (0x1e3604e, 0x1de7260), (0x1de76fa, 0x281d230),
                     (0x19f91ca, 0x197ab70), (0x19f93c7, 0x197ab70),
                     (0x197af46, 0x26563e0), (0x197b08a, 0x2680ef0),
                     (0x26564e4, 0x284daa0), (0x2680fa1, 0x284daa0),
                     (0x265648a, 0x1961a70), (0x2680f55, 0x1834eb0),
                     (0x18355c2, 0x1961a70), (0x1961f88, 0x1689950),
                     (0x1689a8a, 0x1a38ab0), (0x1a38bcf, 0x280a770),
                     (0x26014eb, 0x265b560), (0x265b5b6, 0x1b81580),
                     (0x1b81802, 0x1baac30), (0x26016af, 0x1baac30),
                     (0x1baae02, 0x281d3a0), (0x281d417, 0x1bab5b0)]:
            self.assertIn(edge, calls)

    def test_field_role_and_failure_literals(self):
        self.assertEqual(self.record['field']['ascii'], 'uta')
        self.assertEqual(self.record['struct_diagnostic']['ascii'],
                         'struct ExchangeMisc with 1 element')
        self.assertEqual([(v['parser_tag'], v['name'], v['buffer_marker'])
                          for v in self.record['role_variants']],
                         [(0, 'technical', 0xa9), (1, 'treasury', 0xa8)])
        self.assertEqual(self.record['duplicate_key_diagnostics'],
                         ['duplicate key', 'duplicate key', 'duplicate key', 'duplicate key'])
        for field in ('reader_va', 'writer_va', 'diagnostic_va'):
            self.assertEqual(self.image.read(int(self.record['field'][field], 16), 3), b'uta')

    def test_binary_role_classifier_and_corruption(self):
        rows = self.record['binary_role_classifier']
        self.assertEqual([(r['tag'], r['name']) for r in rows],
                         [(0, 'technical'), (1, 'treasury')])
        img = subject.Image(self.corrupt(0x280a782), verify_digest=False)
        with self.assertRaisesRegex(ValueError, 'classifiers differ'):
            subject.binary_role_checks(img, subject.role_names(img))

    def test_role_match_boundaries_and_near_names(self):
        # This is a model of the two length-and-byte comparisons, not node execution.
        variants = [row['name'].encode('ascii') for row in self.record['role_variants']]
        def classify(value):
            return next((i for i, candidate in enumerate(variants) if value == candidate), None)
        for tag, word in enumerate(variants):
            self.assertEqual(classify(word), tag)
            self.assertIsNone(classify(word[:-1]))
            self.assertIsNone(classify(word + b'x'))
            for i, original in enumerate(word):
                for byte in range(256):
                    if byte != original:
                        self.assertIsNone(classify(word[:i] + bytes([byte]) + word[i+1:]))
        self.assertIsNone(classify(b'Technical'))
        self.assertIsNone(classify(b'treasurY'))

    def test_reader_and_writer_branches(self):
        rows = {(int(x['site_va'], 16), x['operation'], int(x['target_va'], 16))
                for x in self.record['conditional_branches']}
        self.assertEqual(len(rows), len(subject.BRANCHES))
        for edge in [(0x221aaa2, 'je', 0x221aad0),
                     (0x221aaef, 'jne', 0x221ab0b),
                     (0x221ab21, 'jne', 0x221ab36),
                     (0x19f91a2, 'jne', 0x19f8e46),
                     (0x19f91b0, 'jne', 0x19f9770),
                     (0x19f922e, 'je', 0x19f9251),
                     (0x19f8e40, 'je', 0x19f91a8),
                     (0x1bab68f, 'jne', 0x1bab6cc)]:
            self.assertIn(edge, rows)

    def test_collector_tree_record_layout(self):
        compare = self.record['tree_key_comparison']
        self.assertEqual((compare['symbol'], compare['key_length']), ('memcmp', 20))
        b = self.image.read(0x256ba6a, 38, True)
        self.assertEqual(b[:4], bytes.fromhex('4c8d1492'))
        self.assertEqual(b[4:8], bytes.fromhex('4f8d1491'))
        self.assertEqual(b[8:15], bytes.fromhex('4981c2b8000000'))
        self.assertEqual(b[15:19], bytes.fromhex('48c1e204'))
        self.assertIn(bytes.fromhex('4a89540b08'), b)

    def test_integer_width_boundaries(self):
        expected = ['00', '7f', 'cc80', 'ccff', 'cd0100', 'cdffff',
                    'ce00010000', 'ceffffffff', 'cf0000000100000000',
                    'cfffffffffffffffff']
        self.assertEqual([r['model_hex'] for r in self.record['integer_boundary_model']], expected)
        rules = self.record['integer_rules']
        for value in (-1, 1 << 64, '1', True):
            with self.assertRaises(ValueError):
                subject.integer_model(value, rules)

    def test_integer_threshold_mutation_rejected(self):
        img = subject.Image(self.corrupt(0x25abd4b), verify_digest=False)
        with self.assertRaisesRegex(ValueError, 'integer rules changed'):
            subject.integer_rules(img)

    def test_bad_digest_rejected_before_parsing(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.Image(self.corrupt(0x221aa80))

    def test_rehashed_code_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'FDE bytes changed'):
            subject.extract(self.corrupt(0x221ab14), verify_digest=False)

    def test_fde_extent_mutation_rejected(self):
        fde = int(next(row['fde_va'] for row in self.record['functions']
                       if row['start_va'] == '0x221aa80'), 16)
        with self.assertRaises(ValueError):
            subject.extract(self.corrupt(fde + 12), verify_digest=False)

    def test_role_marker_mutation_rejected(self):
        img = subject.Image(self.corrupt(0x281d253), verify_digest=False)
        with self.assertRaisesRegex(ValueError, 'role writer branch or marker changed'):
            subject.role_names(img)

    def test_rehashed_field_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'field literal mismatch'):
            subject.extract(self.corrupt(0x3d6bf6), verify_digest=False)

    def test_rehashed_role_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'role literals changed'):
            subject.extract(self.corrupt(0x3f40ff), verify_digest=False)

    def test_changed_opcodes_rejected(self):
        img = subject.Image(self.corrupt(0x221ab14), verify_digest=False)
        with self.assertRaisesRegex(ValueError, 'expected direct call'):
            subject.direct_call(img, 0x221ab14)
        img = subject.Image(self.corrupt(0x19f91b0), verify_digest=False)
        with self.assertRaisesRegex(ValueError, 'expected conditional branch'):
            subject.branch(img, 0x19f91b0)

    def test_duplicate_diagnostic_mutation_rejected(self):
        img = subject.Image(self.corrupt(0x265b625), verify_digest=False)
        with self.assertRaisesRegex(ValueError, 'duplicate diagnostic mismatch'):
            subject.duplicate_key(img, 0x265b620)

    def test_relocation_corruption_rejected(self):
        rel = next(s for s in self.image.sections if s['name'] == '.rela.dyn')
        changed = bytearray(self.data)
        import struct
        for off in range(rel['offset'], rel['offset'] + rel['size'], 24):
            if struct.unpack_from('<Q', changed, off)[0] == 0x56bdef0:
                changed[off + 8] ^= 1
                break
        else:
            self.fail('target relocation not found')
        with self.assertRaisesRegex(ValueError, 'relocation mismatch'):
            subject.capture_context(subject.Image(changed, verify_digest=False))

    def test_compare_relocation_corruption_rejected(self):
        off = int(self.record['tree_key_comparison']['relocation_file_offset'], 16)
        changed = bytearray(self.data)
        changed[off + 8] ^= 1
        with self.assertRaisesRegex(ValueError, 'unexpected compare relocation'):
            subject.compare_slot(subject.Image(changed, verify_digest=False))

    def test_invalid_address_and_nobits_rejected(self):
        with self.assertRaises(ValueError):
            self.image.read(1 << 63, 1)
        with self.assertRaises(ValueError):
            self.image.read(0x221aa80, 0)
        bss = next(s for s in self.image.sections if s['name'] == '.bss' and s['type'] == 8)
        with self.assertRaises(ValueError):
            self.image.read(bss['address'], 1)


if __name__ == '__main__':
    unittest.main()
