import hashlib
import unittest

from tools import outcome_tracker_codec94 as codec


class OutcomeTrackerCodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = codec.BINARY.read_bytes()
        cls.elf = codec.Elf(cls.binary)
        cls.report = codec.build(cls.binary)
        cls.keys = [r['key'].encode('ascii') for r in cls.report['fields']]

    def changed(self, address, value):
        altered = bytearray(self.binary)
        altered[self.elf.offset(address)] = value
        return altered

    def test_writer_layout_and_parent(self):
        self.assertEqual([k.decode() for k in self.keys],
                         ['dga', 'nou', 'nqu', 'fs', 'l', 'ndo', 'mut',
                          'uoa', 'utd', 'tto', 'otq', 'ots', 'qts'])
        self.assertEqual([r['object_offset'] for r in self.report['fields']],
                         ['0x0', '0x130', '0x138', '0x140', '0x158', '0x148',
                          '0x150', '0x159', '0x40', '0x70', '0xa0', '0xd0', '0x100'])
        self.assertEqual(self.report['outer']['wrapper_key'], 'outr')
        self.assertEqual(self.report['outer']['named_count'], 13)
        self.assertEqual(self.report['outer']['positional_count'], 13)

    def test_reader_duplicate_dispatch(self):
        rows = self.report['reader_dispatch']
        self.assertEqual([r['key'] for r in rows[:-1]], [k.decode() for k in self.keys])
        self.assertIsNone(rows[-1]['key'])
        self.assertEqual(len({r['duplicate_target_va'] for r in rows[:-1]}), 13)
        self.assertEqual([r['key'] for r in self.report['missing_diagnostics']],
                         ['nou', 'nqu', 'utd', 'tto', 'ots'])

    def test_classifier_all_single_byte_substitutions(self):
        expected = {key: index for index, key in enumerate(self.keys)}
        cases = 0
        for key in self.keys:
            self.assertEqual(codec.run_classifier(self.elf, key), (9, expected[key]))
            for index, original in enumerate(key):
                for value in range(256):
                    if value == original:
                        continue
                    other = key[:index] + bytes([value]) + key[index + 1:]
                    self.assertEqual(codec.run_classifier(self.elf, other),
                                     (9, expected.get(other, 13)), other)
                    cases += 1
        self.assertEqual(cases, 9180)

    def test_length_and_case_controls(self):
        for sample in (b'', b'DGA', b'dga\0', b'ot', b'otx', b'zzzz', b'\xff'):
            self.assertEqual(codec.run_classifier(self.elf, sample), (9, 13))
        self.assertEqual(codec.run_classifier(self.elf, b'otq'), (9, 10))
        self.assertEqual(codec.run_classifier(self.elf, b'ots'), (9, 11))

    def test_error_branch_table(self):
        messagepack = self.report['messagepack_decisions']
        json_rows = self.report['json_decisions']
        self.assertEqual(len(messagepack), 18)
        self.assertEqual(len(json_rows), 13)
        self.assertEqual({int(r['field_index']) for r in messagepack}, set(range(13)))
        self.assertEqual({r['failure_va'] for r in json_rows}, {'0x26d0d8a'})
        self.assertEqual(len(self.report['duplicate_errors']), 13)

    def test_map_completion_defaults(self):
        defaults = self.report['map_defaults']
        self.assertEqual([r['key'] for r in defaults], ['fs', 'ndo', 'mut'])
        self.assertEqual([r['default_bits'] for r in defaults], ['0x0000000000000000'] * 3)
        self.assertEqual([r['presence_stack_offset'] for r in defaults],
                         ['0x380', '0x388', '0xe8'])
        bad = self.changed(0x17f2d7d, 0x90)
        with self.assertRaisesRegex(ValueError, 'body mismatch'):
            codec.build(bad, hashlib.sha256(bad).hexdigest())

    def test_collection_edges_and_small_sort(self):
        nested = self.report['nested_adapters']
        self.assertEqual([r['key'] for r in nested], ['utd', 'tto', 'otq', 'ots', 'qts'])
        self.assertEqual(nested[1]['emit_target_va'], nested[2]['emit_target_va'])
        sort = self.report['small_sort']
        self.assertEqual((sort['exclusive_limit'], sort['record_bytes']), (21, 16))
        for length in (0, 1, 2, 20):
            rows = [(i % 4, i) for i in range(length - 1, -1, -1)]
            self.assertEqual(codec.small_sort_model(rows, 21), sorted(rows, key=lambda r: r[0]))
        rows = [(2**64 - 1, 'a'), (0, 'b'), (2**64 - 1, 'c')]
        self.assertEqual(codec.small_sort_model(rows, 21), [rows[1], rows[0], rows[2]])
        with self.assertRaisesRegex(ValueError, 'outside small sort'):
            codec.small_sort_model([(0, i) for i in range(21)], 21)
        with self.assertRaisesRegex(ValueError, 'invalid sort'):
            codec.small_sort_model([(-1, 'bad')], 21)

    def test_rehashed_sort_corruption(self):
        bad = self.changed(0x1fec5a2, 0x72)
        with self.assertRaisesRegex(ValueError, 'body mismatch'):
            codec.build(bad, hashlib.sha256(bad).hexdigest())

    def test_digest_guard(self):
        bad = self.changed(0x26d074b, 0x90)
        with self.assertRaisesRegex(ValueError, 'digest'):
            codec.build(bad)

    def test_rehashed_instruction_corruption(self):
        bad = self.changed(0x26d074b, 0x90)
        with self.assertRaisesRegex(ValueError, 'body mismatch'):
            codec.build(bad, hashlib.sha256(bad).hexdigest())

    def test_rehashed_type_diagnostic_corruption(self):
        record = self.report['type_record']
        self.assertEqual(record['literal'], 'struct OutcomeTracker with 13 elements')
        self.assertEqual(record['element_count'], 13)
        bad = self.changed(int(record['literal_va'], 16), ord('X'))
        with self.assertRaisesRegex(ValueError, 'type diagnostic'):
            codec.build(bad, hashlib.sha256(bad).hexdigest())

    def test_rehashed_field_corruption(self):
        bad = self.changed(0x3ef861, ord('z'))
        with self.assertRaisesRegex(ValueError, 'reader and writer'):
            codec.build(bad, hashlib.sha256(bad).hexdigest())

    def test_reader_jump_table_outside_extent(self):
        bad = self.changed(0x2e44ef, 0x7f)
        with self.assertRaisesRegex(ValueError, 'reader table target'):
            codec.build(bad, hashlib.sha256(bad).hexdigest())

    def test_classifier_jump_table_outside_extent(self):
        bad = self.changed(0x29456b, 0x7f)
        with self.assertRaisesRegex(ValueError, 'classifier branch outside'):
            codec.build(bad, hashlib.sha256(bad).hexdigest())

    def test_file_backing_and_bounds(self):
        with self.assertRaisesRegex(ValueError, 'file backed'):
            self.elf.read(0xffffffffffffffff, 1)
        bss = next(s for s in self.elf.secs if s['name'] == '.bss' and s['type'] == 8 and s['size'])
        with self.assertRaisesRegex(ValueError, 'file backed'):
            self.elf.read(bss['address'], 1)
        with self.assertRaisesRegex(ValueError, 'bad address'):
            self.elf.read(-1, 1)


if __name__ == '__main__':
    unittest.main()
