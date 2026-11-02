import copy
from pathlib import Path
import unittest

from tools import twap_sequence_size94 as q
from tools.elf_index import sections


class TwapSequenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = q.TARGET.read_bytes()
        cls.secs = sections(cls.data)
        cls.evidence = q.collect(cls.data)
        cls.base = [('asset', 7), ('bool', 1), ('size', (1, 22, 33)),
                    ('bool', 1), ('uint', (4, 9)), ('bool', 1)]

    def test_target_and_boundaries(self):
        q.authenticate(self.data)
        self.assertEqual(len(self.evidence['functions']), 18)
        self.assertEqual(len(self.evidence['branches']), 81)
        self.assertEqual(len(self.evidence['edges']), 33)
        self.assertEqual(len(self.evidence['descriptors']), 36)
        self.assertEqual(len(self.evidence['positions']), 18)
        self.assertEqual(len(self.evidence['outer_anchors']), 3)
        self.assertEqual(sum(x['role'] == 'finish_count_overflow' for x in self.evidence['branches']), 3)
        self.assertEqual(len(self.evidence['raw_copy_differences']), 158)
        self.assertTrue(all(r['mask_kind'] for r in self.evidence['raw_copy_differences']))
        self.assertEqual({r['text'] for r in self.evidence['descriptors']}, set(q.NAMES))
        self.assertEqual(len({r['sha256'] for r in self.evidence['functions']}), 18)

    def test_bad_digest(self):
        with self.assertRaisesRegex(ValueError, 'digest'):
            q.authenticate(self.data, '0' * 64)

    def test_modified_instruction_rejected(self):
        bad = bytearray(self.data)
        offset, _ = q.resolver(bad, self.secs, 0x212eaf2, 1, True)
        bad[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'body digest'):
            q.collect(bad, verify=False)

    def test_bad_descriptor_bytes_rejected(self):
        bad = bytearray(self.data)
        offset, _ = q.resolver(bad, self.secs, 0x3d6b27, 1)
        bad[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'descriptor'):
            q.collect(bad, verify=False)

    def test_cursor_replay_and_mutation(self):
        rows = q.cursor_fixture(self.data, self.secs)
        self.assertEqual(len(rows), 1536)
        # The marker advances by a record even though it does not increment count.
        marker = q.replay_bool_cursor(self.data, self.secs, True, False, 0x16, 19)
        self.assertEqual((marker['status'], marker['advance'], marker['counter']), ('absent', 32, 19))
        bad = bytearray(self.data)
        offset, _ = q.resolver(bad, self.secs, 0x1eee54c, 1, True)
        bad[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'cursor instruction'):
            q.replay_bool_cursor(bad, self.secs, True, False, 0, 0)

    def test_copy_comparison_rejects_changed_unmasked_byte(self):
        comparisons, masks = q.compare_selected_windows(self.data, self.secs)
        self.assertEqual((len(comparisons), len(masks)), (8, 48))
        bad = bytearray(self.data)
        addr = q.READERS[1] + 0x212ea91 - q.READERS[0]
        offset, _ = q.resolver(bad, self.secs, addr, 1, True)
        bad[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'windows differ'):
            q.compare_selected_windows(bad, self.secs)

    def test_helper_copy_windows_and_integer_table_mutation(self):
        comparisons, masks = q.compare_helper_windows(self.data, self.secs)
        self.assertEqual((len(comparisons), len(masks)), (5, 21))
        dispatch = q.integer_copy_dispatch(self.data, self.secs)
        self.assertEqual(len(dispatch), 24)
        bad = bytearray(self.data)
        target = int(dispatch[8]['entry_va'], 16)
        offset, _ = q.resolver(bad, self.secs, target, 1)
        bad[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'copy table'):
            q.integer_copy_dispatch(bad, self.secs)

    def test_all_sequence_patterns(self):
        rows = q.pattern_fixture()
        self.assertEqual(len(rows), 729)
        self.assertEqual(sum(r['converter_called'] for r in rows), 4)
        self.assertTrue(all(r['status'] == 'ok' for r in rows if r['converter_called']))

    def test_inline_cursor_model(self):
        self.assertEqual(len(q.inline_fixture(self.data, self.secs)), 3072)
        for which in ('size', 'minutes'):
            row = q.replay_inline_cursor(self.data, self.secs, which, True, False, 0x16, 3)
            self.assertEqual(row, {'status': 'absent', 'advance': 32, 'counter': 3})

    def test_outer_name_corruption(self):
        self.assertEqual([x['name'] for x in self.evidence['outer_anchors']], ['TwapWireSerde'] * 3)
        bad = bytearray(self.data)
        addr = int(self.evidence['outer_anchors'][0]['name_va'], 16)
        offset, _ = q.resolver(bad, self.secs, addr, 1)
        bad[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'descriptor setup'):
            q.collect(bad, verify=False)

    def test_bad_numeric_table_rejected(self):
        bad = bytearray(self.data)
        offset, _ = q.resolver(bad, self.secs, 0x3c6d08, 1)
        bad[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'table'):
            q.collect(bad, verify=False)

    def test_file_backed_ranges_and_bad_opcodes(self):
        for addr, n in ((0, 1), (2**64 - 1, 2), (-1, 1), (0x212e4a0, 0)):
            with self.assertRaises(ValueError):
                q.resolver(self.data, self.secs, addr, n)
        bss = next(s for s in self.secs if s['name'] == '.bss' and s['type'] == 8)
        with self.assertRaises(ValueError):
            q.resolver(self.data, self.secs, bss['address'], 1)
        with self.assertRaises(ValueError):
            q.branch(self.data, self.secs, 0x212e4a0)
        with self.assertRaises(ValueError):
            q.direct_call(self.data, self.secs, 0x212e4a0)
        with self.assertRaises(ValueError):
            q.slot_call(self.data, self.secs, 0x212e4a0)

    def test_empty_and_prefixes(self):
        expected = ['missing:0', 'missing:1', 'missing:2', 'missing:4',
                    'missing:4', 'ok', 'ok']
        for n, status in enumerate(expected):
            with self.subTest(n=n):
                result = q.model_sequence(self.base[:n])
                self.assertEqual(result['status'], status)
                self.assertEqual(result['cursor'], n)
                self.assertEqual(result['counter'], n)
                self.assertEqual('convert:ok' in result['events'], status == 'ok')
        self.assertEqual(q.model_sequence(self.base, buffer_present=False)['status'], 'missing:0')

    def test_missing_marker_and_consumption(self):
        for i, expected in enumerate(('missing:0', 'missing:1', 'missing:2', 'ok', 'missing:4', 'ok')):
            seq = list(self.base)
            seq[i] = ('marker', 0)
            with self.subTest(i=i):
                result = q.model_sequence(seq)
                self.assertEqual(result['status'], expected)
                self.assertEqual(result['cursor'], 6 if expected == 'ok' else i + 1)
                self.assertEqual(result['counter'], 5 if expected == 'ok' else i)
        seq = self.base + [('marker', 0)]
        result = q.model_sequence(seq)
        self.assertEqual(result['status'], 'trailing')
        self.assertNotIn('convert:ok', result['events'])

    def test_boolean_payload_handling(self):
        for value in range(256):
            for i, name in ((1, 'isBuy'), (3, 'reduceOnly'), (5, 'randomize')):
                seq = list(self.base)
                seq[i] = ('bool', value)
                result = q.model_sequence(seq)
                if i == 1 and value == 2:
                    self.assertEqual(result['status'], 'missing:1')
                else:
                    self.assertEqual(result['status'], 'ok')
                    self.assertEqual(result['fields'][name], value if i == 1 else value & 1)

    def test_reader_error_precedes_converter(self):
        for i in range(6):
            seq = list(self.base)
            seq[i] = ('error', 0)
            result = q.model_sequence(seq)
            self.assertEqual(result['status'], 'reader_error:' + str(i))
            self.assertNotIn('convert:ok', result['events'])
        self.assertEqual(q.model_sequence(self.base, convert_ok=False)['status'], 'conversion_error')

    def test_integer_tag_width_and_sign(self):
        for tag in range(256):
            for raw in (0, 1, 127, 128, 255, 256, 32767, 32768,
                        2**31-1, 2**31, 2**63-1, 2**63, q.MASK):
                actual = q.decode_unsigned(tag, raw)
                if tag not in range(1, 9):
                    expected = ('type_error', None)
                else:
                    bits = [8, 16, 32, 64][(tag-1) % 4]
                    n = raw % 2**bits
                    expected = ('negative_error', None) if tag >= 5 and n >= 2**(bits-1) else ('ok', n)
                self.assertEqual(actual, expected)
        self.assertEqual([r['bits'] for r in self.evidence['integer_dispatch']], [8,16,32,64]*2)
        self.assertEqual([r['signed'] for r in self.evidence['integer_dispatch']], [False]*4 + [True]*4)

    def test_byte_replay_numeric_domain_and_mutation(self):
        for tag in (2, 6):
            for word in range(65536):
                self.assertEqual(q.replay_unsigned(self.data, self.secs, tag, word), q.decode_unsigned(tag, word))
        self.assertEqual(len(q.integer_fixture(self.data, self.secs)), 2650)
        bad = bytearray(self.data)
        offset, _ = q.resolver(bad, self.secs, 0x207fc1f, 1, True)
        bad[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction'):
            q.replay_unsigned(bad, self.secs, 2, 10)

    def test_size_sentinel_and_overflow_order(self):
        self.assertEqual(len(q.finish_fixture(self.data, self.secs)), 16)
        self.assertEqual(q.replay_finish(self.data, self.secs, q.MASK - 1, 1), ('remaining_constructor', q.MASK))
        self.assertEqual(q.replay_finish(self.data, self.secs, q.MASK, 1), ('counter_overflow', None))
        with self.assertRaises(ValueError):
            q.replay_finish(self.data, self.secs, 0, (q.MASK >> 5) + 1)
        bad_branch = bytearray(self.data)
        offset, _ = q.resolver(bad_branch, self.secs, 0x1eb4512, 1, True)
        bad_branch[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'finish branch'):
            q.replay_finish(bad_branch, self.secs, 0, 1)
        bad = bytearray(self.data)
        offset, _ = q.resolver(bad, self.secs, 0x1eb450e, 1, True)
        bad[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'cursor instruction'):
            q.replay_finish(bad, self.secs, 0, 1)
        extra = self.base + [('marker', 0)]
        self.assertEqual(q.model_sequence(extra, counter=q.MASK - 7)['status'], 'trailing')
        self.assertEqual(q.model_sequence(extra, counter=q.MASK - 6)['status'], 'finish_counter_overflow')
        seq = list(self.base)
        seq[2] = ('size', (2**63, 0, 0))
        self.assertEqual(q.model_sequence(seq)['status'], 'missing:2')
        for initial, expected, cursor in ((q.MASK, 'counter_overflow:0', 1),
                                          (q.MASK-2, 'counter_overflow:2', 3),
                                          (q.MASK-6, 'ok', 6)):
            actual = q.model_sequence(self.base, counter=initial)
            self.assertEqual(actual['status'], expected)
            self.assertEqual(actual['cursor'], cursor)

    def test_invalid_abstract_inputs(self):
        for tag, word in ((-1, 0), (256, 0), (1, -1), (1, 2**64), (True, 0)):
            with self.assertRaises(ValueError):
                q.decode_unsigned(tag, word)
        with self.assertRaises(ValueError):
            q.model_sequence(self.base, counter=-1)
        with self.assertRaises(ValueError):
            q.model_sequence(self.base, convert_ok=1)
        seq = copy.deepcopy(self.base)
        seq[2] = ('size', (1, 2))
        with self.assertRaises(ValueError):
            q.model_sequence(seq)

    def test_expected_final_branches(self):
        for reader in q.READERS:
            subset = {x['role']: x for x in self.evidence['branches'] if x['owner'] == hex(reader)}
            self.assertEqual(subset['size_present']['condition'], 5)
            self.assertEqual(subset['size_reader_absent']['condition'], 0)
            self.assertEqual(subset['finish_ok']['condition'], 4)
            self.assertEqual(int(subset['size_present']['target_va'], 16) - reader, 0xb2d)
        self.assertEqual(len(q.fixtures()), 182)


if __name__ == '__main__':
    unittest.main()
