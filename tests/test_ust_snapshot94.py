import contextlib
import hashlib
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import ust_snapshot94 as m
from elf_index import sections


class UstSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(m.BINARY.read_bytes())
        cls.secs = sections(cls.data)
        cls.records, cls.bodies, cls.markers, cls.variants = m.analyze(cls.data)

    @contextlib.contextmanager
    def changed(self, address, replacement):
        off = m.va_offset(self.secs, address, len(replacement))
        original = self.data[off:off + len(replacement)]
        self.data[off:off + len(replacement)] = replacement
        try:
            yield
        finally:
            self.data[off:off + len(original)] = original

    def test_authenticated_identity_and_selected_extents(self):
        self.assertEqual(self.records['target']['sha256'], m.DIGEST)
        self.assertEqual(len(self.records['functions']), 22)
        self.assertEqual(len(self.bodies), 22)
        self.assertEqual(len(self.records['fields']), 9)
        self.assertEqual(len(self.records['variants']), 5)
        for body, function in zip(self.bodies, self.records['functions']):
            self.assertEqual(hashlib.sha256(bytes.fromhex(body['bytes'])).hexdigest(), function['sha256'])

    def test_wrong_digest_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            m.checked_digest(b'not the target')

    def test_rehashed_modified_instruction_is_refused(self):
        address = 0x275cf75
        off = m.va_offset(self.secs, address, 1)
        with self.changed(address, bytes((self.data[off] ^ 1,))):
            with mock.patch.object(m, 'DIGEST', hashlib.sha256(self.data).hexdigest()):
                with self.assertRaisesRegex(ValueError, 'body changed'):
                    m.analyze(self.data)

    def test_file_backed_mapping_rejects_nobits_and_invalid_ranges(self):
        bss = next(s for s in self.secs if s['name'] == '.bss')
        for address, size in ((bss['address'], 1), (0xffffffffffffffff, 8), (0, 0), (-1, 1)):
            with self.subTest(address=address, size=size), self.assertRaises(ValueError):
                m.va_offset(self.secs, address, size)
        with self.assertRaisesRegex(ValueError, 'exceeds the input'):
            m.va_bytes(self.data[:100], self.secs, 0x20296f0, 1)

    def test_call_and_branch_opcodes_reject_corruption(self):
        self.assertEqual(m.relative_target(self.data, self.secs, 0x2029740), 0x256dd10)
        self.assertEqual(m.branch(self.data, self.secs, 0x275d21d)['target'], '0x275d23f')
        with self.changed(0x2029740, b'\x90'), self.assertRaises(ValueError):
            m.relative_target(self.data, self.secs, 0x2029740)
        with self.changed(0x275d21d, b'\x90'), self.assertRaises(ValueError):
            m.branch(self.data, self.secs, 0x275d21d)

    def test_context_and_writer_call_order(self):
        self.assertEqual([v['name'] for v in self.records['context_names']], ['locus', 'ust'])
        calls = {v['role']: v['target'] for v in self.records['calls']}
        self.assertEqual([calls[x] for x in ('collect pairs', 'sort pairs', 'write sequence')],
                         ['0x256dd10', '0x1fe87b0', '0x1e4a430'])
        self.assertEqual(self.records['context_tag_four']['target'], '0x173a6fc')
        branches = {v['role']: v['target'] for v in self.records['branches']}
        self.assertEqual(branches['initial default helper failure'], '0x275d35f')

    def test_field_order_offsets_and_guard_targets(self):
        fields = self.records['fields']
        self.assertEqual([v['name']['name'] for v in fields], ['ln', 'R', 'C', 'P', 't', 'no', 'f', 'r', 'a'])
        self.assertEqual([v['value_offset'] for v in fields],
                         ['0x0', '0x8', '0x10', '0x18', '0x30', '0x20', '0x3d', '0x28', '0x3c'])
        self.assertEqual(fields[4]['skip_branch']['target'], '0x275d123')
        self.assertEqual(fields[8]['skip_branch']['target'], '0x275d23f')

    def test_field_offset_is_read_from_the_instruction(self):
        self.assertEqual(m.field_displacement(self.data, self.secs, 0x275ce7c, '4c8b6e', True), 8)
        with self.changed(0x275ce7f, b'\x09'):
            self.assertEqual(m.field_displacement(self.data, self.secs, 0x275ce7c, '4c8b6e', True), 9)
            with mock.patch.object(m, 'DIGEST', hashlib.sha256(self.data).hexdigest()):
                with self.assertRaisesRegex(ValueError, 'body changed'):
                    m.analyze(self.data)

    def test_name_literal_corruption_is_detected(self):
        self.assertEqual(m.read_name(self.data, self.secs, 0x275cf7e)['name'], 'ln')
        with self.changed(0x3ef169, b'X'):
            self.assertNotEqual(m.read_name(self.data, self.secs, 0x275cf7e)['name'], 'ln')
            with mock.patch.object(m, 'DIGEST', hashlib.sha256(self.data).hexdigest()):
                with self.assertRaisesRegex(ValueError, 'field name or value call changed'):
                    m.analyze(self.data)

    def test_presence_empty_full_and_each_individual(self):
        self.assertEqual(m.presence({}), [])
        names = ['ln', 'R', 'C', 'P', 't', 'no', 'f', 'r', 'a']
        for name in names:
            key = 't_diff' if name == 't' else name
            self.assertEqual(m.presence({key: 1}), [name])
        self.assertEqual(m.presence({('t_diff' if n == 't' else n): 1 for n in names}), names)

    def test_all_presence_combinations(self):
        names = ['ln', 'R', 'C', 'P', 't', 'no', 'f', 'r', 'a']
        for mask in range(1 << len(names)):
            row = {('t_diff' if name == 't' else name): (mask >> i) & 1 for i, name in enumerate(names)}
            expected = [name for i, name in enumerate(names) if mask & (1 << i)]
            self.assertEqual(m.presence(row), expected)
            self.assertEqual(len(expected), mask.bit_count())

    def test_invalid_boolean_or_variant_is_refused_by_model(self):
        for row in ({'f': 2}, {'f': 255}, {'a': 5}, {'a': 255}):
            with self.subTest(row=row), self.assertRaises(ValueError):
                m.presence(row)

    def test_variant_table_and_out_of_range_target_control(self):
        self.assertEqual([v['label'] for v in self.variants], ['e', 'i', 'd', 'u', 'p'])
        with self.changed(0x3f5a20, b'\0\0\0\0'), self.assertRaises(ValueError):
            m.variant_table(self.data, self.secs)
        with self.changed(0x19583a2, b'\x06'), self.assertRaises(ValueError):
            m.variant_table(self.data, self.secs)

    def test_variant_label_corruption_is_detected(self):
        with self.changed(0x3f6767, b'X'), self.assertRaises(ValueError):
            m.variant_table(self.data, self.secs)

    def test_small_key_order_and_boundary(self):
        bound = self.records['small_sort_exclusive_upper_bound']
        self.assertEqual(bound, 21)
        for count in (0, 1, 2, 19, 20):
            keys = [bytes((i,)) + bytes(19) for i in range(count)][::-1]
            self.assertEqual(m.insertion_order(keys, bound), sorted(keys))
        with self.assertRaises(ValueError):
            m.insertion_order([bytes(20)] * 21, bound)
        with self.assertRaises(ValueError):
            m.insertion_order([bytes(19)], bound)

    def test_small_key_order_nontrivial_permutations(self):
        keys = [bytes.fromhex(s) for s in (
            'ff00000000000000000000000000000000000000',
            '00000000000000000000000000000000000000ff',
            '0080000000000000000000000000000000000000',
            '0000000000000000000000000000000000000000')]
        for shift in range(len(keys)):
            rotated = keys[shift:] + keys[:shift]
            self.assertEqual(m.insertion_order(rotated, 21), sorted(keys))

    def test_sort_branch_boundaries(self):
        small = self.records['small_sort_exclusive_upper_bound']
        medium = self.records['medium_sort_inclusive_upper_bound']
        self.assertEqual((small, medium), (21, 2000))
        self.assertEqual([m.sort_path(n, small, medium) for n in (0, 1, 2, 20, 21, 2000, 2001)],
                         ['return before comparison', 'return before comparison',
                          'local comparison loop', 'local comparison loop',
                          'allocation then medium helper', 'allocation then medium helper',
                          'allocation then large helper'])
        for invalid in (-1, 0x1000000000000000, 0x10000000000000000):
            with self.assertRaises(ValueError):
                m.sort_path(invalid, small, medium)

    def test_modeled_row_examples(self):
        encode = lambda row, mode: m.model_row(row, mode, self.markers, self.variants).hex()
        self.assertEqual(encode({}, 1), '80')
        self.assertEqual(encode({}, 0), '90')
        self.assertEqual(encode({'ln': 1}, 1), '81a26c6e01')
        self.assertEqual(encode({'ln': 1}, 0), '9101')
        self.assertEqual(encode({'C': -1, 'f': 1, 'a': 2}, 1), '83a143ffa166c3a161a164')
        self.assertEqual(encode({'C': -32, 'ln': 127}, 1), '82a26c6e7fa143e0')

    def test_model_refuses_values_outside_qualified_sample_domain(self):
        for row, mode in (({'ln': 128}, 1), ({'C': -33}, 1), ({'C': 1}, 1),
                          ({'t_diff': True}, 1), ({}, 2)):
            with self.subTest(row=row, mode=mode), self.assertRaises(ValueError):
                m.model_row(row, mode, self.markers, self.variants)

    def test_modeled_container_empty_and_one_entry(self):
        text = self.records['shared_key_text']
        args = (1, self.markers, self.variants, text['alphabet'].encode(), text['prefix'].encode(), 21)
        self.assertEqual(m.model_container([], *args).hex(), '90')
        key = bytes(19) + b'\x01'
        self.assertEqual(m.model_container([(key, {})], *args),
                         bytes.fromhex('9192d92a') + b'0x' + b'0' * 38 + b'01' + b'\x80')

    def test_modeled_container_sorts_distinct_keys(self):
        text = self.records['shared_key_text']
        args = (1, self.markers, self.variants, text['alphabet'].encode(), text['prefix'].encode(), 21)
        first, last = bytes(20), bytes((255,)) * 20
        left = m.model_container([(last, {'ln': 1}), (first, {})], *args)
        right = m.model_container([(first, {}), (last, {'ln': 1})], *args)
        self.assertEqual(left, right)
        self.assertTrue(left.startswith(bytes.fromhex('9292d92a3078') + b'0' * 40))

    def test_modeled_container_rejects_unqualified_inputs(self):
        text = self.records['shared_key_text']
        args = (1, self.markers, self.variants, text['alphabet'].encode(), text['prefix'].encode(), 21)
        for items in ([(bytes(20), {})] * 2, [(bytes(19), {})], [(bytes((i,)) + bytes(19), {}) for i in range(16)]):
            with self.subTest(count=len(items)), self.assertRaises(ValueError):
                m.model_container(items, *args)

    def test_classifier_all_single_bytes_and_known_two_byte_names(self):
        left, right = self.records['reader_classifiers']
        expected = {b'ln': 0, b'R': 1, b'C': 2, b'P': 3, b't': 4,
                    b'no': 5, b'f': 6, b'r': 7, b'a': 8}
        for byte in range(256):
            key = bytes((byte,))
            self.assertEqual(m.classify(key, left), expected.get(key, 9))
            self.assertEqual(m.classify(key, right), expected.get(key, 9))
        for key in (b'ln', b'no', b'', b'LN', b'lnx', b'no\0'):
            self.assertEqual(m.classify(key, left), expected.get(key, 9))
            self.assertEqual(m.classify(key, right), expected.get(key, 9))

    def test_classifier_table_corruption_is_refused(self):
        with self.changed(0x3ecc48, b'\0\0\0\0'):
            with self.assertRaises(ValueError):
                m.classifier_table(self.data, self.secs, 0x26bf820, self.records['fields'])

    def test_reader_dispatch_and_duplicate_names(self):
        names = ['ln', 'R', 'C', 'P', 't', 'no', 'f', 'r', 'a', 'unknown']
        for kind in ('compact', 'json_shaped'):
            cases = self.records['reader_dispatch'][kind]['entries']
            self.assertEqual([v['name'] for v in cases], names)
            self.assertTrue(all('duplicate_branch' in v for v in cases[:9]))
            self.assertNotIn('duplicate_branch', cases[9])

    def test_reader_dispatch_corruption_is_refused(self):
        with self.changed(0x35ccb8, b'\0\0\0\0'):
            with self.assertRaises(ValueError):
                m.reader_dispatch(self.data, self.secs, 0x1958123,
                                  (9, 9, 9, 9, 5, 9, 4, 9, 8),
                                  (0x1956bf0, 0x1958628), self.records['fields'])

    def test_duplicate_key_paths_and_shared_insertion_helper(self):
        calls = {v['role']: v['target'] for v in self.records['calls']}
        self.assertEqual(calls['compact insert entry'], '0x27c8cf0')
        self.assertEqual(calls['pair-sequence insert entry'], '0x27c8cf0')
        self.assertEqual(calls['JSON insert entry'], '0x27c8cf0')
        branches = {v['role']: v['target'] for v in self.records['branches']}
        self.assertEqual(branches['insertion existing key matches'], '0x27c8e01')
        self.assertEqual(branches['compact new key continues'], '0x2635250')
        self.assertEqual(branches['pair-sequence new key continues'], '0x2661b30')
        self.assertEqual(branches['JSON new key continues'], '0x259d720')
        messages = self.records['duplicate_key_messages']
        self.assertEqual([messages[k]['message'] for k in ('compact', 'compact_pairs', 'json_shaped')],
                         ['duplicate key', 'duplicate key', 'duplicate key'])

    def test_duplicate_diagnostic_corruption_is_refused(self):
        with self.changed(0x263553d, b'X'):
            with self.assertRaisesRegex(ValueError, 'diagnostic message changed'):
                m.duplicate_key_message(self.data, self.secs, 0x263552d, 0x263553b)
        with self.changed(0x259d8ac, b'\x90'):
            with self.assertRaisesRegex(ValueError, 'diagnostic store changed'):
                m.duplicate_key_message(self.data, self.secs, 0x259d8a2, 0x259d8b0)

    def test_pair_sequence_calls_and_length_boundaries(self):
        calls = {v['role']: v['target'] for v in self.records['calls']}
        self.assertEqual(calls['collection to pair-sequence loop'], '0x2661ac0')
        self.assertEqual(calls['pair-sequence to pair reader'], '0x18e0050')
        self.assertEqual(calls['pair reader key decoder'], '0x190f5b0')
        self.assertEqual(calls['pair reader value decoder'], '0x1956bf0')
        self.assertEqual(self.records['pair_required_length'], 2)
        branches = {v['role']: v['target'] for v in self.records['branches']}
        for role, target in (('empty pair', '0x18e0bf9'), ('one-item pair', '0x18e0c7e'),
                             ('pair count not two', '0x18e0b79')):
            self.assertEqual(branches[role], target)
        routes = [m.pair_length_route(n, 2) for n in (0, 1, 2, 3, 0xffffffff)]
        self.assertEqual(routes, ['missing first element', 'missing second element after key',
                                  'pair after key and value', 'extra-element result after key and value',
                                  'extra-element result after key and value'])
        for bad in (-1, 0x100000000):
            with self.assertRaises(ValueError):
                m.pair_length_route(bad, 2)

    def test_shared_relocations_and_key_shape(self):
        slots = {x['slot']: x for x in self.records['relocations']}
        self.assertEqual(slots['0x576e488']['symbol'], 'memcmp')
        self.assertEqual(self.records['key_formatter'], {'capacity': 42, 'input_bytes': 20, 'mode': 0})
        self.assertEqual(self.records['entry_key_type_label'], 'User')
        calls = {x['role']: x['target'] for x in self.records['calls']}
        self.assertEqual(calls['user-key generic decoder'], '0x190f5b0')
        branches = {x['role']: x['target'] for x in self.records['branches']}
        self.assertEqual(branches['user-key takes ordinary path'], '0x16990b2')


if __name__ == '__main__':
    unittest.main()
