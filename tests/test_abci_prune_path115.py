"""Static #115 path-selection evidence and corruption controls; no execution."""
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import abci_prune_path115 as subject


class PrunePathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        subject.authenticate(cls.data)
        cls.secs, cls.table = subject.unwind_index(cls.data)
        _, cls.fdes = subject.eh_frame_records(cls.data, cls.secs)
        cls.functions = subject.selected_fdes(cls.data, cls.secs, cls.table, cls.fdes)
        cls.windows = subject.selected_windows(cls.data, cls.secs)
        cls.edges = subject.selected_edges(cls.data, cls.secs)
        cls.fields, cls.values = subject.selected_fields(cls.data, cls.secs)
        cls.relocs = subject.selected_relocations(cls.data, cls.secs)

    def test_target_hash_and_corruption(self):
        self.assertEqual(subject.authenticate(self.data), subject.TARGET_SHA256)
        corrupted = bytearray(self.data)
        corrupted[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.authenticate(corrupted)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.authenticate(self.data, '0' * 64)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.verify_historical(b'not the historical capture')

    def test_bad_input_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            bad = base / 'bad-input'
            out = base / 'output'
            bad.write_bytes(b'not an authenticated ELF')
            with mock.patch.object(subject, 'TARGET', bad):
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    subject.main(['--out', str(out)])
            self.assertFalse(out.exists())


    def test_file_backing_and_ambiguous_mappings(self):
        sec = {'name': '.text', 'type': 1, 'flags': 4, 'address': 0x1000,
               'offset': 0, 'size': 4}
        self.assertEqual(subject.file_offset(b'abcd', [sec], 0x1001, 2, True), 1)
        cases = [([dict(sec, type=8)], 0x1000, 1),
                 ([sec, dict(sec, name='.other')], 0x1000, 1),
                 ([sec], 0x0fff, 1), ([sec], 0x1003, 2),
                 ([sec], 0x1000, 0), ([dict(sec, flags=2)], 0x1000, 1)]
        for secs, va, size in cases:
            with self.subTest(sections=secs, va=va, size=size):
                with self.assertRaises(ValueError):
                    subject.file_offset(b'abcd', secs, va, size, True)
        with self.assertRaises(ValueError):
            subject.named_section([sec, dict(sec)], '.text')

    def test_real_fdes_match_index_and_complete_body_hash(self):
        self.assertEqual(len(self.functions), 12)
        self.assertEqual(sum(row['size'] for row in self.functions), 9601)
        for row in self.functions:
            raw = bytes.fromhex(row['body_hex'])
            self.assertEqual(len(raw), row['size'])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row['sha256'])
        self.assertEqual(len({row['fde_va'] for row in self.functions}), len(self.functions))

    def test_fde_bad_extent_hash_index_and_overlap(self):
        data = b'\x90\xc3\xcc\xcc'
        sec = {'name': '.text', 'type': 1, 'flags': 4, 'address': 0x1000,
               'offset': 0, 'size': len(data)}
        fde = {'start': 0x1000, 'end': 0x1002, 'fde': 0x2000,
               'cie': 0x2100, 'lsda': None}
        header = {'start': 0x1000, 'fde': 0x2000, 'index': 1}
        spec = [('sample', 0x1000, 0x1002, hashlib.sha256(data[:2]).hexdigest())]
        self.assertEqual(len(subject.selected_fdes(data, [sec], [header], [fde], spec)), 1)
        with self.assertRaises(ValueError):
            subject.selected_fdes(data, [sec], [dict(header, fde=0x2001)], [fde], spec)
        with self.assertRaises(ValueError):
            subject.selected_fdes(data, [sec], [header], [dict(fde, end=0x1003)], spec)
        with self.assertRaises(ValueError):
            subject.selected_fdes(data, [sec], [header], [fde], [('sample', 0x1000, 0x1002, '0'*64)])
        overlapping = dict(fde, start=0x1001, end=0x1003, fde=0x2004)
        with self.assertRaises(ValueError):
            subject.selected_fdes(data, [sec], [header], [fde, overlapping], spec)

    def test_every_pinned_window_detects_corruption(self):
        original = subject.read_va
        for spec in subject.WINDOWS:
            label, _, start, _ = spec
            def damaged(data, secs, va, size, executable=False):
                raw = original(data, secs, va, size, executable)
                if va == start:
                    return bytes([raw[0] ^ 1]) + raw[1:]
                return raw
            with self.subTest(window=label), mock.patch.object(subject, 'read_va', side_effect=damaged):
                with self.assertRaises(ValueError):
                    subject.selected_windows(self.data, self.secs, [spec])

    def test_key_parser_opcode_and_pool_corruption(self):
        original = subject.read_va
        target = next(x for x in subject.WINDOWS if x[0] == 'parse_entire')
        def damaged_parser(data, secs, va, size, executable=False):
            raw = original(data, secs, va, size, executable)
            if va == target[2]:
                altered = bytearray(raw)
                altered[0x156864f - va] ^= 1
                return bytes(altered)
            return raw
        with mock.patch.object(subject, 'read_va', side_effect=damaged_parser):
            with self.assertRaisesRegex(ValueError, 'selected bytes changed'):
                subject.selected_windows(self.data, self.secs, [target])
        heap = next(x for x in subject.WINDOWS if x[0] == 'heap_fallback_entire')
        def damaged_heap_comparison(data, secs, va, size, executable=False):
            raw = original(data, secs, va, size, executable)
            if va == heap[2]:
                altered = bytearray(raw)
                altered[0x15506a4 - va] ^= 1
                return bytes(altered)
            return raw
        with mock.patch.object(subject, 'read_va', side_effect=damaged_heap_comparison):
            with self.assertRaisesRegex(ValueError, 'selected bytes changed'):
                subject.selected_windows(self.data, self.secs, [heap])
        def damaged_pool(data, secs, va, size, executable=False):
            raw = original(data, secs, va, size, executable)
            return bytes([raw[0] ^ 1]) + raw[1:] if va == 0x449b0f else raw
        with mock.patch.object(subject, 'read_va', side_effect=damaged_pool):
            with self.assertRaisesRegex(ValueError, 'data changed'):
                subject.selected_pools(self.data, self.secs)


    def test_edge_targets_and_bad_displacement(self):
        edges = {row['label']: row for row in self.edges}
        self.assertEqual(edges['classify_first']['target_va'], '0x150bad0')
        self.assertEqual(edges['parse_later']['target_va'], '0x1568570')
        self.assertEqual(edges['vector_format_loop']['target_va'], '0x1532490')
        self.assertEqual(edges['integer_format_callback']['target_va'], '0x64e0a98')
        self.assertEqual(edges['prefix_format_descriptor']['target_va'], '0x449b0f')
        spec = next(x for x in subject.EDGES if x[0] == 'parse_later')
        original = subject.read_va
        def damaged(data, secs, va, size, executable=False):
            raw = original(data, secs, va, size, executable)
            if va == spec[2] and size == 5:
                return raw[:-1] + bytes([raw[-1] ^ 1])
            return raw
        with mock.patch.object(subject, 'read_va', side_effect=damaged):
            with self.assertRaisesRegex(ValueError, 'target'):
                subject.selected_edges(self.data, self.secs, [spec])
        fake = {'name': '.text', 'type': 1, 'flags': 4, 'address': 0x1000, 'offset': 0, 'size': 5}
        with self.assertRaises(ValueError):
            subject.decode_edge(b'\x90\x00\x00\x00\x00', [fake], 0x1000, 'call')

    def test_relocation_wrong_type_addend_duplicate_and_missing(self):
        slot = 0x3000
        expected = [('one', slot, 8, 0, 0x2200)]
        def fixture(entries):
            raw = b''.join(struct.pack('<QQq', *row) for row in entries) + bytes(8)
            secs = [{'name': '.rela.dyn', 'type': 4, 'flags': 2, 'address': 0x1000,
                     'offset': 0, 'size': 24 * len(entries)},
                    {'name': '.got', 'type': 1, 'flags': 2, 'address': slot,
                     'offset': 24 * len(entries), 'size': 8}]
            return raw, secs
        data, secs = fixture([(slot, 8, 0x2200)])
        self.assertEqual(subject.selected_relocations(data, secs, expected)[0]['addend'], '0x2200')
        for entries in ([], [(slot, 7, 0x2200)], [(slot, 8, 0x2201)],
                        [(slot, 8, 0x2200), (slot, 8, 0x2200)]):
            with self.subTest(entries=entries):
                data, secs = fixture(entries)
                with self.assertRaises(ValueError):
                    subject.selected_relocations(data, secs, expected)

    def test_location_and_imports(self):
        result = subject.location_record(self.data, self.secs, self.relocs)
        self.assertEqual((result['path'], result['line'], result['column']),
                         ('l1/src/abci/state.rs', 123, 37))
        self.assertEqual(subject.dynamic_symbol(self.data, self.secs, 11), 'bcmp')
        self.assertEqual(subject.dynamic_symbol(self.data, self.secs, 7), 'memcpy')
        changed = [dict(row) for row in self.relocs]
        next(row for row in changed if row['label'] == 'state_location_path')['addend'] = '0x0'
        with self.assertRaises(ValueError):
            subject.location_record(self.data, self.secs, changed)
        with self.assertRaises(ValueError):
            subject.dynamic_symbol(self.data, self.secs, 1 << 30)

    def test_exception_rows_bounds_and_truncation(self):
        data = bytes.fromhex('ffff010400010000')
        sec = {'name': '.gcc_except_table', 'type': 1, 'flags': 2,
               'address': 0x1000, 'offset': 0, 'size': len(data)}
        fde = {'start': 0x2000, 'end': 0x2010, 'lsda': 0x1000}
        self.assertEqual(subject.lsda_rows(data, [sec], fde)[0]['start_va'], '0x2000')
        with self.assertRaises(ValueError):
            subject.lsda_rows(data[:-1], [dict(sec, size=len(data)-1)], fde)
        altered = bytearray(data)
        altered[5] = 0x20
        with self.assertRaises(ValueError):
            subject.lsda_rows(altered, [sec], fde)
        altered = bytearray(data)
        altered[2] = 3
        with self.assertRaises(ValueError):
            subject.lsda_rows(altered, [sec], fde)
        self.assertEqual(len(subject.collect_exception_rows(self.data, self.secs, self.fdes)), 49)

    def test_selected_call_to_unwind_links(self):
        rows = subject.collect_exception_rows(self.data, self.secs, self.fdes)
        joined = subject.join_unwind_calls(self.edges, rows, self.functions)
        by_name = {row['call']: row for row in joined}
        self.assertEqual(by_name['metadata_stat']['landing_va'], '0x150bcde')
        self.assertEqual(by_name['name_decode']['landing_va'], '0x150bcde')
        self.assertEqual(by_name['vector_format_loop']['landing_va'], '0x1533286')
        self.assertEqual(by_name['prefix_compare']['status'], 'no-lsda')
        duplicated = rows + [r for r in rows if r['function'] == 'metadata_classifier']
        with self.assertRaises(ValueError):
            subject.join_unwind_calls(self.edges, duplicated, self.functions)


    def test_field_relationships_and_independent_boundary(self):
        v = self.values
        self.assertEqual((v['tree32_capacity'], v['tree24_capacity']), (11, 11))
        self.assertEqual((v['tree32_length_offset'], v['tree24_length_offset']), (0x16a, 0x112))
        self.assertEqual((v['tree32_leaf_bytes'], v['tree32_internal_bytes']), (0x170, 0x1d0))
        self.assertEqual((v['tree24_leaf_bytes'], v['tree24_internal_bytes']), (0x118, 0x178))
        self.assertEqual((v['cursor32_remaining_offset'], v['cursor24_remaining_offset']), (0x40, 0x40))
        self.assertEqual((v['numeric_radix'], v['numeric_checked_digit_cutoff']), (10, 17))
        self.assertEqual(v['numeric_sort_cutoff'], 21)
        self.assertEqual(v['sink_output_stride'], 24)
        self.assertEqual(v['sink_stop_sentinel'], 1 << 63)
        bound = v['path_input_byte_bound']
        self.assertEqual(bound % 8, 0)
        self.assertLessEqual(3 * bound, (1 << 63) - 1)
        self.assertGreater(3 * (bound + 8), (1 << 63) - 1)

    def test_type_mode_selected_branches(self):
        mask, directory, failure = (self.values['metadata_mode_mask'],
                                    self.values['metadata_directory_mode'],
                                    self.values['metadata_error_tag'])
        for mode in range(1 << 16):
            self.assertEqual(subject.metadata_flag(failure, mode, failure, mask, directory), 0)
            self.assertEqual(subject.metadata_flag(0, mode, failure, mask, directory), int((mode >> 12) == 4))
        self.assertFalse((0xa000 & mask) == directory)
        self.assertTrue((0x4fff & mask) == directory)

    def test_numeric_parser_boundaries_and_affixes(self):
        parse = subject.parse_numeric_component
        prefix, suffix = b'base/', b'.x'
        examples = {b'0': 0, b'+0': 0, b'0007': 7, b'+0007': 7,
                    b'18446744073709551615': (1 << 64) - 1,
                    b'00000000000000000000000000000007': 7,
                    b'': None, b'+': None, b'-1': None, b'1x': None,
                    b'18446744073709551616': None, b'++1': None}
        for middle, expected in examples.items():
            with self.subTest(middle=middle):
                self.assertEqual(parse(prefix + middle + suffix, prefix, suffix), expected)
        self.assertIsNone(parse(b'bad/7.x', prefix, suffix))
        self.assertIsNone(parse(b'base/7.y', prefix, suffix))
        self.assertIsNone(parse(b'abc', b'ab', b'bc'))
        self.assertEqual(parse(b'7', b'', b''), 7)
        with self.assertRaises(ValueError):
            parse(b'7', b'', b'', checked_cutoff=16)

    def test_numeric_parser_exhaustive_one_and_two_bytes(self):
        def oracle(raw):
            if raw.startswith(b'+'):
                raw = raw[1:]
            if not raw or any(c < 48 or c > 57 for c in raw):
                return None
            return int(raw)
        parse = subject.parse_numeric_component
        for length in (1, 2):
            for digits in itertools.product(range(256), repeat=length):
                raw = bytes(digits)
                self.assertEqual(parse(raw, b'', b''), oracle(raw), raw.hex())

    def test_adjacent_duplicates_are_stage_specific(self):
        rows = [(b'x', 0, 'first'), (b'x', 0, 'later'), (b'x', 1, 'different flag'),
                (b'y', 0, 'middle'), (b'x', 0, 'nonadjacent')]
        a = subject.deduplicate_adjacent(rows, compare_flag=True)
        self.assertEqual([r[2] for r in a], ['later', 'different flag', 'middle', 'nonadjacent'])
        b = subject.deduplicate_adjacent(rows, compare_flag=False)
        self.assertEqual([r[2] for r in b], ['different flag', 'middle', 'nonadjacent'])
        self.assertEqual(subject.deduplicate_adjacent([], True), [])

    def test_distinct_names_can_become_identical_number_arguments(self):
        names = [b'base/+01', b'base/1']
        rows = [(name, 0, i) for i, name in enumerate(names)]
        self.assertEqual(len(subject.deduplicate_adjacent(rows, compare_flag=False)), 2)
        numeric = [subject.parse_numeric_component(name, b'base/', b'') for name in names]
        self.assertEqual(numeric, [1, 1])
        self.assertEqual(subject.sort_small(numeric), [1, 1])
        self.assertEqual([(b'base/', n, b'') for n in numeric],
                         [(b'base/', 1, b''), (b'base/', 1, b'')])

    def test_small_sort_against_reference_and_cutoff(self):
        cutoff = self.values['numeric_sort_cutoff']
        for length in range(2, 8):
            for xs in itertools.product(range(3), repeat=length):
                self.assertEqual(subject.sort_small(xs, cutoff), sorted(xs))
        self.assertEqual(subject.sort_small(list(range(19, -1, -1)), cutoff), list(range(20)))
        self.assertEqual(subject.sort_small([0xffffffffffffffff, 0, 1]), [0, 1, 0xffffffffffffffff])
        for invalid in ([-1, 0], [0, 1 << 64]):
            with self.assertRaises(ValueError):
                subject.sort_small(invalid, cutoff)
        for xs in ([], [1], list(range(21))):
            with self.assertRaises(ValueError):
                subject.sort_small(xs, cutoff)

    def test_large_sort_monotone_and_general_paths(self):
        for count in (2, 20, 21, 33, 64):
            ascending = list(range(count))
            route, value = subject.monotone_sort_route(ascending)
            self.assertEqual((route, value), ('ascending', ascending))
            route, value = subject.monotone_sort_route(list(reversed(ascending)))
            self.assertEqual((route, value), ('descending', ascending))
        self.assertEqual(subject.monotone_sort_route([3, 2, 2]), ('partition', None))
        self.assertEqual(subject.monotone_sort_route([1, 3, 2]), ('partition', None))
        self.assertEqual(subject.monotone_sort_route([1]), ('short', [1]))
        with self.assertRaises(ValueError):
            subject.monotone_sort_route([-1, 1])

    def test_heap_fallback_against_reference_and_binding(self):
        bindings = {row['label']: row for row in self.relocs}
        self.assertEqual(bindings['numeric_heap_fallback']['addend'], '0x1550630')
        bad_binding = [('heap', 0x64e10b8, 8, 0, 0x1550631)]
        with self.assertRaisesRegex(ValueError, 'relocation changed'):
            subject.selected_relocations(self.data, self.secs, bad_binding)
        for length in range(9):
            for values in itertools.product(range(3), repeat=length):
                self.assertEqual(subject.heap_fallback(values), sorted(values))
        for count in (21, 32, 33, 64, 257):
            values = [((i * 137) % 31) | ((i % 2) << 63) for i in range(count)]
            self.assertEqual(subject.heap_fallback(values), sorted(values))
            self.assertEqual(subject.heap_fallback(list(reversed(values))), sorted(values))
        for values in ([-1], [1 << 64], [True]):
            with self.assertRaises(ValueError):
                subject.heap_fallback(values)

    def test_sink_pop_and_sentinel_controls(self):
        stop = object()
        self.assertEqual(subject.sink_iteration([], stop), (None, []))
        self.assertEqual(subject.sink_iteration(['last'], stop), ('last', []))
        self.assertEqual(subject.sink_iteration(['a', 'b', 'last'], stop), ('last', ['a', 'b']))
        self.assertEqual(subject.sink_iteration(['a', stop, 'b', 'last'], stop), ('last', ['a']))
        self.assertEqual(subject.sink_iteration([stop], stop), (stop, []))

    def test_machine_readable_summary_has_no_unobserved_completion_claim(self):
        records = subject.collect(self.data)
        self.assertEqual(set(records), {'functions.tsv', 'windows.tsv', 'edges.tsv', 'fields.tsv',
                                        'relocations.tsv', 'pools.tsv', 'exceptions.tsv',
                                        'location.json', 'unwind-links.tsv', 'summary.json'})
        summary = json.loads(records['summary.json'])
        self.assertEqual(summary['binary_sha256'], subject.TARGET_SHA256)
        self.assertEqual(summary['counts']['new_fdes'], 12)
        self.assertEqual(summary['symbol_bindings']['comparison'], 'bcmp')
        self.assertIn('not a complete function census', summary['limitations'])


if __name__ == '__main__':
    unittest.main()
