"""Static controls for the node 94 reload-to-nonce-view packet."""
import itertools
import mmap
from pathlib import Path
import struct
import tempfile
import unittest

from tools import abci_reload_nonce_view94 as view


class BinaryEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stream = view.BINARY.open('rb')
        cls.data = mmap.mmap(cls.stream.fileno(), 0, access=mmap.ACCESS_COPY)
        view.verify_digest(cls.data)
        cls.image = view.Image(cls.data)
        cls.functions = view.fde_rows(cls.image)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.stream.close()

    def changed(self, offset, replacement, check):
        old = self.data[offset:offset + len(replacement)]
        try:
            self.data[offset:offset + len(replacement)] = replacement
            with self.assertRaises((ValueError, struct.error, UnicodeError)):
                check()
        finally:
            self.data[offset:offset + len(replacement)] = old

    def test_target_digest(self):
        view.verify_digest(self.data)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            view.verify_digest(self.data, '0' * 64)

    def test_wrong_target_fails_before_creating_output(self):
        with tempfile.TemporaryDirectory() as parent:
            dest = Path(parent) / 'result'
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                view.produce(b'not an ELF capture', dest)
            self.assertFalse(dest.exists())

    def test_selected_fdes_are_indexed_and_distinct(self):
        self.assertEqual(len(self.functions), 14)
        self.assertEqual(len({f['start'] for f in self.functions}), 14)
        self.assertEqual(sum(f['size'] for f in self.functions), 9375)
        self.assertTrue(all(f['end'] > f['start'] for f in self.functions))

    def test_body_mutation_fails_fde_check(self):
        _, off = self.image.location(0x4888e80, 1)
        self.changed(off, bytes([self.data[off] ^ 1]), lambda: view.fde_rows(self.image))

    def test_fde_range_mutation_rejected(self):
        f = next(r for r in self.functions if r['start'] == 0x489ea70)
        off = f['fde_offset'] + 12
        val = struct.unpack_from('<i', self.data, off)[0]
        self.changed(off, struct.pack('<i', val - 1), lambda: view.fde_rows(self.image))

    def test_windows_and_context_classification(self):
        rows = view.window_rows(self.image)
        self.assertEqual(len(rows), 41)
        self.assertEqual(sum(r['ownership'] == 'prior-context' for r in rows), 7)
        self.assertNotIn(0x4548cc0, {f['start'] for f in self.functions})
        self.assertNotIn(0x45271a0, {f['start'] for f in self.functions})

    def test_boundary_instruction_corruption_rejected(self):
        _, off = self.image.location(0x4549e5a, 1)
        self.changed(off, bytes([self.data[off] ^ 1]), lambda: view.window_rows(self.image))

    def test_branch_targets_and_conditions_are_pinned(self):
        rows = {r['role']: r for r in view.site_rows(self.image)}
        self.assertEqual(rows['skip_excluded']['target'], 0x4888ef0)
        self.assertEqual(rows['large_sort']['bytes'][:2], '73')
        self.assertEqual(rows['bad_root_next']['target'], 0x4889758)
        self.assertEqual(rows['coalesce_repeat']['target'], 0x4ada720)

    def test_bad_branch_opcode_rejected(self):
        _, off = self.image.location(0x4888fb9, 1)
        self.changed(off, b'\x90', lambda: view.site_rows(self.image))

    def test_in_range_branch_retarget_rejected(self):
        _, off = self.image.location(0x4888fb9, 6)
        changed = bytearray(self.data[off:off+6])
        changed[-1] ^= 1
        self.changed(off, bytes(changed), lambda: view.site_rows(self.image))

    def test_invalid_lea_and_retarget_are_rejected(self):
        _, off = self.image.location(0x3423988, 7)
        original = bytes(self.data[off:off+7])
        bad_opcode = bytearray(original)
        bad_opcode[1] ^= 1
        self.changed(off, bytes(bad_opcode), lambda: view.site_rows(self.image))
        bad_target = bytearray(original)
        bad_target[3] ^= 1
        self.changed(off, bytes(bad_target), lambda: view.site_rows(self.image))

    def test_operands_are_extracted_from_instructions(self):
        facts = {r['role']: r['value'] for r in view.fact_rows(self.image)}
        self.assertEqual(facts['tracker_offset'] + facts['lookup_table_offset'], 0x41e0)
        self.assertEqual(facts['address_bytes'], 20)
        self.assertEqual(facts['record_sort_threshold'], 21)
        self.assertEqual(facts['record_bytes'], 48)
        self.assertEqual(facts['node_capacity'], 11)
        self.assertEqual(facts['record_tree_leaf_bytes'], 0x1f0)
        self.assertEqual(facts['record_tree_internal_bytes'], 0x250)
        self.assertEqual(facts['large_sort_stack_limit'], 86)
        self.assertEqual(facts['large_sort_internal_threshold'], 65)
        self.assertEqual(facts['large_sort_buffer_cap'], 166666)

    def test_operand_mutation_rejected(self):
        _, off = self.image.location(0x488900a, 1)
        self.changed(off, b'\x51', lambda: view.fact_rows(self.image))

    def test_relocation_links_and_symbol(self):
        relocs = {r['role']: r for r in view.relocation_rows(self.image)}
        self.assertEqual(relocs['nonce_lookup_slot']['addend'], 0x3423840)
        self.assertEqual(relocs['large_sort_slot']['addend'], 0x4488d70)
        self.assertEqual(len(relocs), 5)
        self.assertEqual(relocs['default_initializer']['addend'], 0x3438e50)
        self.assertEqual(relocs['once_method_a']['addend'], 0x3432790)
        self.assertEqual(relocs['once_method_b']['addend'], 0x3431820)

    def test_relocation_addend_type_and_symbol_corruption(self):
        row = next(r for r in view.relocation_rows(self.image) if r['role'] == 'nonce_lookup_slot')
        off = row['offset']
        original = bytes(self.data[off:off+24])
        for index in (8, 12, 16):
            altered = bytearray(original)
            altered[index] ^= 1
            with self.subTest(byte=index):
                self.changed(off, bytes(altered), lambda: view.relocation_rows(self.image))

    def test_duplicate_relocation_is_rejected(self):
        section = self.image.named('.rela.dyn')
        row = next(r for r in view.relocation_rows(self.image) if r['role'] == 'nonce_lookup_slot')
        first = section['offset']
        self.assertNotEqual(first, row['offset'])
        self.changed(first, bytes(self.data[row['offset']:row['offset']+24]),
                     lambda: view.relocation_rows(self.image))

    def test_indirect_compare_slot_is_a_prior_work_boundary(self):
        rows = {r['role']: r for r in view.site_rows(self.image)}
        self.assertEqual(rows['exclude_compare']['target'], 0x576e488)
        self.assertEqual(rows['exclude_compare_next']['target'], 0x576e488)
        self.assertNotIn(0x576e488, {r['slot'] for r in view.relocation_rows(self.image)})

    def test_lazy_descriptor_and_initial_word(self):
        data = {r['role']: r for r in view.data_rows(self.image)}
        self.assertEqual(data['once_descriptor_header']['bytes'],
                         '000000000000000008000000000000000800000000000000')
        self.assertEqual(data['initial_once_word']['bytes'], '03000000')
        sites = {r['role']: r for r in view.site_rows(self.image)}
        self.assertEqual(sites['once_descriptor']['target'], 0x56eb448)
        self.assertEqual(sites['default_address']['target'], 0x5786170)
        self.assertEqual(sites['once_state_address']['target'], 0x5786188)

    def test_lazy_descriptor_mutation_rejected(self):
        _, off = self.image.location(0x56eb450, 1)
        self.changed(off, b'\x09', lambda: view.data_rows(self.image))

    def test_range_bounds_and_non_file_sections(self):
        for va, length in ((-1, 1), (0, 0), (1 << 63, 8)):
            with self.subTest(va=va, length=length), self.assertRaises(ValueError):
                self.image.location(va, length)
        bss = self.image.named('.data')
        fake = dict(bss, name='fake-nobits', type=8, address=0x123456789, size=32)
        synthetic = view.Image(self.data, [fake])
        with self.assertRaises(ValueError):
            synthetic.read(fake['address'], 1)

    def test_ambiguous_file_backed_mapping_rejected(self):
        sec = next(s for s in self.image.sections if s['name'] == '.text')
        image = view.Image(self.data, [sec, dict(sec, name='ambiguous')])
        with self.assertRaises(ValueError):
            image.read(0x4888e80, 1)

    def test_lsda_tables_and_witnesses(self):
        headers, rows = view.lsda_rows(self.image, self.functions)
        self.assertEqual(len(headers), 7)
        self.assertEqual(len(rows), 61)
        calls = {r['role']: r for r in view.witnesses(view.site_rows(self.image), rows)}
        self.assertEqual(calls['clone_first']['landing'], 0x48897b3)
        self.assertEqual(calls['clone_next']['landing'], 0x48897a6)
        self.assertEqual(calls['builder_next']['landing'], 0x428d022)

    def test_corrupt_lsda_header_rejected(self):
        row = next(r for r in self.functions if r['start'] == 0x4888e80)
        _, off = self.image.location(row['lsda'], 1)
        self.changed(off, b'\x00', lambda: view.lsda_rows(self.image, self.functions))

    def test_corrupt_lsda_action_byte_rejected(self):
        _, rows = view.lsda_rows(self.image, self.functions)
        row = next(r for r in rows if r['owner'] == 0x4888e80)
        off = row['entry_offset'] + len(bytes.fromhex(row['bytes'])) - 1
        self.changed(off, bytes([self.data[off] ^ 1]), lambda: view.lsda_rows(self.image, self.functions))

    def test_large_sort_slot_and_unwind_are_pinned(self):
        sites = {r['role']: r for r in view.site_rows(self.image)}
        self.assertEqual(sites['sort_large_slot']['target'], 0x5776760)
        self.assertEqual(sites['large_sort_inner']['target'], 0x4dc76d0)
        headers, rows = view.lsda_rows(self.image, self.functions)
        calls = {r['role']: r for r in view.witnesses(list(sites.values()), rows)}
        self.assertEqual(calls['sort_large_slot']['landing'], 0x489ebd9)

    def test_large_sort_slot_mutation_is_rejected(self):
        row = next(r for r in view.relocation_rows(self.image) if r['role'] == 'large_sort_slot')
        off = row['offset'] + 16
        self.changed(off, bytes([self.data[off] ^ 1]), lambda: view.relocation_rows(self.image))

    def test_queue_projection_and_capacity(self):
        facts = {r['role']: r['value'] for r in view.fact_rows(self.image)}
        self.assertEqual(facts['parent_payload_bytes'], 0x148)
        self.assertEqual(facts['queue_copy_bytes'], 8 + facts['parent_payload_bytes'])
        self.assertEqual(facts['receiver_copy_bytes'], facts['queue_copy_bytes'])
        self.assertEqual(facts['receiver_wrapper_copy_bytes'], facts['queue_copy_bytes'])
        # Parent map occupies stack [0x220,0x238); payload starts at 0xf8.
        start, end = 0x220 - 0xf8, 0x238 - 0xf8
        self.assertEqual((start, end), (0x128, 0x140))
        self.assertLessEqual(end, facts['parent_payload_bytes'])
        self.assertEqual((start + 8, end + 8), (0x130, 0x148))

    def test_receive_branches_and_retry(self):
        sites = {r['role']: r for r in view.site_rows(self.image)}
        self.assertEqual(sites['recv_wrapper_first']['target'], 0x4b45f20)
        self.assertEqual(sites['recv_wrapper_retry']['target'], 0x4b45f20)
        self.assertEqual(sites['recv_published']['target'], 0x4b460c9)
        self.assertEqual(sites['recv_closed']['target'], 0x4b460d9)
        self.assertEqual(sites['recv_tag_no_advance']['target'], 0x4b460e0)

    def test_receive_branch_corruption_rejected(self):
        _, off = self.image.location(0x4b460ce, 2)
        self.changed(off, b'\x90\x09', lambda: view.site_rows(self.image))

    def test_queue_copy_size_corruption_rejected(self):
        _, off = self.image.location(0x4b47a9e, 1)
        self.changed(off, b'\x51', lambda: view.fact_rows(self.image))

    def test_output_is_deterministic_and_rewritable(self):
        with tempfile.TemporaryDirectory() as parent:
            first, second = Path(parent) / 'a', Path(parent) / 'b'
            view.produce(self.data, first)
            view.produce(self.data, second)
            self.assertEqual(sorted(x.name for x in first.iterdir()), sorted(x.name for x in second.iterdir()))
            for p in first.iterdir():
                with self.subTest(name=p.name):
                    self.assertEqual(p.read_bytes(), (second / p.name).read_bytes())
            (first / 'README.md').write_text('review context\n', encoding='utf-8')
            view.produce(self.data, first)
            self.assertEqual((first / 'README.md').read_text(encoding='utf-8'), 'review context\n')
            (first / 'unexpected').write_text('x', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'unexpected'):
                view.produce(self.data, first)


class ConditionalModelTests(unittest.TestCase):
    """Synthetic arithmetic controls; these do not execute target instructions."""

    @staticmethod
    def mask20(left, right):
        if len(left) != 20 or len(right) != 20:
            raise ValueError('expected two 20-byte keys')
        # PCMPEQB of bytes 0..15 ANDs with MOVD/PCMPEQB of bytes 16..19.
        # MOVD zeroes the remaining 12 lanes on both sides.
        return sum(((left[i] == right[i]) and
                    (left[16+i] == right[16+i] if i < 4 else True)) << i
                   for i in range(16))

    def test_vector_equality_checks_all_20_bytes(self):
        a = bytes(range(20))
        self.assertEqual(self.mask20(a, a), 0xffff)
        for i in range(20):
            b = bytearray(a)
            b[i] ^= 0x80
            with self.subTest(position=i):
                self.assertNotEqual(self.mask20(a, bytes(b)), 0xffff)
        with self.assertRaises(ValueError):
            self.mask20(a, a[:-1])

    def test_vector_mask_against_independent_equality(self):
        values = [bytes([i]) * 20 for i in (0, 1, 127, 128, 255)]
        values += [bytes(range(20)), bytes(range(19)) + b'\xff']
        for a, b in itertools.product(values, repeat=2):
            self.assertEqual(self.mask20(a, b) == 0xffff, a == b)

    @staticmethod
    def receive_model(ready, closed, tag):
        # Conditional model of the selected reader, not target execution.
        if not ready:
            return (2 if closed else 3, False)
        return tag, tag < 2

    def test_receive_slot_tag_and_advance_controls(self):
        for closed in (False, True):
            for tag in (0, 1, 2, 3):
                self.assertEqual(self.receive_model(True, closed, tag), (tag, tag < 2))
        self.assertEqual(self.receive_model(False, False, 0), (3, False))
        self.assertEqual(self.receive_model(False, True, 0), (2, False))

    @staticmethod
    def buffer_plan(n):
        if n < 21:
            raise ValueError('large-sort branch not reached')
        half = n - n // 2
        if half > 0x2aaaaaaaaaaaaaa:
            raise OverflowError('allocation size bound')
        capacity = max(min(n, 0x28b0a), half)
        return capacity, capacity >= 0x56, n < 0x41

    def test_large_sort_buffer_boundary_model(self):
        self.assertEqual(self.buffer_plan(21), (21, False, True))
        self.assertEqual(self.buffer_plan(64), (64, False, True))
        self.assertEqual(self.buffer_plan(65), (65, False, False))
        self.assertEqual(self.buffer_plan(85), (85, False, False))
        self.assertEqual(self.buffer_plan(86), (86, True, False))
        self.assertEqual(self.buffer_plan(166666), (166666, True, False))
        self.assertEqual(self.buffer_plan(333332), (166666, True, False))
        self.assertEqual(self.buffer_plan(333333), (166667, True, False))
        with self.assertRaises(ValueError):
            self.buffer_plan(20)
        with self.assertRaises(OverflowError):
            self.buffer_plan(2 * 0x2aaaaaaaaaaaaaa + 1)

    @staticmethod
    def small_records(first, second, exclusion, nonces):
        keys = list(first) + [key for key in second if key not in exclusion]
        if len(keys) > 20:
            raise ValueError('outside selected small-sort model')
        if any(not isinstance(k, bytes) or len(k) != 20 for k in keys):
            raise ValueError('invalid key')
        records = [(key, tuple(nonces.get(key, ()))) for key in keys]
        # Strictly negative comparison moves rows; equality preserves order.
        for i in range(1, len(records)):
            candidate, j = records[i], i
            while j and candidate[0] < records[j-1][0]:
                records[j] = records[j-1]
                j -= 1
            records[j] = candidate
        # Equal adjacent keys release the previous value and keep the later one.
        result = []
        for record in records:
            if result and result[-1][0] == record[0]:
                result[-1] = record
            else:
                result.append(record)
        return result

    def test_filtered_candidate_cases_and_empty_value(self):
        a, b, c, d = (bytes([i]) * 20 for i in range(4))
        got = self.small_records([c, a], [a, b, d], {a}, {a: (5, 9), b: (11,)})
        self.assertEqual(got, [(a, (5, 9)), (b, (11,)), (c, ()), (d, ())])
        self.assertEqual(self.small_records([], [], set(), {}), [])

    def test_conditional_model_boundaries_and_invalid_key(self):
        keys = [i.to_bytes(20, 'big') for i in range(21)]
        self.assertEqual(len(self.small_records(keys[:20], [], set(), {})), 20)
        with self.assertRaisesRegex(ValueError, 'outside'):
            self.small_records(keys, [], set(), {})
        with self.assertRaisesRegex(ValueError, 'invalid'):
            self.small_records([b'bad'], [], set(), {})

    def test_duplicate_keys_collapse_to_one(self):
        a = b'\xaa' * 20
        b = b'\xbb' * 20
        got = self.small_records([a, b], [a], set(), {a: (3,), b: (4,)})
        self.assertEqual(got, [(a, (3,)), (b, (4,))])

    def test_equal_run_keeps_last_payload_in_small_sort(self):
        a, b = bytes([1]) * 20, bytes([2]) * 20
        unsorted = [(b, 'first-b'), (a, 'only-a'), (b, 'last-b')]
        ordered = sorted(unsorted, key=lambda item: item[0])
        reduced = []
        for row in ordered:
            if reduced and row[0] == reduced[-1][0]:
                reduced[-1] = row
            else:
                reduced.append(row)
        self.assertEqual(reduced, [(a, 'only-a'), (b, 'last-b')])

    def test_small_set_results_match_independent_set_spec(self):
        keys = [i.to_bytes(20, 'big') for i in range(3)]
        subsets = [set(k for i, k in enumerate(keys) if mask & (1 << i)) for mask in range(8)]
        for first, second, exclusion in itertools.product(subsets, repeat=3):
            got = self.small_records(sorted(first), sorted(second), exclusion, {})
            self.assertEqual([x[0] for x in got], sorted(first | (second - exclusion)))


if __name__ == '__main__':
    unittest.main()
