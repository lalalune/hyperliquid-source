import contextlib
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import re21_borrowed_family94 as subject


class BorrowedFamilyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(subject.TARGET.read_bytes())
        subject.authenticate(cls.data)
        cls.image = subject.Image(cls.data)
        cls.records = subject.relocation_index(cls.image)
        cls.providers = {va: subject.provider(cls.image, va) for va in subject.PROVIDERS}
        cls.revisions, cls.cases, cls.table, cls.table_bytes = subject.revision_cases(
            cls.image, cls.records, cls.providers)
        cls.frames, cls.functions, cls.bodies = subject.select_functions(cls.image, cls.cases)
        cls.exception = {f['start']: subject.lsda_record(cls.image, f)
                         for f in cls.frames if f['lsda'] is not None}

    @contextlib.contextmanager
    def changed(self, va, xor=1):
        off = self.image.offset(va, 1)
        old = self.data[off]
        self.data[off] ^= xor
        try:
            yield
        finally:
            self.data[off] = old

    def test_input_digest_and_corruption(self):
        subject.authenticate(self.data)
        with self.changed(0x37fc048):
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                subject.authenticate(self.data)

    def test_file_backing_and_executable_requirements(self):
        text = next(s for s in self.image.secs if s['name'] == '.text')
        bss = next(s for s in self.image.secs if s['name'] == '.bss')
        self.assertEqual(self.image.offset(text['address'], 1, True), text['offset'])
        for va, n in ((bss['address'], 1), (0, 1), (text['address'] + text['size'] - 1, 2),
                      (1 << 64, 1), (-1, 1), (text['address'], 0)):
            with self.subTest(va=va, n=n), self.assertRaises(ValueError):
                self.image.read(va, n, True)

    def test_ambiguous_section_is_rejected(self):
        sec = next(s for s in self.image.secs if s['name'] == '.text')
        image = subject.Image(self.data, self.image.secs + [dict(sec)])
        with self.assertRaisesRegex(ValueError, 'uniquely'):
            image.read(sec['address'], 1, True)

    def test_all_revision_provider_modes(self):
        for revision, row in enumerate(self.revisions):
            expected = (0 if revision <= 5 else 1 if revision <= 8 else
                        2 if revision <= 10 else 3 if revision <= 16 else
                        4 if revision == 17 else 5)
            with self.subTest(revision=revision):
                self.assertEqual(row['input_byte'], revision)
                self.assertEqual(row['mode'], expected)
                self.assertEqual(row['address09_from_prior_lineage'], expected >= 2)
        self.assertEqual(self.revisions[9]['case_va'], self.revisions[10]['case_va'])
        self.assertEqual(self.revisions[9]['provider_va'], '0x328c570')
        self.assertEqual(self.revisions[19]['canonical'], 19)
        self.assertEqual(self.revisions[20]['canonical'], 255)
        self.assertEqual(self.revisions[255]['canonical'], 255)

    def test_revision_table_and_bound_are_checked(self):
        for va in (self.table, self.table + 4 * 9, 0x37fbbad, 0x37fbbb8):
            with self.subTest(va=hex(va)), self.changed(va):
                with self.assertRaises(ValueError):
                    subject.revision_cases(self.image, self.records, self.providers)

    def test_case_target_and_join_mutation(self):
        for va in (0x37fc098, 0x37fc1c2, 0x37fc1bf):
            with self.subTest(va=hex(va)), self.changed(va):
                with self.assertRaises(ValueError):
                    subject.revision_cases(self.image, self.records, self.providers)

    def test_provider_pointer_and_zero_tag(self):
        row = self.providers[0x328c570]
        self.assertEqual(row['constructor_va'], '0x4e99650')
        self.assertEqual(row['mode'], 2)
        self.assertEqual(row['cache_va'], '0x5788450')
        self.assertEqual(self.image.allocated_section(int(row['cache_va'], 16))['type'], 8)
        for va in (0x328c570, 0x328c57b, 0x328c582, 0x328c587):
            with self.subTest(va=hex(va)), self.changed(va):
                with self.assertRaises(ValueError):
                    subject.provider(self.image, 0x328c570)

    def test_provider_rejects_file_backed_cache(self):
        fake = [dict(s) for s in self.image.secs]
        sec = next(s for s in fake if s['name'] == '.bss')
        sec['type'] = 1
        with self.assertRaisesRegex(ValueError, 'NOBITS'):
            subject.provider(subject.Image(self.data, fake), 0x328c570)

    def test_relative_relocation_controls(self):
        slot = 0x56e1a18
        self.assertEqual(subject.relative(self.records, slot)[0], 0x328c570)
        altered = dict(self.records)
        info, addend, off = altered[slot]
        altered[slot] = (info | (1 << 32), addend, off)
        with self.assertRaises(ValueError):
            subject.relative(altered, slot)
        altered[slot] = (7, addend, off)
        with self.assertRaises(ValueError):
            subject.relative(altered, slot)
        del altered[slot]
        with self.assertRaises(ValueError):
            subject.relative(altered, slot)

    def test_changed_provider_relocation_is_rejected(self):
        altered = dict(self.records)
        slot = 0x56e1a18
        info, _, off = altered[slot]
        altered[slot] = (info, 0x32885e0, off)
        with self.assertRaises(ValueError):
            subject.revision_cases(self.image, altered, self.providers)
        # The complete-input gate also rejects relocation-record corruption.
        with self.changed(int(off)):
            with self.assertRaises(ValueError):
                subject.authenticate(self.data)

    def test_callback_pair_offsets_and_frame_method(self):
        pairs = subject.callback_pairs(self.image, self.records)
        self.assertEqual([p['descriptor_output_offset'] for p in pairs],
                         [8 + 16 * i for i in range(11)])
        self.assertEqual(pairs[0]['methods'][2]['addend_va'], '0x3286e10')
        self.assertEqual(pairs[2]['descriptor_va'], '0x56e6400')
        self.assertEqual(pairs[2]['methods'][2]['addend_va'], '0x3287080')

    def test_post_callbacks_and_status_classes(self):
        pairs = subject.post_pairs(self.image, self.records)
        self.assertEqual([p['descriptor_output_offset'] for p in pairs],
                         [8 + 16 * i for i in range(6)])
        self.assertEqual([p['methods'][2]['addend_va'] for p in pairs[:4]],
                         ['0x3286bf0', '0x3287b50', '0x32876d0', '0x3286e80'])
        rows = subject.status_classes(self.image)
        for byte, row in enumerate(rows):
            expected = 16 if byte <= 4 else 8 if 16 <= byte <= 21 else 0
            with self.subTest(status=byte):
                self.assertEqual(row['preserved_bytes'], expected)
        with self.changed(0x3286e5c):
            with self.assertRaises(ValueError):
                subject.status_classes(self.image)
        with self.changed(0x32be01a):
            with self.assertRaises(ValueError):
                subject.post_pairs(self.image, self.records)

    def test_final_output_status_mapping(self):
        rows, meta = subject.output_status_map(self.image)
        self.assertEqual(len(rows), 113)
        self.assertEqual(meta['counts'], {'trap': 68, '0': 4, '1': 3, '2': 31, '3': 1, '4': 6})
        self.assertEqual(meta['first_unselected_target_va'], '0x324d340')
        self.assertEqual((rows[1]['returned_class'], rows[1]['returned_low_byte'], rows[1]['output_arm_va']),
                         (0, 0, '0x32d38cc'))
        self.assertEqual((rows[16]['returned_class'], rows[16]['returned_low_byte'], rows[16]['output_arm_va']),
                         (1, 16, '0x32d3973'))
        self.assertEqual((rows[17]['returned_class'], rows[17]['returned_low_byte'], rows[17]['output_arm_va']),
                         (2, 22, '0x32d3968'))
        self.assertEqual((rows[101]['returned_class'], rows[101]['output_arm_va']), (3, '0x32d3b15'))
        self.assertEqual((rows[0]['returned_class'], rows[0]['output_arm_va']), (4, '0x32d3b15'))
        self.assertEqual(rows[5]['kind'], 'trap')
        self.assertEqual(rows[112]['output_arm_va'], '0x32d3968')

    def test_final_output_status_corruption(self):
        for va in (0x580fd4, 0x580fd4 + 4 * 112, 0x582234, 0x324d170,
                   0x324d1fa, 0x324d28b):
            with self.subTest(va=hex(va)), self.changed(va):
                with self.assertRaises(ValueError):
                    subject.output_status_map(self.image)
        with self.assertRaises(ValueError):
            subject.status_result_shape(self.image, 0x324d28c, 0)

    def test_state_reset_constants_and_allocation_failure(self):
        detail = subject.state_reset_details(self.image, self.records)
        self.assertEqual(detail['requested_bytes'], 24)
        self.assertEqual(detail['null_target_va'], '0x32ac713')
        self.assertEqual(len(detail['reset_constant_loads']), 4)
        self.assertTrue(all(x['constant_file_bytes'] == '00' * 16 for x in detail['reset_constant_loads']))
        self.assertEqual([len(x['relative_relocations']) for x in detail['reset_constant_loads']], [0, 1, 0, 1])
        self.assertEqual(detail['reset_constant_loads'][1]['relative_relocations'][0]['addend_va'], '0x202e90')
        for va in (0x56df298, 0x56df2a8, 0x32ac56a, 0x32ac587, 0x32ac58b, 0x32ac594):
            with self.subTest(va=hex(va)), self.changed(va):
                with self.assertRaises(ValueError):
                    subject.state_reset_details(self.image, self.records)
        altered = dict(self.records)
        info, _, off = altered[0x56df298]
        altered[0x56df298] = (info, 0, off)
        with self.assertRaises(ValueError):
            subject.state_reset_details(self.image, altered)
        altered = dict(self.records)
        altered[0x56df2a8] = (8, 0, 0)
        with self.assertRaises(ValueError):
            subject.state_reset_details(self.image, altered)

    def test_cap_projection_boundaries_and_failure_order(self):
        self.assertEqual(subject.project_cap(100, 20, 10, 5), ('ok', 15))
        self.assertEqual(subject.project_cap(100, 20, 39, 1), ('ok', 40))
        self.assertEqual(subject.project_cap(100, 20, 40, 1), ('ok', 40))
        self.assertEqual(subject.project_cap(0, 1, 9, 2), ('subtract_borrow', 11))
        self.assertEqual(subject.project_cap(1, 0, (1 << 63) - 1, 1),
                         ('signed_add_overflow', (1 << 63) - 1))
        self.assertEqual(subject.project_cap(0, 0, 1 << 63, (1 << 64) - 1),
                         ('signed_add_overflow', 1 << 63))
        self.assertEqual(subject.project_cap(8, 0, (1 << 64) - 1, 0), ('ok', 4))
        with self.assertRaises(ValueError):
            subject.project_cap(0, 0, -1, 0)

    def test_credit_selection_operand_and_branch_corruption(self):
        rows = subject.credit_selection_inputs(self.image)
        self.assertEqual([r['guard_required'] for r in rows], [1, 1])
        for row in rows:
            self.assertEqual(row['guard_offset'], 0x178)
            groups = row['operands_low_limb_first']
            self.assertEqual([x['offset'] for x in groups['cap']],
                             [0x240, 0x248, 0x250, 0x258])
            self.assertEqual([x['offset'] for x in groups['left']],
                             [0x90, 0x98, 0xa0, 0xa8])
            self.assertEqual([x['offset'] for x in groups['right']],
                             [0x180, 0x188, 0x190, 0x198])
        for va in (0x32d1db6, 0x32d2ea8, 0x32d1dc6, 0x32d2eed, 0x32d1e60):
            with self.subTest(va=hex(va)), self.changed(va):
                with self.assertRaises(ValueError):
                    subject.credit_selection_inputs(self.image)

    def test_credit_selection_against_integer_oracle(self):
        mask = (1 << 256) - 1
        values = (0, 1, 2, (1 << 64) - 1, 1 << 128, 1 << 255, mask - 1, mask)
        for cap in values:
            for left in values:
                for right in values:
                    for discriminator in (0, 1):
                        expected = min(cap, (left + right) & mask) if discriminator == 1 else cap
                        with self.subTest(cap=cap, left=left, right=right, mode=discriminator):
                            self.assertEqual(subject.project_credit_selection(
                                discriminator, cap, left, right), expected)
        self.assertEqual(subject.project_credit_selection(1, mask, mask, 1), 0)
        self.assertEqual(subject.project_credit_selection(2, mask, mask, 1), mask)
        with self.assertRaises(ValueError):
            subject.project_credit_selection(1 << 32, 0, 0, 0)

    def test_credit_projection_against_integer_oracle(self):
        mask = (1 << 256) - 1
        values = (0, 1, 2, (1 << 64) - 1, 1 << 128, 1 << 255, mask - 1, mask)
        for balance in values:
            for price in values:
                for amount in (0, 1, 2, (1 << 64) - 1):
                    product = (price * amount) & mask
                    total = balance + product
                    expected = (min(total, mask), total > mask)
                    with self.subTest(balance=balance, price=price, amount=amount):
                        self.assertEqual(subject.project_credit(balance, price, amount), expected)
        self.assertEqual(subject.project_credit(0, 1 << 255, 2), (0, False))
        self.assertEqual(subject.project_credit(mask - 1, 2, 1), (mask, True))
        with self.assertRaises(ValueError):
            subject.project_credit(0, 0, 1 << 64)

    def test_second_credit_failure_keeps_earlier_flag_write(self):
        self.assertEqual(subject.project_second_credit(2, 3, 0, 0, 100, 1),
                         ('first_subtract_borrow', 4, 100, False))
        self.assertEqual(subject.project_second_credit(3, 2, 2, 0x80, 100, 1),
                         ('second_subtract_borrow', 0x84, 100, False))
        self.assertEqual(subject.project_second_credit(4, 1, 1, 0, 100, 1),
                         ('ok', 4, 102, False))
        mask = (1 << 256) - 1
        self.assertEqual(subject.project_second_credit(1, 0, 0, 4, mask - 1, 2),
                         ('ok', 4, mask, True))
        with self.assertRaises(ValueError):
            subject.project_second_credit(1, 0, 0, 256, 0, 0)

    def test_callback_byte_and_relocation_corruption(self):
        for va in (0x32caf9c, 0x32cafa6):
            with self.subTest(va=hex(va)), self.changed(va):
                with self.assertRaises(ValueError):
                    subject.callback_pairs(self.image, self.records)
        altered = dict(self.records)
        info, _, off = altered[0x56e6428]
        altered[0x56e6428] = (info, 0x3287081, off)
        with self.assertRaises(ValueError):
            subject.callback_pairs(self.image, altered)
        altered = dict(self.records)
        info, _, off = altered[0x56e63c8]
        altered[0x56e63c8] = (info, 0x3286e11, off)
        with self.assertRaises(ValueError):
            subject.callback_pairs(self.image, altered)

    def test_all_reviewed_windows_reject_end_corruption(self):
        for name, va, size, _ in subject.PINS:
            for target in (va, va + size - 1):
                with self.subTest(name=name, target=hex(target)), self.changed(target):
                    with self.assertRaises(ValueError):
                        subject.checked_windows(self.image)

    def test_selected_transfer_corruption(self):
        self.assertEqual(len(subject.checked_edges(self.image)), len(subject.EDGES))
        for _, va, _, _ in subject.EDGES:
            with self.subTest(va=hex(va)), self.changed(va):
                with self.assertRaises(ValueError):
                    subject.checked_edges(self.image)

    def test_unknown_and_truncated_transfer_shapes(self):
        with self.assertRaises(ValueError):
            subject.transfer(self.image, 0x3287080)
        with self.assertRaises(ValueError):
            subject.s32(b'\x01\x02\x03')

    def test_allocation_branch_count_and_null_guard(self):
        rows = subject.allocation_checks(self.image, self.frames)
        self.assertEqual(len(rows), 15 * 4 + 11 + 6)
        self.assertTrue(all(r['requested_size'] == 16 for r in rows))
        selected = next(r for r in rows if r['owner_va'] == '0x32b84c0')
        with self.changed(int(selected['branch_va'], 16)):
            with self.assertRaises(ValueError):
                subject.allocation_checks(self.image, self.frames)

    def test_selected_fdes_are_distinct_and_indexed(self):
        starts = [x['start_va'] for x in self.functions]
        self.assertEqual(len(starts), 37)
        self.assertEqual(len(set(starts)), len(starts))
        self.assertIn('0x37f98f0', starts)
        self.assertNotIn('0x32aceb0', starts)
        self.assertNotIn('0x4e9d2a0', starts)
        for row, body in zip(self.functions, self.bodies):
            self.assertEqual(row['start_va'], body['start_va'])
            self.assertEqual(hashlib.sha256(bytes.fromhex(body['bytes'])).hexdigest(), row['sha256'])

    def test_corrupt_unwind_header_rejected(self):
        hdr = next(s for s in self.image.secs if s['name'] == '.eh_frame_hdr')
        with self.changed(hdr['address']):
            with self.assertRaises(ValueError):
                subject.select_functions(self.image, self.cases)

    def test_exception_cleanup_and_publication(self):
        ex = self.exception[0x37f98f0]
        row = subject.covering(ex, 0x37f9ab7)
        self.assertEqual(row['landing_va'], '0x37fb836')
        self.assertEqual(subject.covering(self.exception[0x3287080], 0x3287090)['landing_va'], '0x32870de')
        self.assertEqual(subject.covering(self.exception[0x3287080], 0x32870a5)['landing_va'], '0x32870c3')
        with self.assertRaises(ValueError):
            subject.covering(ex, 0)
        duplicate = dict(ex, entries=ex['entries'] + [row])
        with self.assertRaises(ValueError):
            subject.covering(duplicate, 0x37f9ab7)

    def test_exception_header_corruption(self):
        f = next(f for f in self.frames if f['start'] == 0x37f98f0)
        with self.changed(f['lsda']):
            with self.assertRaises(ValueError):
                subject.lsda_record(self.image, f)

    def test_evidence_reproduces_exactly(self):
        folder = ROOT / 'research/work-items/RE-021-borrowed-family-94'
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            summary = subject.generate(self.data, out)
            self.assertEqual(summary['selected_fdes'], 37)
            self.assertEqual(summary['raw_revision_entries'], 20)
            generated = sorted(p.name for p in out.iterdir())
            retained = sorted(p.name for p in folder.iterdir() if p.suffix in ('.json', '.tsv'))
            self.assertEqual(generated, retained)
            for name in generated:
                with self.subTest(name=name):
                    self.assertEqual((out / name).read_bytes(), (folder / name).read_bytes())
            evidence = json.loads((out / 'flow.json').read_text(encoding='utf-8'))
            self.assertEqual(evidence['prior_address_key'], '00' * 19 + '09')
            self.assertEqual(evidence['old_map_drop_interval']['landing_va'], '0x37fb836')


if __name__ == '__main__':
    unittest.main()
