"""Controls for static node 94 spot-index failure evidence."""
import contextlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import spot_index_unwind94 as subject


class SpotIndexEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = bytearray(subject.TARGET.read_bytes())
        cls.secs = subject.sections(cls.data)
        cls.result = subject.collect(cls.data)
        _, cls.fdes = subject.eh_frame_records(cls.data, cls.secs)
        cls.by_start = {f['start']: f for f in cls.fdes}

    @contextlib.contextmanager
    def altered(self, offset, xor=1):
        old = self.data[offset]
        self.data[offset] ^= xor
        try:
            yield
        finally:
            self.data[offset] = old

    def test_input_identity_and_corruption(self):
        subject.verify_identity(self.data)
        with self.altered(1000):
            with self.assertRaises(subject.EvidenceError):
                subject.verify_identity(self.data)

    def test_selected_fdes_and_index(self):
        self.assertEqual(len(self.result['functions']), 6)
        _, entries = subject.unwind_index(self.data)
        idx = {r['start']: r for r in entries}
        for _, start, end, _ in subject.FUNCTIONS:
            self.assertEqual(self.by_start[start]['end'], end)
            self.assertEqual(idx[start]['fde'], self.by_start[start]['fde'])

    def test_corrupt_fde_extent_rejected(self):
        fde = self.by_start[0x1ade160]
        off = subject.file_offset(self.secs, fde['fde'], 16) + 12
        with self.altered(off):
            with self.assertRaises((subject.EvidenceError, ValueError)):
                subject.collect(self.data, authenticate=False)

    def test_corrupt_unwind_header_pointer_rejected(self):
        _, entries = subject.unwind_index(self.data)
        row = next(e for e in entries if e['start'] == 0x1ade160)
        hdr = next(s for s in self.secs if s['name'] == '.eh_frame_hdr')
        off = hdr['offset'] + 12 + 8 * row['index'] + 4
        with self.altered(off):
            with self.assertRaises((subject.EvidenceError, ValueError)):
                subject.collect(self.data, authenticate=False)

    def test_all_body_hashes_reject_corruption(self):
        for name, start, end, expected in subject.FUNCTIONS:
            with self.subTest(name=name):
                off = subject.file_offset(self.secs, start, end - start, True)
                with self.altered(off + (end - start) // 2):
                    with self.assertRaises(subject.EvidenceError):
                        subject.checked_window(self.data, self.secs, start, end, expected)

    def test_all_windows_reject_corruption(self):
        for name, start, end, expected in subject.WINDOWS:
            with self.subTest(name=name):
                off = subject.file_offset(self.secs, start, end - start, True)
                with self.altered(off + (end - start) // 2):
                    with self.assertRaises(subject.EvidenceError):
                        subject.checked_window(self.data, self.secs, start, end, expected)

    def test_selected_branch_opcodes_rejected(self):
        for va in subject.BRANCH_SITES:
            with self.subTest(site=hex(va)):
                off = subject.file_offset(self.secs, va, 1, True)
                old = self.data[off]
                self.data[off] = 0x90
                try:
                    with self.assertRaises(subject.EvidenceError):
                        subject.decode_branch(self.data, self.secs, va)
                finally:
                    self.data[off] = old

    def test_each_branch_displacement_is_bound_to_a_pinned_range(self):
        pins = [(start, end, expected) for _, start, end, expected in subject.WINDOWS + subject.FUNCTIONS]
        for va in subject.BRANCH_SITES:
            baseline = subject.decode_branch(self.data, self.secs, va)
            length = len(bytes.fromhex(baseline['bytes']))
            candidates = [(a, b, h) for a, b, h in pins if a <= va and va + length <= b]
            self.assertTrue(candidates, hex(va))
            start, end, expected = candidates[0]
            off = subject.file_offset(self.secs, va, length, True)
            with self.subTest(site=hex(va)), self.altered(off + length - 1):
                altered = subject.decode_branch(self.data, self.secs, va)
                self.assertNotEqual(altered['taken'], baseline['taken'])
                with self.assertRaises(subject.EvidenceError):
                    subject.checked_window(self.data, self.secs, start, end, expected)

    def test_key_branch_predicates_and_valid_opcode_mutants(self):
        expected = {0x26dee92:4, 0x26deed8:4, 0x1a6cac8:2, 0x1a6d46e:4,
                    0x1a6d492:5, 0x1ade182:3, 0x1ade217:3, 0x1ade228:4,
                    0x1ade22e:5, 0x1ade715:4, 0x1ade738:5}
        pins = [(a, b, h) for _, a, b, h in subject.WINDOWS + subject.FUNCTIONS]
        for site, cc in expected.items():
            with self.subTest(site=hex(site)):
                baseline = subject.decode_branch(self.data, self.secs, site)
                self.assertEqual(baseline['cc'], cc)
                raw = bytes.fromhex(baseline['bytes'])
                off = subject.file_offset(self.secs, site, len(raw), True)
                opcode_offset = off + (1 if raw[0] == 0x0f else 0)
                a, b, h = next(pin for pin in pins if pin[0] <= site and site + len(raw) <= pin[1])
                with self.altered(opcode_offset):
                    self.assertEqual(subject.decode_branch(self.data, self.secs, site)['cc'], cc ^ 1)
                    with self.assertRaises(subject.EvidenceError):
                        subject.checked_window(self.data, self.secs, a, b, h)

    def test_direct_transfer_displacements_rejected(self):
        for label, va, target in subject.DIRECT_CALLS:
            with self.subTest(label=label):
                subject.decode_call(self.data, self.secs, va, target)
                off = subject.file_offset(self.secs, va, 5, True)
                with self.altered(off + 1):
                    with self.assertRaises(subject.EvidenceError):
                        subject.decode_call(self.data, self.secs, va, target)

    def test_indirect_slots_and_corruption(self):
        for label, va, slot in subject.RIP_SITES:
            with self.subTest(label=label):
                row = subject.rip_site(self.data, self.secs, va, slot)
                off = subject.file_offset(self.secs, va, len(bytes.fromhex(row['raw'])), True)
                with self.altered(off + len(bytes.fromhex(row['raw'])) - 1):
                    with self.assertRaises(subject.EvidenceError):
                        subject.rip_site(self.data, self.secs, va, slot)

    def test_relative_relocation_corruption(self):
        rows = subject.relocations(self.data, self.secs)
        self.assertEqual(len(rows), 5)
        for row in rows:
            off = int(row['file_offset'], 16)
            with self.subTest(slot=row['slot']), self.altered(off + 16):
                with self.assertRaises(subject.EvidenceError):
                    subject.relocations(self.data, self.secs)

    def test_each_exception_table_rejects_corruption(self):
        for start, expected in subject.LSDA_DIGESTS.items():
            fde = self.by_start[start]
            table = subject.parse_lsda(self.data, self.secs, fde, expected)
            off = int(table['file_offset'], 16)
            with self.subTest(start=hex(start)), self.altered(off):
                with self.assertRaises((subject.EvidenceError, ValueError)):
                    subject.parse_lsda(self.data, self.secs, fde, expected)

    def test_each_exception_record_rejects_corruption(self):
        for table in self.result['exception_tables']:
            start = int(table['function'], 16)
            fde = self.by_start[start]
            for row in table['entries']:
                with self.subTest(record=row['record']):
                    off = subject.file_offset(self.secs, int(row['record'], 16), 1)
                    with self.altered(off):
                        with self.assertRaises((subject.EvidenceError, ValueError)):
                            subject.parse_lsda(self.data, self.secs, fde, subject.LSDA_DIGESTS[start])

    def test_exception_intervals_bind_failure_landings(self):
        got = self.result['height_failure_landings']
        self.assertEqual([(r['failure_call'], r['landing'], r['release_size']) for r in got],
                         [('0x1a6d802', '0x1a6d83a', 0x250),
                          ('0x1adea17', '0x1adea51', 0x120)])
        for row in got:
            self.assertEqual(bytes.fromhex(row['landing_bytes'])[0], 0xbe)
            self.assertEqual(bytes.fromhex(row['landing_bytes'])[-2:], b'\x0f\x0b')

    def test_distinct_mismatch_exception_routes(self):
        rows = {r['label']: r for r in self.result['failure_routes']}
        self.assertEqual(len(rows), 8)
        self.assertEqual(rows['outer_height_mismatch']['landing'], '0x1a6d86e')
        self.assertIsNone(rows['inner_height_mismatch']['landing'])
        self.assertEqual(rows['inner_root_allocation']['landing'], '0x1adea63')
        self.assertEqual(rows['outer_root_allocation']['landing'], '0x1a6d84c')

    def test_slot_miss_branches_past_bookkeeping(self):
        calls = {x['label']: x for x in self.result['direct_calls']}
        self.assertEqual(calls['slot_delete_context']['target'], '0x2866e70')
        branches = {x['site']: x for x in self.result['branches']}
        self.assertEqual(branches['0x26dee92']['taken'], '0x26df0a1')
        self.assertEqual(branches['0x26dee92']['fallthrough'], '0x26dee98')
        self.assertEqual(branches['0x26deed8']['taken'], '0x26deee1')

    def test_extracted_layout_and_split_boundaries(self):
        fields = {r['label']: r['value'] for r in self.result['fields']}
        for prefix in ('outer', 'inner'):
            self.assertEqual(fields[prefix + '_key_capacity'], 11)
            self.assertEqual(fields[prefix + '_split_boundary_five'], 5)
            self.assertEqual(fields[prefix + '_split_boundary_six'], 6)
        self.assertEqual(fields['spot_tracker_offset'], 0x740)
        self.assertEqual(fields['tracker_count_offset'], 0x20)
        self.assertEqual(fields['spot_change_map_offset'], 0x8a0)
        self.assertEqual(fields['slot_node_count_offset'], 0x62)
        self.assertEqual(fields['slot_child_offset'], 0x68)

    def test_cleanup_comparison_and_unmasked_mutation(self):
        comparison = subject.compare_cleanup(self.data, self.secs)
        self.assertEqual((comparison['displacement_mask_start'], comparison['displacement_mask_end']), (119, 123))
        self.assertEqual(comparison['size'], 139)
        off = subject.file_offset(self.secs, 0x28ae330, 0x8b, True)
        with self.altered(off + 10):
            with self.assertRaises(subject.EvidenceError):
                subject.compare_cleanup(self.data, self.secs)

    def test_slot_root_shrink_routes_and_operands(self):
        branches = {int(b['site'], 16): b for b in self.result['branches']}
        for site, taken in ((0x2866f16, 0x2866f4b), (0x2866f1e, 0x2866f5b),
                            (0x2866f27, 0x2866f68)):
            self.assertEqual(branches[site]['cc'], 5 if site == 0x2866f16 else 4)
            self.assertEqual(int(branches[site]['taken'], 16), taken)
        self.assertEqual(subject.read_va(self.data, self.secs, 0x2866f0d, 4, True),
                         bytes.fromhex('48ff4b10'))
        self.assertEqual(subject.read_va(self.data, self.secs, 0x2866f29, 21, True),
                         bytes.fromhex('488b4f6848890b48ffc84889430848c70100000000'))
        fields = {f['label']: f['value'] for f in self.result['fields']}
        self.assertEqual(fields['slot_old_root_release_size'], 0xc8)
        calls = {c['label']: c for c in self.result['direct_calls']}
        self.assertEqual(calls['slot_cursor_delete_context']['target'], '0x1b22d70')
        release = next(s for s in self.result['indirect_sites'] if s['label'] == 'slot_old_root_release')
        self.assertEqual(release['slot'], '0x576e010')
        off = subject.file_offset(self.secs, 0x2866f3e, 5, True)
        with self.altered(off + 1):
            with self.assertRaises(subject.EvidenceError):
                subject.checked_window(self.data, self.secs, 0x2866e70, 0x2866f81,
                                       subject.FUNCTIONS[0][3])

    def test_counter_decrement_boundary_and_miss(self):
        for value in (0, 1, 2, (1 << 64) - 1):
            with self.subTest(value=value):
                self.assertEqual(subject.tracker_counter_projection(value, False), value)
                self.assertEqual(subject.tracker_counter_projection(value, True), max(value - 1, 0))
        for invalid in (-1, 1 << 64, True):
            with self.subTest(invalid=invalid), self.assertRaises(subject.EvidenceError):
                subject.tracker_counter_projection(invalid, True)

    def test_root_projection_boundaries(self):
        model = subject.root_projection
        self.assertEqual(model(False, False, 0, 0)['outcome'], 'missing_root')
        self.assertEqual(model(True, False, 0, 0)['outcome'], 'allocation_failure')
        self.assertEqual(model(True, True, 0, 0)['outcome'], 'normal')
        self.assertTrue(model(True, True, 1, 0)['header_written'])
        self.assertEqual(model(True, True, 1, 0)['outcome'], 'height_mismatch')
        self.assertEqual(model(True, True, (1 << 64) - 1, 0)['outcome'], 'height_overflow')
        self.assertFalse(model(True, True, (1 << 64) - 1, 0)['header_written'])
        for bad in (-1, 1 << 64):
            with self.subTest(height=bad), self.assertRaises(subject.EvidenceError):
                model(True, True, bad, 0)

    def test_full_node_split_projections(self):
        for position in range(12):
            with self.subTest(position=position):
                row = subject.split_projection(position)
                combined = row['left'] + [row['promoted']] + row['right']
                reference = sorted(list(range(2, 24, 2)) + [2 * position + 1])
                self.assertEqual(combined, reference)
                self.assertEqual(sorted((len(row['left']), len(row['right']))), [5, 6])
        for position in (-1, 12, True):
            with self.subTest(position=position), self.assertRaises(subject.EvidenceError):
                subject.split_projection(position)

    def test_reject_unmapped_and_nobits(self):
        for va, size in ((0, 1), ((1 << 64) - 1, 2), (0x2866e70, 0)):
            with self.subTest(va=va, size=size), self.assertRaises(subject.EvidenceError):
                subject.file_offset(self.secs, va, size, True)
        nobits = next(s for s in self.secs if s['name'] == '.bss' and s['type'] == 8 and s['size'])
        with self.assertRaises(subject.EvidenceError):
            subject.file_offset(self.secs, nobits['address'], 1)

    def test_generated_files_match_retained_evidence(self):
        expected = ROOT / 'research/work-items/RE-006-spot-index-unwind-94'
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            subject.generate(out)
            names = ('evidence.json', 'branches.tsv', 'exception-sites.tsv', 'calls.tsv', 'root-cases.tsv', 'split-cases.tsv', 'failure-routes.tsv', 'counter-cases.tsv')
            self.assertEqual(sorted(p.name for p in out.iterdir()), sorted(names))
            for name in names:
                with self.subTest(file=name):
                    self.assertEqual((out / name).read_bytes(), (expected / name).read_bytes())


if __name__ == '__main__':
    unittest.main()
