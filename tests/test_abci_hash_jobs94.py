"""Static, target-grounded controls for the node 94 hash-job packet."""
from contextlib import contextmanager
import mmap
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import abci_hash_jobs94 as subject


class HashJobsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = subject.TARGET.open('rb')
        cls.mapping = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.image = subject.Image(cls.mapping)

    @classmethod
    def tearDownClass(cls):
        cls.mapping.close()
        cls.handle.close()

    @contextmanager
    def changed_va(self, va, index=0):
        offset = self.image.off(va + index, 1)
        original = self.mapping[offset]
        self.mapping[offset] = original ^ 1
        try:
            yield
        finally:
            self.mapping[offset] = original

    @contextmanager
    def changed_offset(self, offset):
        original = self.mapping[offset]
        self.mapping[offset] = original ^ 1
        try:
            yield
        finally:
            self.mapping[offset] = original

    def test_pinned_artifact_and_selected_extents(self):
        subject.verify_digest(self.mapping)
        records = subject.selected_functions(self.image)
        self.assertEqual(len(records), 20)
        owners = {int(record['start_va'], 16): record for record in records}
        self.assertEqual(int(owners[0x2289e30]['end_va'], 16), 0x228a084)
        self.assertEqual(int(owners[0x251c2e0]['end_va'], 16), 0x251c415)
        self.assertTrue(all(int(row['byte_count']) > 0 for row in records))
        self.assertTrue(all(len(row['bytes_hex']) == 2 * row['byte_count'] for row in records))

    def test_bad_and_missing_artifacts_produce_no_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            wrong = base / 'wrong-artifact'
            wrong.write_bytes(b'not the selected node')
            output = base / 'bad-output'
            with mock.patch.object(subject, 'TARGET', wrong):
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    subject.main(['--out', str(output)])
            self.assertFalse(output.exists())
            with mock.patch.object(subject, 'TARGET', base / 'missing-artifact'):
                with self.assertRaises(FileNotFoundError):
                    subject.main(['--out', str(output)])
            self.assertFalse(output.exists())

    def test_real_copy_on_write_digest_change(self):
        with self.changed_va(0x2289e30):
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                subject.verify_digest(self.mapping)
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                subject.Image(self.mapping)
        subject.verify_digest(self.mapping)

    def test_every_selected_body_rejects_a_real_byte_change(self):
        for start, (name, end, _, _) in subject.FUNCTIONS.items():
            with self.subTest(name=name):
                with self.changed_va(start, (end - start) // 2):
                    with self.assertRaisesRegex(ValueError, 'selected body changed'):
                        self.image.check_bodies()
        self.image.check_bodies()

    def test_each_window_detects_corruption(self):
        for name, start, _, _ in subject.WINDOWS:
            with self.subTest(name=name):
                with self.changed_va(start):
                    with self.assertRaises(ValueError):
                        subject.read_windows(self.image)

    def test_all_branch_guards_opcodes_and_displacements_reject_changes(self):
        for name, guard, site, _, raw, _ in subject.BRANCHES:
            for va in (guard, site, site + len(bytes.fromhex(raw)) - 1):
                with self.subTest(name=name, va=hex(va)):
                    with self.changed_va(va):
                        with self.assertRaises(ValueError):
                            subject.read_branches(self.image)
        with self.assertRaises(ValueError):
            subject.decode_conditional(0x100, b'\x90\x00')
        with self.assertRaises(ValueError):
            subject.decode_conditional(0x100, b'\x0f\x85')
        self.assertEqual(subject.decode_conditional(0x100, b'\x75\xfe'), ('ne', 0x100))

    def test_all_selected_transfers_reject_opcode_and_displacement_changes(self):
        for name, site, prefix, _ in subject.TRANSFERS:
            for va in (site, site + len(bytes.fromhex(prefix)) + 3):
                with self.subTest(name=name, va=hex(va)):
                    with self.changed_va(va):
                        with self.assertRaises(ValueError):
                            subject.read_transfers(self.image)
        for name, site, _ in subject.INDIRECTS:
            with self.subTest(name=name):
                with self.changed_va(site):
                    with self.assertRaises(ValueError):
                        subject.read_transfers(self.image)

    def test_fde_range_and_unwind_index_corruption(self):
        owner = 0x2289e30
        frame_offset = self.image.off(self.image.frames[owner]['fde'], 16)
        with self.changed_offset(frame_offset + 12):
            with self.assertRaises(ValueError):
                subject.Image(self.mapping, authenticate=False)
        header = next(s for s in self.image.sections if s['name'] == '.eh_frame_hdr')
        entry = self.image.index[owner]['index']
        index_offset = header['offset'] + 12 + 8 * entry + 4
        with self.changed_offset(index_offset):
            with self.assertRaises(ValueError):
                subject.Image(self.mapping, authenticate=False)

    def test_each_lsda_header_and_call_site_row_detects_corruption(self):
        for start, (name, _, _, lsda_hash) in subject.FUNCTIONS.items():
            if lsda_hash is None:
                self.assertIsNone(self.image.frames[start]['lsda'])
                continue
            header, rows = subject.parse_lsda(self.image, start)
            with self.subTest(name=name, part='header'):
                with self.changed_va(self.image.frames[start]['lsda']):
                    with self.assertRaises(ValueError):
                        subject.parse_lsda(self.image, start)
            row = rows[-1]
            last = int(row['row_file_offset'], 16) + len(bytes.fromhex(row['bytes_hex'])) - 1
            with self.subTest(name=name, part='action'):
                with self.changed_offset(last):
                    with self.assertRaises(ValueError):
                        subject.parse_lsda(self.image, start)
            self.assertEqual(header['rows'], len(rows))

    def test_actual_exception_rows_cover_selected_calls(self):
        headers, rows = subject.read_lsdas(self.image)
        links = subject.read_failure_links(rows)
        self.assertEqual(len(headers), 19)
        by_name = {row['name']: row for row in links}
        self.assertEqual(by_name['serial_invoke']['landing_va'], '0x251c3e5')
        self.assertEqual(by_name['dynamic_callback']['landing_va'], '0x1eace19')
        self.assertEqual(by_name['finish_buffer_header']['landing_va'], '0x1dd1f48')
        self.assertEqual(by_name['finish_buffer_grow']['landing_va'], '0x1dd1f46')
        self.assertEqual(by_name['task_poll_bridge']['action'], 5)
        self.assertEqual(by_name['task_publish_result']['action'], 7)
        self.assertEqual(by_name['enqueue_grow']['landing_va'], '0x4f7c77b')
        self.assertEqual(by_name['join_left_partition']['action'], 3)
        self.assertEqual(by_name['worker_partition']['action'], 7)
        damaged = [dict(row) for row in rows]
        target = next(row for row in damaged if row['landing_va'] == '0x251c3e5')
        target['landing_va'] = '0x0'
        with self.assertRaises(ValueError):
            subject.read_failure_links(damaged)

    def test_file_backed_unique_mapping(self):
        section = {'name': '.text', 'type': 1, 'flags': 6, 'address': 0x100,
                   'offset': 4, 'size': 16}
        self.assertEqual(subject.file_offset([section], 20, 0x101, 3, True), 5)
        for address, size in ((0xff, 1), (0x10f, 2), (0x100, 0), (-1, 1)):
            with self.subTest(address=address, size=size):
                with self.assertRaises(ValueError):
                    subject.file_offset([section], 20, address, size)
        fileless = dict(section, name='.bss', type=8)
        with self.assertRaises(ValueError):
            subject.file_offset([fileless], 20, 0x100, 1)
        with self.assertRaises(ValueError):
            subject.file_offset([section, dict(section)], 20, 0x100, 1)
        nonexec = dict(section, flags=2)
        with self.assertRaises(ValueError):
            subject.file_offset([nonexec], 20, 0x100, 1, True)
        with self.assertRaises(ValueError):
            self.image.read(0xffffffffffffffff, 1)

    def test_extracted_parameters_and_result_slots(self):
        parameters = subject.read_parameters(self.image)
        self.assertEqual(parameters, {'jobs': 41, 'input_stride': 16, 'output_stride': 32})
        encoding = subject.read_encoding(self.image, parameters)
        slots = subject.result_slots(parameters, encoding)
        self.assertEqual(len(slots), 41)
        self.assertEqual(slots[0]['output_start_offset'], '0x0')
        self.assertEqual(slots[20]['input_record_offset'], '0x140')
        self.assertEqual(slots[40]['output_end_offset'], '0x520')
        self.assertEqual(slots[0]['preimage_entry_offset'], '0x3')
        self.assertEqual(slots[40]['preimage_entry_end'], '0xae7')
        with self.changed_va(0x2756fb1, 8):
            with self.assertRaises(ValueError):
                subject.read_parameters(self.image)
        with self.changed_va(0x251c32b, 3):
            with self.assertRaises(ValueError):
                subject.read_parameters(self.image)

    def test_task_table_state_and_relocation_controls(self):
        relocation, dispatch, state = subject.read_task_table(self.image)
        self.assertEqual(len(relocation), 2)
        self.assertEqual(relocation[0]['addend_va'], '0x22a4500')
        self.assertEqual(relocation[1]['addend_va'], '0x4f7c290')
        self.assertEqual([r['target_va'] for r in dispatch],
                         ['0x1d8b7e7', '0x1d8b8e7', '0x1d8ba18', '0x1d8ba10'])
        self.assertEqual(state, {'initial_state': '0xcc', 'cas_desired': '0xc9',
                                 'uncontended_table_index': 0, 'input_bytes': 0x3ec0,
                                 'allocation_bytes': 0x3f80, 'bridge_tail_bytes': 0x3eb8,
                                 'task_input_offset': '0x40', 'task_tail_offset': '0x48'})
        for record in relocation:
            record_offset = int(record['record_file_offset'], 16)
            for offset in (record_offset, record_offset + 8, record_offset + 16):
                with self.subTest(relocation_offset=offset):
                    with self.changed_offset(offset):
                        with self.assertRaises(ValueError):
                            subject.read_task_table(self.image)
            with self.changed_va(int(record['slot_va'], 16)):
                with self.assertRaises(ValueError):
                    subject.read_task_table(self.image)
        for i in range(4):
            with self.subTest(table_index=i):
                with self.changed_va(0x3bc94c + 4 * i):
                    with self.assertRaises(ValueError):
                        subject.read_task_table(self.image)
        with self.changed_va(0x2020d99, 8):
            with self.assertRaises(ValueError):
                subject.read_task_table(self.image)
        for va in (0x22b55cd, 0x2020d92, 0x2020e32, 0x2017d71,
                   0x2020d86, 0x2020df3, 0x2020dfb, 0x2020e51,
                   0x1d8b7fa, 0x2017d44, 0x2017d67,
                   0x2017da7, 0x2017daf, 0x2017fbb):
            with self.subTest(handoff_byte=hex(va)):
                with self.changed_va(va):
                    with self.assertRaises(ValueError):
                        subject.read_task_table(self.image)

    def test_successful_preimage_shape_and_negative_controls(self):
        parameters = subject.read_parameters(self.image)
        encoding = subject.read_encoding(self.image, parameters)
        self.assertEqual(encoding['array_header_hex'], 'dc0029')
        self.assertEqual(encoding['entry_header_hex'], 'd942')
        self.assertEqual(encoding['hex_prefix_ascii'], '0x')
        self.assertEqual(encoding['alphabet_ascii'], '0123456789abcdef')
        self.assertEqual(encoding['direct_finish_result'], '0x8000000000000004')
        self.assertEqual(encoding['total_bytes'], 2791)
        # This is an independently assembled arithmetic example, not node execution.
        digest = bytes(range(32))
        text = encoding['hex_prefix_ascii'].encode('ascii') + digest.hex().encode('ascii')
        entry = bytes.fromhex(encoding['entry_header_hex']) + text
        example = bytes.fromhex(encoding['array_header_hex']) + entry * 41
        self.assertEqual(len(example), 2791)
        self.assertEqual(example[:7], bytes.fromhex('dc0029d9423078'))
        self.assertEqual(example[7:71], b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
        self.assertEqual(example[71:75], bytes.fromhex('d9423078'))
        for va in (0x1e5de66, 0x1e5decd, 0x1e5df56, 0x1e5df7e, 0x1dd1dd4,
                   0x1e5df31, 0x1e5df37, 0x25a9bde, 0x25a9cde, 0x25acc25,
                   0x25aa806, 0x25aa81f, 0x25aa93a, 0x25aabad, 0x29ed392, 0x208620):
            with self.subTest(va=hex(va)):
                with self.changed_va(va):
                    with self.assertRaises(ValueError):
                        subject.read_encoding(self.image, parameters)

    def test_partition_model_across_sizes_and_completion_orders(self):
        for n in range(0, 66):
            for cutoff in range(1, max(2, n + 2)):
                leaves = subject.leaf_ranges(0, n, cutoff)
                slots = subject.checked_slots(n, 16, 32, leaves)
                self.assertEqual(len(slots), n)
                self.assertEqual([(row[1], row[2]) for row in slots],
                                 [(i * 16, i * 32) for i in range(n)])
                # Reverse completion changes execution order, not target slot addresses.
                observed = [None] * n
                for lo, hi in reversed(leaves):
                    for i in range(lo, hi):
                        observed[i] = i
                self.assertEqual(observed, list(range(n)))
        self.assertEqual(subject.leaf_ranges(0, 41, 21), [(0, 20), (20, 41)])

    def test_partition_rejects_gaps_overlaps_and_reordered_ranges(self):
        for leaves in ([(0, 1), (2, 4)], [(0, 3), (2, 4)],
                       [(2, 4), (0, 2)], [(0, 3)], [(0, 5)]):
            with self.subTest(leaves=leaves):
                with self.assertRaises(ValueError):
                    subject.checked_slots(4, 16, 32, leaves)
        for args in ((0, -1, 1), (0, 4, 0), (-1, 4, 1)):
            with self.assertRaises(ValueError):
                subject.leaf_ranges(*args)

    def test_merge_branches_and_64_bit_boundaries(self):
        m = subject.MASK64
        self.assertEqual(subject.merge_segments((0x1000, 20, 20), (0x1280, 21, 21), 32),
                         ('merged', (0x1000, 41, 41)))
        self.assertEqual(subject.merge_segments((0x1000, 20, 20), (0x1281, 21, 21), 32),
                         ('nonadjacent', (0x1000, 20, 20)))
        self.assertEqual(subject.merge_segments((m - 31, 1, 1), (0, 1, 1), 32),
                         ('merged', (m - 31, 2, 2)))
        with self.assertRaisesRegex(OverflowError, 'first'):
            subject.merge_segments((0x1000, m, 1), (0x1020, 1, 1), 32)
        with self.assertRaisesRegex(OverflowError, 'second'):
            subject.merge_segments((0, 0, m), (m - 31, 0, 1), 32)
        with self.assertRaises(ValueError):
            subject.merge_segments((0, 0, 0), (0, 0, 0), 16)
        with self.assertRaises(ValueError):
            subject.merge_segments((-1, 0, 0), (0, 0, 0), 32)

    def test_generated_rows_use_only_selected_scopes(self):
        result = subject.collect(self.image)
        self.assertEqual(len(result), 11)
        self.assertEqual(set(result), {'summary.json', 'functions.tsv', 'windows.tsv',
                                       'branches.tsv', 'transfers.tsv', 'lsda.tsv',
                                       'lsda-headers.tsv', 'failure-links.tsv', 'result-slots.tsv',
                                       'task-relocation.tsv', 'task-dispatch.tsv'})
        self.assertEqual(result, subject.collect(self.image))


if __name__ == '__main__':
    unittest.main()
