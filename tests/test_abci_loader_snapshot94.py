"""Controls for the node 94 conditional state-snapshot handoff."""
import csv
import hashlib
import io
import json
import mmap
import struct
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools import abci_loader_snapshot94 as subject


class SnapshotHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = subject.TARGET.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.secs = subject.sections(cls.data)
        cls.rela = subject.section_named(cls.secs, '.rela.dyn')
        cls.relocs = subject.collect_relocations(cls.data, cls.rela, subject.RELOCATIONS)
        cls.records = subject.analyse(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    def mutate_va(self, address, delta=1):
        pos = subject.file_offset(self.secs, address, 1, len(self.data))
        old = self.data[pos]
        self.data[pos] = old ^ delta
        self.addCleanup(self.data.__setitem__, pos, old)
        return pos

    def mutate_offset(self, pos, delta=1):
        old = self.data[pos]
        self.data[pos] = old ^ delta
        self.addCleanup(self.data.__setitem__, pos, old)

    def test_digest_and_output_facts(self):
        summary = self.records['summary.json']
        self.assertEqual(summary['binary_sha256'], subject.EXPECTED_SHA256)
        self.assertEqual(summary['initial_task_word'], '0xcc')
        self.assertEqual(summary['state_copy_bytes'], 0x3ae8)
        self.assertEqual(summary['selected_fde_count'], 12)
        self.assertEqual(summary['conditional_branch_count'], 71)
        self.assertEqual(summary['table_entry_count'], 9)
        self.assertEqual(summary['relative_relocation_count'], 16)

    def test_wrong_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.check_digest(b'not the captured file')
        self.mutate_va(0x201667e)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.check_digest(self.data)

    def test_owned_extent_corruption_rejected_below_digest_gate(self):
        name, start, end, digest = next(x for x in subject.FUNCTIONS if x[0] == 'poll_bridge')
        self.mutate_va(0x2016728)
        with self.assertRaisesRegex(ValueError, 'extent bytes changed'):
            subject.checked_window(self.data, self.secs, start, end, digest)

    def test_boundary_window_corruption_rejected_below_digest_gate(self):
        name, start, end, digest = next(x for x in subject.WINDOWS if x[0] == 'status_path_copy')
        self.mutate_va(0x22b4d63)
        with self.assertRaisesRegex(ValueError, 'window or extent'):
            subject.checked_window(self.data, self.secs, start, end, digest)

    def test_fde_end_and_index_mismatch_rejected(self):
        items, index = subject.unwind_index(self.data)
        _, fdes = subject.eh_frame_records(self.data, items)
        altered = [dict(f) for f in fdes]
        row = next(f for f in altered if f['start'] == 0x2016670)
        row['end'] += 1
        with self.assertRaisesRegex(ValueError, 'FDE extent/index mismatch'):
            subject.selected_extents(self.data, items, index, altered)
        altered = [dict(e) for e in index]
        next(e for e in altered if e['start'] == 0x2016670)['fde'] += 1
        with self.assertRaisesRegex(ValueError, 'FDE extent/index mismatch'):
            subject.selected_extents(self.data, items, altered, fdes)

    def test_actual_fde_range_byte_corruption(self):
        items, index = subject.unwind_index(self.data)
        _, fdes = subject.eh_frame_records(self.data, items)
        original = next(f for f in fdes if f['start'] == 0x2016670)
        self.mutate_va(original['fde'] + 12)
        _, corrupted = subject.eh_frame_records(self.data, items)
        with self.assertRaisesRegex(ValueError, 'FDE extent/index mismatch'):
            subject.selected_extents(self.data, items, index, corrupted)

    def test_duplicate_fde_rejected(self):
        items, index = subject.unwind_index(self.data)
        _, fdes = subject.eh_frame_records(self.data, items)
        fde = next(x for x in fdes if x['start'] == 0x2016670)
        with self.assertRaisesRegex(ValueError, 'duplicate FDE'):
            subject.selected_extents(self.data, items, index, fdes + [dict(fde)])
        entry = next(x for x in index if x['start'] == 0x2016670)
        with self.assertRaisesRegex(ValueError, 'duplicate unwind index'):
            subject.selected_extents(self.data, items, index + [dict(entry)], fdes)

    def test_branch_target_and_opcode_controls(self):
        site, raw_hex, target = next(x for x in subject.BRANCHES if x[0] == 0x22b4c36)
        self.assertEqual(subject.decode_branch(bytes.fromhex(raw_hex), site), target)
        self.mutate_va(site + 2)
        with self.assertRaisesRegex(ValueError, 'branch changed'):
            subject.selected_branches(self.data, self.secs)
        with self.assertRaises(ValueError):
            subject.decode_branch(b'\x90\x00', site)
        with self.assertRaises(ValueError):
            subject.decode_branch(b'\x0f\x84', site)

    def test_condition_decoding_for_short_and_near_branches(self):
        for code, name in enumerate(('o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a',
                                     's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g')):
            with self.subTest(condition=name):
                self.assertEqual(subject.branch_condition(bytes((0x70 + code, 0))), name)
                self.assertEqual(subject.branch_condition(bytes((0x0f, 0x80 + code, 0, 0, 0, 0))), name)
        for bad in (b'', b'\xeb\x00', b'\x0f\x84'):
            with self.assertRaises(ValueError):
                subject.branch_condition(bad)
        rows = {row['site_va']: row for row in self.records['branches.tsv']}
        self.assertEqual(rows['0x22b4c36']['condition'], 'e')
        self.assertEqual(rows['0x201670b']['condition'], 'o')

    def test_transfer_target_and_opcode_controls(self):
        label, site, raw_hex, target = next(x for x in subject.TRANSFERS if x[0] == 'scheduler_poll')
        self.assertEqual(subject.decode_transfer(bytes.fromhex(raw_hex), site), ('call_rel32', target))
        self.mutate_va(site + 1)
        with self.assertRaisesRegex(ValueError, 'transfer changed'):
            subject.selected_transfers(self.data, self.secs)
        with self.assertRaises(ValueError):
            subject.decode_transfer(b'\x90' * 5, site)
        with self.assertRaises(ValueError):
            subject.decode_transfer(b'\xff\x15', site)

    def test_every_branch_and_transfer_rejects_a_changed_displacement(self):
        for site, encoded, target in subject.BRANCHES:
            with self.subTest(kind='branch', site=hex(site)):
                pos = subject.file_offset(self.secs, site + len(bytes.fromhex(encoded)) - 1, 1, len(self.data), True)
                old = self.data[pos]
                try:
                    self.data[pos] = old ^ 1
                    with self.assertRaises(ValueError):
                        subject.selected_branches(self.data, self.secs)
                finally:
                    self.data[pos] = old
        for name, site, encoded, target in subject.TRANSFERS:
            with self.subTest(kind='transfer', site=hex(site)):
                pos = subject.file_offset(self.secs, site + len(bytes.fromhex(encoded)) - 1, 1, len(self.data), True)
                old = self.data[pos]
                try:
                    self.data[pos] = old ^ 1
                    with self.assertRaises(ValueError):
                        subject.selected_transfers(self.data, self.secs)
                finally:
                    self.data[pos] = old

    def test_jump_table_is_signed_and_mutation_is_rejected(self):
        table = self.records['jump-tables.tsv']
        first = next(r for r in table if r['table'] == 'scheduler_before_poll' and r['index'] == 0)
        self.assertEqual(first['target_va'], '0x1d96547')
        self.assertGreater(first['displacement'], 0)
        self.mutate_va(0x3bce8c)
        with self.assertRaisesRegex(ValueError, 'jump table entry changed'):
            subject.selected_tables(self.data, self.secs)

    def test_operand_and_rip_reference_corruption(self):
        operands = {r['name']: r for r in self.records['operands.tsv']}
        self.assertEqual(operands['replace_destination_ptr']['value_hex'], '0x7620')
        self.assertEqual(operands['task_initial_word']['value_hex'], '0xcc')
        self.assertEqual(operands['bridge_length_offset']['value_hex'], '0x30')
        refs = {r['name']: r for r in self.records['references.tsv']}
        self.assertEqual(refs['task_vtable']['target_va'], '0x56967b0')
        self.mutate_va(0x2021dcf + 3)
        with self.assertRaisesRegex(ValueError, 'RIP reference changed'):
            subject.selected_references(self.data, self.secs)

    def test_operand_corruption(self):
        self.mutate_va(0x22b4d55 + 3)
        with self.assertRaisesRegex(ValueError, 'operand instruction changed'):
            subject.selected_operands(self.data, self.secs)

    def test_relocation_type_symbol_and_addend_corruption(self):
        record = self.relocs[0x56967c8]
        pos = int(record['record_file_offset'], 16)
        for displacement in (8, 12, 16):
            with self.subTest(displacement=displacement):
                old = self.data[pos + displacement]
                try:
                    self.data[pos + displacement] = old ^ 1
                    with self.assertRaises(ValueError):
                        subject.collect_relocations(self.data, self.rela, subject.RELOCATIONS)
                finally:
                    self.data[pos + displacement] = old

    def test_duplicate_and_missing_relocation_rejected(self):
        row = struct.pack('<QQq', 0x1000, 8, 0x2000)
        wanted = {0x1000: ('test_slot', 0x2000)}
        sec = {'type': 4, 'offset': 0, 'size': len(row) * 2}
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            subject.collect_relocations(row * 2, sec, wanted)
        sec['size'] = len(row)
        with self.assertRaisesRegex(ValueError, 'missing'):
            subject.collect_relocations(row, sec, {0x1001: ('other', 0x2000)})
        sec['size'] = 23
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            subject.collect_relocations(row, sec, wanted)

    def test_status_name_and_location_mutations(self):
        self.mutate_va(0x59c148)
        with self.assertRaisesRegex(ValueError, 'descriptor changed'):
            subject.selected_data(self.data, self.secs, self.relocs)

    def test_location_column_mutation(self):
        self.mutate_va(0x56926f8 + 20)
        with self.assertRaisesRegex(ValueError, 'Location changed'):
            subject.selected_data(self.data, self.secs, self.relocs)

    def test_template_mutation(self):
        self.mutate_va(0x1f9c15 + 3)
        with self.assertRaisesRegex(ValueError, 'template changed'):
            subject.selected_data(self.data, self.secs, self.relocs)

    def test_mappings_exclude_nobits_and_detect_ambiguity(self):
        def section(kind, off=0):
            return {'type': kind, 'flags': 4, 'address': 0x100, 'size': 0x10, 'offset': off}
        with self.assertRaisesRegex(ValueError, 'unique'):
            subject.file_offset([section(8)], 0x100, 1, 16, True)
        self.assertEqual(subject.file_offset([section(8), section(1)], 0x102, 2, 16, True), 2)
        with self.assertRaisesRegex(ValueError, 'unique'):
            subject.file_offset([section(1), section(1)], 0x100, 1, 16, True)
        with self.assertRaises(ValueError):
            subject.file_offset([section(1)], 0x10f, 2, 16, True)
        with self.assertRaises(ValueError):
            subject.file_offset([section(1)], 0x100, 0, 16, True)
        with self.assertRaises(ValueError):
            subject.file_offset([section(1)], (1 << 64) - 1, 2, 16)

    def test_selected_no_interleaving_task_transition(self):
        word, index = subject.select_before_poll(0xcc)
        self.assertEqual((word, index), (0xc9, 0))
        completed, payload_retained = subject.selected_finish(word)
        self.assertEqual(completed, 0xca)
        self.assertTrue(payload_retained)
        after_reference_decrement = completed - 0x40
        self.assertNotEqual(after_reference_decrement & 2, 0)
        values = {row['name']: row['unsigned_value'] for row in self.records['operands.tsv']}
        self.assertEqual((values['guard_fast_value'], values['guard_ready_mask']), (1, 2))

    def test_task_boundary_and_negative_routes(self):
        self.assertEqual(subject.select_before_poll(0x24), (0x21, 1))
        self.assertEqual(subject.select_before_poll(0x45), (5, 3))
        self.assertEqual(subject.select_before_poll(0x85), (0x45, 2))
        self.assertEqual(subject.selected_finish(0xc1), (0xc2, False))
        for value in (-1, 0, 5, 1 << 64):
            with self.subTest(word=value), self.assertRaises(ValueError):
                subject.select_before_poll(value)
        for value in (-1, 0, 0xc2, 1 << 64):
            with self.subTest(finish=value), self.assertRaises(ValueError):
                subject.selected_finish(value)

    def test_table_links_are_distinct_and_data_bound(self):
        self.assertEqual(self.relocs[0x56967b0]['addend_va'], '0x22a4270')
        self.assertEqual(self.relocs[0x56967c8]['addend_va'], '0x229f8f0')
        entries = {x['name']: x for x in self.records['transfers.tsv']}
        self.assertEqual(entries['scheduler_thunk']['target_va'], '0x1d964d0')
        self.assertEqual(entries['reader_thunk']['target_va'], '0x1d579c0')
        self.assertEqual(entries['bridge_touch']['target_va'], '0x576f668')
        self.assertEqual(self.relocs[0x576f668]['addend_va'], '0x144fd70')

    def test_path_formatters_share_their_inputs_and_targets(self):
        refs = {row['name']: row['target_va'] for row in self.records['references.tsv']}
        self.assertEqual(refs['factory_config_slot'], refs['host_config_slot'])
        self.assertEqual(refs['factory_config_slot'], refs['previous_config_slot'])
        self.assertEqual(refs['factory_date_formatter_slot'], refs['previous_date_formatter_slot'])
        self.assertEqual(refs['factory_word_formatter_slot'], refs['previous_word_formatter_slot'])
        self.assertEqual(self.relocs[0x576ea60]['addend_va'], '0x1454a00')
        self.assertEqual(self.relocs[0x576ea30]['addend_va'], '0x1570900')
        literals = {row['name']: row['text'] for row in self.records['data.json']['literals']}
        self.assertEqual(literals['date_format'], '%Y%m%d')
        windows = {row['name']: row['scope'] for row in self.records['windows.tsv']}
        self.assertEqual(windows['previous_path_format'], 'prior-boundary')
        self.assertEqual(windows['date_format_boundary'], 'prior-boundary')

    def test_last_reference_reaches_tagged_output_drop(self):
        transfers = {row['name']: row['target_va'] for row in self.records['transfers.tsv']}
        self.assertEqual(transfers['scheduler_drop_task'], '0x1d3bdd0')
        self.assertEqual(transfers['finish_drop_task'], '0x1d3bdd0')
        self.assertEqual(transfers['deallocate_drop_output'], '0x1d38d70')
        operands = {row['name']: row['unsigned_value'] for row in self.records['operands.tsv']}
        self.assertEqual(operands['drop_output_completed_tag'], 1)
        self.assertEqual(operands['drop_task_size'], 0x100)
        self.mutate_va(0x1d38d7d)
        with self.assertRaisesRegex(ValueError, 'operand instruction changed'):
            subject.selected_operands(self.data, self.secs)

    def test_location_and_named_directories(self):
        record = self.records['data.json']
        self.assertEqual((record['location']['line'], record['location']['column']), (250, 32))
        names = [r['text'] for r in record['descriptors']]
        self.assertEqual(names, ['abci_state', 'periodic_abci_states', 'periodic_abci_state_statuses'])
        self.assertEqual(record['location']['source_suffix'], 'base/src/fu.rs')

    def test_failure_literals_are_bound_to_the_selected_branches(self):
        literals = {row['name']: row['text'] for row in self.records['data.json']['literals']}
        self.assertEqual(literals['finish_not_running'], 'assertion failed: prev.is_running()')
        self.assertEqual(literals['finish_already_complete'], 'assertion failed: !prev.is_complete()')
        self.assertEqual(literals['bridge_repeat'], '[internal exception] blocking task ran twice.')
        self.mutate_va(0x7d08c0)
        with self.assertRaisesRegex(ValueError, 'literal changed'):
            subject.selected_data(self.data, self.secs, self.relocs)

    def test_encoded_rows_keep_deterministic_field_order(self):
        rows = self.records['branches.tsv']
        encoded = subject.encode_table(rows)
        decoded = list(csv.DictReader(io.StringIO(encoded.decode()), delimiter='\t'))
        self.assertEqual(len(decoded), len(rows))
        self.assertEqual(decoded[0]['site_va'], rows[0]['site_va'])
        with self.assertRaises(ValueError):
            subject.encode_table([])

    def test_regeneration_matches_in_memory_records(self):
        with TemporaryDirectory() as directory:
            result = subject.generate(Path(directory))
            self.assertEqual(result, self.records['summary.json'])
            self.assertEqual({p.name for p in Path(directory).iterdir()}, set(self.records))
            for name, record in self.records.items():
                with self.subTest(file=name):
                    expected = ((json.dumps(record, indent=2, sort_keys=True) + '\n').encode()
                                if name.endswith('.json') else subject.encode_table(record))
                    self.assertEqual((Path(directory) / name).read_bytes(), expected)


if __name__ == '__main__':
    unittest.main()
