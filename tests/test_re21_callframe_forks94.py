import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import re21_callframe_forks94 as subject
from tools.elf_index import sections
from tools.fde_extents import eh_frame_records


class CallFrameForksEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.load_authenticated()
        cls.secs = sections(cls.data)
        _, fdes = eh_frame_records(cls.data, cls.secs)
        cls.fdes = {f['start']: f for f in fdes}
        cls.rels = subject.relocations(cls.data, cls.secs)
        cls.generated = subject.collect(cls.data)

    @staticmethod
    def rows(text):
        return list(csv.DictReader(io.StringIO(text), delimiter='\t'))

    def test_selected_corpus_and_ownership_boundary(self):
        summary = json.loads(self.generated['summary.json'])
        self.assertEqual(summary['binary_sha256'], subject.DIGEST)
        self.assertEqual(summary['selected_fdes'], 12)
        self.assertEqual(summary['selected_opcode_slots'], 8)
        self.assertEqual(summary['key_lane_rows'], 40)
        selected = {int(r['start_va'], 16) for r in self.rows(self.generated['functions.tsv'])}
        self.assertEqual(selected, set(subject.BODIES))
        self.assertNotIn(0x44bc770, selected)
        self.assertNotIn(0x4c09420, selected)
        self.assertNotIn(0x4dd6ea0, selected)
        self.assertNotIn(0x4e9d2a0, selected)

    def test_artifact_and_all_evidence_match(self):
        packet = subject.ROOT / 'research/work-items/RE-021-callframe-forks-94'
        names = {p.name for p in packet.iterdir() if p.suffix in ('.tsv', '.json')}
        self.assertEqual(names, set(self.generated))
        for name, expected in self.generated.items():
            with self.subTest(name=name):
                self.assertEqual((packet / name).read_bytes(), expected.encode('ascii'))

    def test_hash_failure_and_no_trusted_elf_before_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            damaged = Path(directory) / 'bad-elf'
            damaged.write_bytes(b'\x7fELF' + b'\0' * 60)
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                subject.load_authenticated(damaged)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.collect(self.data[:-1])

    def test_table_slots_and_selector_copy(self):
        table = self.rows(self.generated['opcode-table.tsv'])
        self.assertEqual(len(table), 8)
        for row in table:
            revision = int(row['raw_case'])
            opcode, base = int(row['opcode'], 16), int(row['table_va'], 16)
            self.assertEqual(int(row['slot_va'], 16), base + 8 * opcode)
            info, addend, _ = self.rels[int(row['slot_va'], 16)][0]
            self.assertEqual(info, 8)
            self.assertEqual(addend, subject.TABLES[revision][1][opcode])
        selectors = self.rows(self.generated['selector-boundaries.tsv'])
        self.assertEqual([int(r['raw_case']) for r in selectors], [9, 10, 18])
        self.assertEqual([int(r['copy_size']) for r in selectors], [2048] * 3)
        self.assertEqual(selectors[0]['case_va'], selectors[1]['case_va'])
        self.assertNotEqual(selectors[0]['opcode_table_va'], selectors[2]['opcode_table_va'])

    def test_wrong_relocation_type_target_duplicate_or_missing(self):
        slot = 0x5724658
        info, addend, off = self.rels[slot][0]
        for replacement in ([], [(9, addend, off)], [(info, addend + 1, off)],
                            [(info, addend, off), (info, addend, off)]):
            with self.subTest(replacement=replacement):
                with self.assertRaises(ValueError):
                    subject.rela_at(self.data, {slot: replacement}, slot, addend)

    def test_selector_link_rejects_corrupt_jump_lea_and_copy(self):
        original = subject.read_va
        for target, index in ((0x6f2ab0, 0), (0x44bce6a, 3), (0x44bce71, 1)):
            def corrupt(data, secs, va, size, executable=False, target=target, index=index):
                raw = original(data, secs, va, size, executable)
                if va == target:
                    changed = bytearray(raw)
                    changed[index] ^= 1
                    return bytes(changed)
                return raw
            with self.subTest(target=hex(target)):
                with mock.patch.object(subject, 'read_va', side_effect=corrupt):
                    with self.assertRaises(ValueError):
                        subject.selector_records(self.data, self.secs)

    def test_displacements_are_signed_and_opcode_checked(self):
        self.assertEqual(subject.relative(bytes.fromhex('ebfe'), 0x1000), 0x1000)
        self.assertEqual(subject.relative(bytes.fromhex('e8f6ffffff'), 0x1000), 0xffb)
        self.assertEqual(subject.relative(bytes.fromhex('0f85faffffff'), 0x1000), 0x1000)
        for invalid in (b'', b'\x90\x00', b'\xe8\x00', b'\x0f\x00\0\0\0\0'):
            with self.subTest(raw=invalid.hex()):
                with self.assertRaises(ValueError):
                    subject.relative(invalid, 0x1000)

    def test_transfer_controls_reject_wrong_branch_and_outside_range(self):
        sec = {'type': 1, 'flags': 6, 'address': 0x1000, 'offset': 0, 'size': 5}
        code = bytes.fromhex('e8fbffffff')
        self.assertEqual(subject.transfer(code, [sec], 0x1000, 0x1000)[1], 0x1000)
        with self.assertRaises(ValueError):
            subject.transfer(code, [sec], 0x1000, 0x1001)
        with self.assertRaises(ValueError):
            subject.transfer(code, [sec], 0x1004, 0x1000)
        with self.assertRaises(ValueError):
            subject.transfer(bytes.fromhex('e900000000'), [sec], 0x1000, 0x1000)

    def test_immediate_corruption_is_not_a_new_observation(self):
        sec = {'type': 1, 'flags': 6, 'address': 0x2000, 'offset': 0, 'size': 6}
        raw = bytes.fromhex('483dbc020000')
        self.assertEqual(subject.immediate(raw, [sec], 0x2000, '483d', 4, 700)[1], 700)
        for mutant in (bytes.fromhex('483dbd020000'), bytes.fromhex('483cbc020000')):
            with self.assertRaises(ValueError):
                subject.immediate(mutant, [sec], 0x2000, '483d', 4, 700)
        with self.assertRaises(ValueError):
            subject.immediate(raw, [sec], 0x2000, '483d', 8, 700)

    def test_file_mapping_excludes_nobits_crossing_and_ambiguity(self):
        valid = {'type': 1, 'flags': 6, 'address': 0x4000, 'offset': 2, 'size': 4}
        nobits = {'type': 8, 'flags': 6, 'address': 0x5000, 'offset': 0, 'size': 4}
        self.assertEqual(subject.file_offset([valid, nobits], 0x4001, 3, True), 3)
        for va, size in ((0x4003, 2), (0x5000, 1), (0, 1), (0x4000, 0)):
            with self.subTest(va=va, size=size):
                with self.assertRaises(ValueError):
                    subject.file_offset([valid, nobits], va, size, True)
        with self.assertRaises(ValueError):
            subject.file_offset([valid, dict(valid)], 0x4000, 1, True)
        no_exec = dict(valid, flags=2)
        with self.assertRaises(ValueError):
            subject.file_offset([no_exec], 0x4000, 1, True)

    def test_fde_bytes_and_selected_transfer_destinations(self):
        for row in self.rows(self.generated['functions.tsv']):
            start, end = int(row['start_va'], 16), int(row['end_va'], 16)
            frame = self.fdes[start]
            self.assertEqual(frame['end'], end)
            raw = subject.read_va(self.data, self.secs, start, end - start, True)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row['sha256'])
        for row in self.rows(self.generated['transfers.tsv']):
            raw = bytes.fromhex(row['raw'])
            self.assertEqual(subject.relative(raw, int(row['site_va'], 16)), int(row['target_va'], 16))

    def test_f4_lanes_reverse_twenty_low_bytes_for_both_tables(self):
        rows = self.rows(self.generated['delegate-key-lanes.tsv'])
        for case in (9, 18):
            selected = [row for row in rows if int(row['raw_case']) == case]
            self.assertEqual([int(row['output_lane']) for row in selected], list(range(20)))
            self.assertEqual([int(row['source_word_byte']) for row in selected], list(reversed(range(20))))
            self.assertEqual([int(row['frame_offset'], 16) for row in selected], list(range(0x60, 0x74)))
            raw_word = (9).to_bytes(32, 'little')
            result = bytes(raw_word[int(row['source_word_byte'])] for row in selected)
            self.assertEqual(result, b'\0' * 19 + b'\x09')
            for bit in range(256):
                mutated = bytearray(raw_word)
                mutated[bit // 8] ^= 1 << (bit % 8)
                projected = bytes(mutated[int(row['source_word_byte'])] for row in selected)
                self.assertEqual(projected != result, bit < 160)

    def test_lane_extractor_rejects_load_and_store_corruption(self):
        original = subject.read_va
        args = (0x4c91f01, 0x4c91fc8, 0x4c920a4, 0x4c92150, 0x4c9224d, 0x4c92335)
        for target, index in ((args[0], 0), (args[2], 0), (args[4], 0)):
            def corrupt(data, secs, va, size, executable=False, target=target, index=index):
                raw = original(data, secs, va, size, executable)
                if va == target:
                    altered = bytearray(raw)
                    altered[index] ^= 1
                    return bytes(altered)
                return raw
            with self.subTest(region=hex(target)):
                with mock.patch.object(subject, 'read_va', side_effect=corrupt):
                    with self.assertRaises(ValueError):
                        subject.symbolic_lanes(self.data, self.secs, *args)

    def test_payload_word_mapping_and_length_boundaries(self):
        flow = json.loads(self.generated['delegate-payload-flow.json'])
        self.assertEqual(flow['stack_word_bytes'], 32)
        self.assertEqual(flow['length_word_from_top'], 2)
        self.assertEqual(flow['length_word_low_limb_relative_to_cursor'], -64)
        self.assertEqual(flow['copy_symbol']['name'], 'memcpy')
        self.assertEqual(flow['copy_symbol']['relocation_type'], 6)
        self.assertEqual(len(flow['copy_symbol']['calls']), 3)
        for case in (9, 18):
            rows = [row for row in flow['rows'] if row['raw_case'] == case]
            self.assertEqual([row['word_index'] for row in rows], [0, 1, 2, 3])
            self.assertEqual([int(row['helper_output_offset'], 16) for row in rows], [0, 8, 16, 24])
            self.assertEqual([int(row['frame_offset'], 16) for row in rows], [0x28, 0x30, 0x38, 0x40])
            for length in (0, 1, 212, 213, 214, (1 << 64) - 1):
                helper = bytearray.fromhex('112233445566778899aabbccddeeff00')
                helper.extend(length.to_bytes(8, 'little'))
                helper.extend(bytes.fromhex('fedcba9876543210'))
                frame = bytearray(160)
                for row in rows:
                    src, dst = int(row['helper_output_offset'], 16), int(row['frame_offset'], 16)
                    frame[dst:dst + 8] = helper[src:src + 8]
                self.assertEqual(frame[0x28:0x48], helper)
                self.assertEqual(int.from_bytes(frame[0x38:0x40], 'little'), length)
                self.assertEqual(frame[0x38:0x40] == (213).to_bytes(8, 'little'), length == 213)

    def test_payload_pins_are_file_bytes_and_corruption_is_rejected(self):
        flow = subject.payload_flow(self.data, self.secs)
        self.assertEqual(len(flow['rows']), 8)
        for pin in flow['pins']:
            raw = bytes.fromhex(pin['raw'])
            self.assertEqual(subject.read_va(self.data, self.secs, int(pin['site_va'], 16), len(raw), True), raw)
        original = subject.read_va
        for target, index in ((0x4c91b56, 4), (0x4c91d5f, 4), (0x4c91dea, 3),
                              (0x4c92072, 1), (0x4c921e1, 4), (0x4c92911, 4)):
            def corrupt(data, secs, va, size, executable=False, target=target, index=index):
                raw = original(data, secs, va, size, executable)
                if va == target and len(raw) > index:
                    mutant = bytearray(raw)
                    mutant[index] ^= 1
                    return bytes(mutant)
                return raw
            with self.subTest(site=hex(target)):
                with mock.patch.object(subject, 'read_va', side_effect=corrupt):
                    with self.assertRaises(ValueError):
                        subject.payload_flow(self.data, self.secs)

    def test_copy_binding_rejects_bad_relocation_and_symbol(self):
        slot = 0x576dfe0
        info, addend, offset = self.rels[slot][0]
        for replacement in ([], [(info + 1, addend, offset)], [(info, 1, offset)],
                            [(info | (0xffff << 32), addend, offset)],
                            [(info, addend, offset), (info, addend, offset)]):
            with self.subTest(replacement=replacement):
                with self.assertRaises(ValueError):
                    subject.memcpy_binding(self.data, self.secs, {slot: replacement})
        sections_shifted = [dict(sec, offset=sec['offset'] + 1) if sec['name'] == '.dynstr' else sec
                            for sec in self.secs]
        with self.assertRaisesRegex(ValueError, 'name changed'):
            subject.memcpy_binding(self.data, sections_shifted, self.rels)

    def test_lane_source_and_destinations_are_real_instruction_bytes(self):
        # Every recorded destination for a spill-based lane is the store itself,
        # rather than the preceding stack load.
        rows = self.rows(self.generated['delegate-key-lanes.tsv'])
        for row in rows:
            for field in ('host_store_va', 'frame_store_va'):
                site = int(row[field], 16)
                raw = subject.read_va(self.data, self.secs, site, 2, True)
                self.assertIn(raw, (bytes.fromhex('8844'), bytes.fromhex('8884'), bytes.fromhex('4488')))

    def test_publish_and_exception_landings(self):
        actions = self.rows(self.generated['publications.tsv'])
        self.assertEqual(len(actions), 8)
        for row in actions:
            self.assertEqual((int(row['action_offset'], 16), int(row['action_value'])), (0x188, 0x6c))
            self.assertEqual((int(row['status_offset'], 16), int(row['status_value'])), (0x1f3, 0x20))
        drops = self.rows(self.generated['drop-landings.tsv'])
        self.assertEqual(len(drops), 8)
        for row in drops:
            self.assertEqual(int(row['resume_target_va'], 16), 0x5660110)
            self.assertEqual(int(row['interval_length']), 5)
            self.assertIn('880100006c', row['landing_through_resume'])

    def test_lsda_rejects_bad_encoding_bounds_and_landing(self):
        sec = {'name': '.gcc_except_table', 'type': 1, 'flags': 2, 'address': 0x1000, 'offset': 0, 'size': 8}
        frame = {'start': 0x2000, 'end': 0x2010, 'lsda': 0x1000}
        raw = bytes.fromhex('ffff010400050600')
        out = subject.lsda_records(raw, [sec], frame)
        self.assertEqual(out['entries'][0]['landing_va'], '0x2006')
        for mutant in (bytes.fromhex('feff010400050600'), bytes.fromhex('ffff010400051100'),
                       bytes.fromhex('ffff010400110600'), bytes.fromhex('ffff010500050600')):
            with self.subTest(mutant=mutant.hex()):
                with self.assertRaises(ValueError):
                    subject.lsda_records(mutant, [sec], frame)

    def test_corrupt_landing_shape_is_rejected(self):
        original = subject.read_va
        landing = 0x4c91a97
        def corrupt(data, secs, va, size, executable=False):
            raw = original(data, secs, va, size, executable)
            if va == landing:
                altered = bytearray(raw)
                altered[0] ^= 1
                return bytes(altered)
            return raw
        with mock.patch.object(subject, 'read_va', side_effect=corrupt):
            with self.assertRaisesRegex(ValueError, 'landing publication'):
                subject.collect(self.data)

    def test_missing_duplicate_mismatched_and_corrupt_fde_rejected(self):
        selected = [dict(self.fdes[start]) for start in sorted(subject.BODIES)]
        headers = [{'start': item['start'], 'fde': item['fde']} for item in selected]
        first = selected[0]
        self.assertEqual(len(subject.select_fdes(self.data, self.secs, selected, headers)), 12)
        with self.assertRaises(ValueError):
            subject.select_fdes(self.data, self.secs, selected[1:], headers)
        with self.assertRaises(ValueError):
            subject.select_fdes(self.data, self.secs, selected + [first], headers)
        bad_headers = [dict(item) for item in headers]
        bad_headers[0]['fde'] += 1
        with self.assertRaises(ValueError):
            subject.select_fdes(self.data, self.secs, selected, bad_headers)
        invalid = [dict(item) for item in selected]
        invalid[0]['end'] = invalid[0]['start']
        with self.assertRaises(ValueError):
            subject.select_fdes(self.data, self.secs, invalid, headers)
        original = subject.read_va
        def corrupt(data, secs, va, size, executable=False):
            raw = original(data, secs, va, size, executable)
            if va == first['start']:
                altered = bytearray(raw)
                altered[0] ^= 1
                return bytes(altered)
            return raw
        with mock.patch.object(subject, 'read_va', side_effect=corrupt):
            with self.assertRaisesRegex(ValueError, 'body hash'):
                subject.select_fdes(self.data, self.secs, selected, headers)

    def test_executor_boundary_instruction_corruption(self):
        original = subject.read_va
        def corrupt(data, secs, va, size, executable=False):
            raw = original(data, secs, va, size, executable)
            if va == 0x47f36dc:
                altered = bytearray(raw)
                altered[-1] ^= 1
                return bytes(altered)
            return raw
        with mock.patch.object(subject, 'read_va', side_effect=corrupt):
            with self.assertRaisesRegex(ValueError, 'executor boundary'):
                subject.handoff_boundaries(self.data, self.secs)

    def test_relative_relocations_bind_shared_callbacks(self):
        values = json.loads(self.generated['boundary-relocations.json'])
        self.assertEqual(len(values), 5)
        mapping = {int(x['slot_va'], 16): int(x['addend_va'], 16) for x in values}
        self.assertEqual(mapping[0x5745d68], 0x4da4c60)
        self.assertEqual(mapping[0x5745c18], 0x4da4c60)
        self.assertEqual(mapping[0x5745948], 0x4da6590)
        self.assertEqual(mapping[0x5774df8], 0x4e8f2b0)
        self.assertEqual(mapping[0x5773f40], 0x4e8fcb0)

    def test_no_environment_paths_in_generated_evidence(self):
        banned = tuple(chr(47) + part for part in ('tmp', 'mnt', 'srv', 'home', 'root', 'opt'))
        for name, contents in self.generated.items():
            for prefix in banned:
                with self.subTest(name=name, prefix=prefix):
                    self.assertNotIn(prefix, contents)


    def test_callback_boundaries_and_action_table(self):
        rows = self.rows(self.generated['callback-boundaries.tsv'])
        self.assertEqual(len(rows), 6)
        for row in rows:
            role, case = row['role'], int(row['raw_case'])
            field = int(row['output_offset'], 16)
            expected = {'loop': (0x18, 0x4da4c60), 'child': (0x28, 0x4da4e20),
                        'result': (0x48, 0x4da6590)}[role]
            self.assertEqual((field, int(row['method_va'], 16)), expected)
            self.assertIn(case, (9, 18))
        entry = json.loads(self.generated['action-table-boundary.json'])
        raw = bytes.fromhex(entry['entry_raw'])
        self.assertEqual(int(entry['table_va'], 16) + struct.unpack('<i', raw)[0], 0x47f379e)

    def test_callback_lea_and_relocation_corruption(self):
        original = subject.read_va
        def corrupt(data, secs, va, size, executable=False):
            raw = original(data, secs, va, size, executable)
            if va == 0x4ddd698:
                modified = bytearray(raw)
                modified[3] ^= 1
                return bytes(modified)
            return raw
        with mock.patch.object(subject, 'read_va', side_effect=corrupt):
            with self.assertRaises(ValueError):
                subject.callback_bindings(self.data, self.secs, self.rels)
        changed = dict(self.rels)
        info, addend, offset = changed[0x5745d68][0]
        changed[0x5745d68] = [(info, addend + 1, offset)]
        with self.assertRaises(ValueError):
            subject.callback_bindings(self.data, self.secs, changed)

    def test_handoff_offsets_and_copy_size(self):
        rows = {row['label']: int(row['operand']) for row in self.rows(self.generated['handoff-boundaries.tsv'])}
        self.assertEqual(rows['handler_table_copy_destination'], 0x198)
        self.assertEqual(rows['handler_table_copy_source'], 0x1a8)
        self.assertEqual(rows['handler_table_copy_length'], 0x1000)
        self.assertEqual(rows['handler_callback_destination'], 0xe8)
        # This uses the separately established engine+0x110 handler boundary.
        self.assertEqual(0x110 + rows['handler_table_copy_destination'], rows['engine_loop_table'])
        self.assertEqual(0x110 + rows['handler_callback_destination'] + 0x18, rows['engine_loop_descriptor'])
        self.assertEqual(0x110 + rows['handler_callback_destination'] + 0x28, rows['engine_child_descriptor'])
        self.assertEqual(0x110 + rows['handler_callback_destination'] + 0x48, rows['engine_result_descriptor'])

    def test_frame_layout_for_every_selected_opcode(self):
        rows = self.rows(self.generated['frame-layout.tsv'])
        self.assertEqual(len(rows), 8)
        for row in rows:
            opcode = int(row['opcode'], 16)
            self.assertEqual(int(row['tag']), int(opcode == 0xf4))
            self.assertEqual(int(row['scheme']), {0xf1: 0, 0xf2: 1, 0xf4: 2, 0xfa: 3}[opcode])
            self.assertEqual(int(row['scheme_offset'], 16), 0x9e)
            self.assertEqual(int(row['flag_offset'], 16), 0x9c)
            self.assertEqual(int(row['frame_size']), 160)
            self.assertEqual(row['flag_kind'], 'constant_one' if opcode == 0xfa else 'copied_interpreter_flag')
            if opcode == 0xfa:
                self.assertEqual(row['zero_raw'], '660fefc0')

    def test_frame_layout_rejects_mutated_scheme_flag_and_simd_zero(self):
        original = subject.read_va
        for target, index in ((0x4c9234c, 9), (0x4c92345, 3), (0x4c91937, 0)):
            def corrupt(data, secs, va, size, executable=False, target=target, index=index):
                raw = original(data, secs, va, size, executable)
                if va == target:
                    altered = bytearray(raw)
                    altered[index] ^= 1
                    return bytes(altered)
                return raw
            with self.subTest(site=hex(target)):
                with mock.patch.object(subject, 'read_va', side_effect=corrupt):
                    with self.assertRaises(ValueError):
                        subject.frame_records(self.data, self.secs)

    def test_model_costs_are_bound_to_decoded_immediates(self):
        operands = {r['label']: int(r['value']) for r in self.rows(self.generated['immediates.tsv'])}
        self.assertEqual(subject.price(9, 0xfa, 0), operands['fa9_base_cost'])
        self.assertEqual(subject.price(9, 0xf4, 0), operands['f4_9_base_cost'])
        self.assertEqual(subject.price(9, 0xf1, 0, True), operands['f1_9_value_cost'])
        self.assertEqual(subject.price(9, 0xf1, 0x10000, True), operands['f1_9_value_empty_cost'])
        self.assertEqual(subject.price(9, 0xf2, 0, True), operands['f2_9_value_cost'])
        self.assertEqual(subject.price(18, 0xfa, 0), 2 * operands['fa18_price_low'])
        self.assertEqual(subject.price(18, 0xfa, 0x101), 2 * operands['fa18_price_high'])
        self.assertEqual(subject.price(18, 0xf1, 0, True),
                         2 * operands['f1_18_price_low'] + operands['f1_18_value'])
        self.assertEqual(subject.price(18, 0xf1, 0x10000, True),
                         2 * operands['f1_18_price_low'] + operands['f1_18_value_empty'])

    def test_address09_object_links_to_recovered_lanes(self):
        obj = json.loads(self.generated['object-boundary.json'])
        expected = '00' * 19 + '09'
        self.assertEqual(obj['key_bytes'], expected)
        self.assertEqual(obj['projected_key'], expected)
        self.assertEqual(obj['record_callback_relocation']['addend_va'], '0x4e9d2a0')
        raw_word = bytes.fromhex(obj['key_as_little_endian_stack_word'])
        self.assertEqual(int.from_bytes(raw_word, 'little'), 9)
        self.assertEqual(len(raw_word), 32)

    def test_host_comparison_words_and_corruption(self):
        rows = self.rows(self.generated['host-constants.tsv'])
        self.assertEqual(len(rows), 2)
        joined = bytes.fromhex(''.join(row['raw'] for row in rows))
        self.assertEqual(joined.hex(), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        original = subject.read_va
        def corrupt(data, secs, va, size, executable=False):
            raw = original(data, secs, va, size, executable)
            if va == 0x204be0:
                modified = bytearray(raw)
                modified[-1] ^= 1
                return bytes(modified)
            return raw
        with mock.patch.object(subject, 'read_va', side_effect=corrupt):
            with self.assertRaisesRegex(ValueError, 'comparison constant'):
                subject.host_constants(self.data, self.secs)

    def test_host_class_pins_and_branch_corruption(self):
        observed = json.loads(self.generated['host-classification.json'])
        self.assertEqual((observed['revision_threshold'], observed['old_flag_mask'],
                          observed['old_flag_value']), (4, 12, 8))
        self.assertEqual((observed['secondary_default'], observed['secondary_account_tag']), (2, 3))
        self.assertEqual((observed['class_shift_within_secondary'],
                          observed['secondary_shift_within_return']), (8, 8))
        for branch in observed['branches']:
            self.assertEqual(subject.relative(bytes.fromhex(branch['raw']), int(branch['site_va'], 16)),
                             int(branch['target_va'], 16))
        original = subject.read_va
        for target in (0x44c9f04, 0x44c9f5f, 0x44c9f80, 0x44ca0e8):
            def corrupt(data, secs, va, size, executable=False, target=target):
                raw = original(data, secs, va, size, executable)
                if va == target and size > 2:
                    altered = bytearray(raw)
                    altered[-1] ^= 1
                    return bytes(altered)
                return raw
            with self.subTest(site=hex(target)):
                with mock.patch.object(subject, 'read_va', side_effect=corrupt):
                    with self.assertRaises(ValueError):
                        subject.host_classification(self.data, self.secs)

    def test_host_class_old_and_new_predicate_boundaries(self):
        words = (0, 0, 0, 0)
        empty = bytes.fromhex('c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        for flag in range(256):
            for revision in (0, 4):
                self.assertEqual(subject.project_host_class(revision, flag, empty, words, 0),
                                 (flag & 12) == 8)
        for revision in (5, 255):
            for digest in (bytes(32), empty):
                self.assertTrue(subject.project_host_class(revision, 0xff, digest, words, 0))
                self.assertFalse(subject.project_host_class(revision, 0, digest, words, 1))
                for index in range(4):
                    changed = tuple(int(i == index) for i in range(4))
                    self.assertFalse(subject.project_host_class(revision, 0, digest, changed, 0))
            for bit in range(256):
                altered = bytearray(empty)
                altered[bit // 8] ^= 1 << (bit % 8)
                self.assertFalse(subject.project_host_class(revision, 0, bytes(altered), words, 0))
        for bad_args in ((256, 0, empty, words, 0), (5, -1, empty, words, 0),
                         (5, 0, empty[:-1], words, 0), (5, 0, empty, (0,), 0),
                         (5, 0, empty, words, 1 << 64)):
            with self.assertRaises(ValueError):
                subject.project_host_class(*bad_args)

    def test_host_normal_packing_feeds_selected_charge(self):
        for low in (0, 1, 2, 255):
            for middle in (0, 1, 2, 255):
                for flag in (False, True):
                    result = subject.pack_host_success(low, middle, flag)
                    self.assertEqual(result & 0xff, low)
                    self.assertEqual((result >> 8) & 0xff, middle)
                    self.assertEqual((result >> 16) & 1, flag)
        plain = subject.pack_host_success(0, 2, False)
        flagged = subject.pack_host_success(0, 2, True)
        self.assertEqual(subject.price(18, 0xf1, plain, True), 9100)
        self.assertEqual(subject.price(18, 0xf1, flagged, True), 34100)
        with self.assertRaises(ValueError):
            subject.pack_host_success(256, 0, False)
        with self.assertRaises(ValueError):
            subject.pack_host_success(0, 0, 1)

    def test_sanitized_source_locations_and_corruption(self):
        rows = self.rows(self.generated['source-locations.tsv'])
        self.assertEqual(len(rows), 4)
        self.assertEqual({(int(r['line']), int(r['column'])) for r in rows}, {(42, 18), (117, 9)})
        self.assertTrue(all(r['sanitized_suffix'].startswith('revm-interpreter-15.0.0/') for r in rows))
        original = subject.read_va
        for target, index in ((0x4c91e3e, 3), (0x5743460, 16)):
            def corrupt(data, secs, va, size, executable=False, target=target, index=index):
                raw = original(data, secs, va, size, executable)
                if va == target:
                    modified = bytearray(raw)
                    modified[index] ^= 1
                    return bytes(modified)
                return raw
            with self.subTest(target=hex(target)):
                with mock.patch.object(subject, 'read_va', side_effect=corrupt):
                    with self.assertRaises(ValueError):
                        subject.source_locations(self.data, self.secs, self.rels)


class ChargeProjectionTests(unittest.TestCase):
    def test_old_table_static_or_delegate_cost(self):
        for opcode in (0xf4, 0xfa):
            for host in (0, 1, 0x100, 0x101, 0x200, 0x10000):
                self.assertEqual(subject.price(9, opcode, host), 700)

    def test_new_table_independent_flag_combinations(self):
        for host, expected in ((0, 200), (1, 2700), (0x100, 2700), (0x101, 5200),
                               (0x200, 100), (0x201, 2600)):
            with self.subTest(host=host):
                self.assertEqual(subject.price(18, 0xfa, host), expected)
                self.assertEqual(subject.price(18, 0xf4, host), expected)

    def test_old_and_new_value_branches_and_stipend(self):
        self.assertEqual(subject.price(9, 0xf1, 0, True), 9700)
        self.assertEqual(subject.price(9, 0xf1, 0x10000, True), 34700)
        self.assertEqual(subject.price(9, 0xf2, 0x10000, True), 9700)
        self.assertEqual(subject.price(18, 0xf1, 0, True), 9200)
        self.assertEqual(subject.price(18, 0xf1, 0x10000, True), 34200)
        self.assertEqual(subject.price(18, 0xf2, 0x10000, True), 9200)
        out = subject.project_charge(9, 0xf2, 0, True, 10000, 100)
        self.assertEqual(out['cost'], 9700)
        self.assertEqual(out['forwarded'], 100)
        self.assertEqual(out['parent_remaining'], 200)
        self.assertEqual(out['child_gas'], 2400)

    def test_host_failure_precedes_gas_failure(self):
        self.assertEqual(subject.project_charge(9, 0xfa, 2, False, 0, 0), {'status': 0x65})
        self.assertEqual(subject.project_charge(18, 0xf4, 2, False, 0, 0), {'status': 0x65})
        self.assertEqual(subject.project_charge(9, 0xfa, 0, False, 699, 0), {'status': 0x50})
        self.assertEqual(subject.project_charge(18, 0xfa, 0, False, 199, 0), {'status': 0x50})

    def test_equal_cost_and_forwarding_cap(self):
        result = subject.project_charge(9, 0xfa, 0, False, 700, 9)
        self.assertEqual(result, {'status': 0x20, 'cost': 700, 'forwarded': 0,
                                  'parent_remaining': 0, 'child_gas': 0})
        for available in (1, 63, 64, 65, 1000, (1 << 64) - 701):
            out = subject.project_charge(9, 0xfa, 0, False, available + 700, (1 << 256) - 1)
            cap = available - available // 64
            self.assertEqual(out['forwarded'], cap)
            self.assertEqual(out['parent_remaining'], available - cap)

    def test_all_middle_bytes_and_low_flag_classes(self):
        # Independent table of the four possible second-charge outcomes.
        expected_second = {0: 100, 1: 2600, 2: 0, 3: 2600}
        for middle in range(256):
            second = 0 if middle == 2 else expected_second[middle & 1]
            for low in (0, 1):
                expected_first = (100, 2600)[low]
                word = (middle << 8) | low
                self.assertEqual(subject.price(18, 0xfa, word), expected_first + second)

    def test_projection_rejects_invalid_domains(self):
        for args in ((8, 0xfa, 0, False), (9, 0xff, 0, False), (18, 0xf4, -1, False),
                     (18, 0xf4, 1 << 24, False), (18, 0xf4, 0, 1)):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    subject.price(*args)
        for remaining, request in ((-1, 0), (1 << 64, 0), (0, -1), (0, 1 << 256)):
            with self.assertRaises(ValueError):
                subject.project_charge(9, 0xfa, 0, False, remaining, request)


if __name__ == '__main__':
    unittest.main()
