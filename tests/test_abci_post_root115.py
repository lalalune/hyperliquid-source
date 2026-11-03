"""Target-grounded and adversarial tests for the static post-root extractor."""
import csv
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import abci_post_root115 as re115


def section(address, length, *, offset=0, flags=6, kind=1, name='.text'):
    return {'name': name, 'address': address, 'size': length, 'offset': offset,
            'flags': flags, 'type': kind}


def fixture_lsda(raw):
    return [section(0x500, len(raw), flags=2, name='.gcc_except_table')], {
        'start': 0x100, 'end': 0x110, 'lsda': 0x500}


class GateTests(unittest.TestCase):
    def test_divisibility_matches_independent_modulo(self):
        # Unlike the machine-code model, the oracle uses integer remainder.
        heights = list(range(20002))
        largest = re115.MASK // 10000 * 10000
        heights.extend([largest - 1, largest, largest + 1, re115.MASK,
                        1 << 63, 12345678901234500000, 9999999999999999999])
        for height in heights:
            expected = 'enqueue_then_copy' if height % 10000 == 0 else 'sentinel'
            self.assertEqual(re115.gate_model(height, 0, 0, 0, 0, 0), expected, height)

    def test_multiplier_proof_constants_and_bound(self):
        inverse = 0xd288ce703afb7e91
        bound = 0x68db8bac710cb
        self.assertEqual((625 * inverse) & re115.MASK, 1)
        self.assertEqual(bound, re115.MASK // 10000)
        self.assertLess(bound, 1 << 60)
        self.assertLessEqual(bound * 10000, re115.MASK)
        self.assertGreater((bound + 1) * 10000, re115.MASK)

    def test_sentinel_and_height_short_circuit_every_later_condition(self):
        for height, head in [(1, 0), (10000, re115.SENTINEL),
                             (1, re115.SENTINEL)]:
            self.assertEqual(re115.gate_model(height, head, 0, 1, 0, re115.MASK - 1), 'sentinel')
        self.assertEqual(re115.gate_model(10000, re115.SENTINEL + 1, 0, 0, 0, 0), 'enqueue_then_copy')

    def test_one_flag_bypasses_freeze_assertion_and_queue(self):
        self.assertEqual(re115.gate_model(10000, 0, 1, 1, 0, re115.MASK - 1), 'copy_without_queue')
        self.assertEqual(re115.gate_model(10000, 0, 2, 1, 0, 0), 'assertion')

    def test_freeze_target_order_and_other_tags(self):
        self.assertEqual(re115.gate_model(10000, 0, 0, 1, 9999, 0), 'assertion')
        self.assertEqual(re115.gate_model(10000, 0, 0, 1, 10000, 0), 'copy_without_queue')
        self.assertEqual(re115.gate_model(10000, 0, 0, 1, 10001, 0), 'enqueue_then_copy')
        self.assertEqual(re115.gate_model(10000, 0, 0, 2, 0, 0), 'enqueue_then_copy')

    def test_queue_low_bit_precedes_counter_limit(self):
        self.assertEqual(re115.gate_model(10000, 0, 0, 0, 0, 1), 'copy_closed_queue')
        self.assertEqual(re115.gate_model(10000, 0, 0, 0, 0, re115.MASK), 'copy_closed_queue')
        self.assertEqual(re115.gate_model(10000, 0, 0, 0, 0, re115.MASK - 1), 'counter_failure')
        self.assertEqual(re115.gate_model(10000, 0, 0, 0, 0, re115.MASK - 3), 'enqueue_then_copy')

    def test_reject_invalid_branch_inputs(self):
        for values in [(-1, 0, 0, 0, 0, 0), (1 << 64, 0, 0, 0, 0, 0),
                       (0, -1, 0, 0, 0, 0), (0, 0, 256, 0, 0, 0),
                       (0, 0, 0, 1 << 32, 0, 0), (0, 0, 0, 0, -1, 0),
                       (0, 0, 0, 0, 0, 1 << 64), (True, 0, 0, 0, 0, 0)]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                re115.gate_model(*values)

    def test_aux_zero_minus_head_overflow_only_at_signed_minimum(self):
        sign = 1 << 63
        values = list(range(65537)) + [sign - 1, sign, sign + 1, re115.MASK - 1, re115.MASK]
        for value in values:
            result = (-value) & re115.MASK
            overflow = bool((value & result) & sign)
            self.assertEqual(overflow, value == re115.SENTINEL, value)

    def test_32_byte_equality_changes_at_every_position(self):
        value = bytes(range(32))
        self.assertTrue(re115.equal_saved_digest(value, value))
        for index in range(32):
            changed = bytearray(value)
            changed[index] ^= 1
            self.assertFalse(re115.equal_saved_digest(value, changed), index)
        with self.assertRaises(ValueError):
            re115.equal_saved_digest(value, value[:-1])


class ParserTests(unittest.TestCase):
    def test_mapping_rejects_fileless_and_ambiguous_sections(self):
        regular = section(0x100, 8)
        bss = section(0x100, 8, kind=8)
        self.assertEqual(re115.read_at(b'abcdefgh', [regular, bss], 0x102, 3), b'cde')
        for secs, address, length in [([bss], 0x100, 1),
                                      ([regular, dict(regular)], 0x100, 1),
                                      ([regular], 0xff, 1), ([regular], 0x107, 2),
                                      ([regular], 0x100, 0), ([regular], -1, 1),
                                      ([dict(regular, flags=4)], 0x100, 1)]:
            with self.subTest(secs=secs, address=address, length=length):
                with self.assertRaises(ValueError):
                    re115.read_at(b'abcdefgh', secs, address, length)
        with self.assertRaises(ValueError):
            re115.read_at(b'abc', [regular], 0x102, 3)

    def test_transfer_decoder_controls(self):
        self.assertEqual(re115.decode_transfer(b'\xe8\x10\x00\x00\x00', 0x100), ('call', 0x115))
        self.assertEqual(re115.decode_transfer(b'\xeb\xfe', 0x100), ('jump', 0x100))
        self.assertEqual(re115.decode_transfer(b'\x75\x02', 0x100), ('branch', 0x104))
        self.assertEqual(re115.decode_transfer(b'\xff\x15\x01\x00\x00\x00', 0x100), ('slot_call', 0x107))
        for raw in [b'', b'\x90', b'\xe8\x00', b'\xff\x10\x00\x00\x00\x00']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                re115.decode_transfer(raw, 0x100)

    def test_location_reference_target_and_opcode(self):
        raw = b'\x48\x8d\x15\x11\x00\x00\x00'
        secs = [section(0x100, len(raw))]
        record = re115.checked_location_reference(raw, secs, 0x100, '488d15', 0x118)
        self.assertEqual(record['reference_target_va'], '0x118')
        with self.assertRaises(ValueError):
            re115.checked_location_reference(raw, secs, 0x100, '488d15', 0x119)
        with self.assertRaises(ValueError):
            re115.checked_location_reference(b'\x90' + raw[1:], secs, 0x100, '488d15', 0x118)

    def test_relative_relocations_and_corruption(self):
        record = struct.pack('<QQq', 0x200, 8, 0x1234)
        sec = section(0, len(record), flags=2, kind=4, name='.rela.dyn')
        self.assertEqual(re115.collect_relocations(record, [sec], {0x200: 0x1234})[0][:4],
                         (0x200, 8, 0, 0x1234))
        cases = [struct.pack('<QQq', 0x200, 7, 0x1234),
                 struct.pack('<QQq', 0x200, (1 << 32) | 8, 0x1234),
                 struct.pack('<QQq', 0x200, 8, 0x1235),
                 struct.pack('<QQq', 0x201, 8, 0x1234)]
        for bad in cases:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                re115.collect_relocations(bad, [sec], {0x200: 0x1234})
        with self.assertRaises(ValueError):
            re115.collect_relocations(record * 2, [dict(sec, size=48)], {0x200: 0x1234})
        with self.assertRaises(ValueError):
            re115.collect_relocations(record[:-1], [sec], {0x200: 0x1234})

    def test_lsda_one_row_and_callsite_bounds(self):
        raw = bytes([0xff, 0xff, 1, 4, 2, 3, 8, 0])
        secs, fde = fixture_lsda(raw)
        rows = re115.parse_lsda(raw, secs, fde)
        self.assertEqual((rows[0]['start'], rows[0]['end'], rows[0]['landing'], rows[0]['action']),
                         (0x102, 0x105, 0x108, 0))
        self.assertEqual(re115.callsite_witness(rows, 0x102, 3), rows[0])
        self.assertIsNone(re115.callsite_witness(rows, 0x105, 1))
        with self.assertRaises(ValueError):
            re115.callsite_witness(rows, 0x104, 2)
        with self.assertRaises(ValueError):
            re115.callsite_witness(rows * 2, 0x102, 1)
        self.assertEqual(re115.parse_lsda(raw, secs, dict(fde, lsda=None)), [])

    def test_lsda_rejects_damage_truncation_and_escape(self):
        valid = bytes([0xff, 0xff, 1, 4, 2, 3, 8, 0])
        for bad in [valid[:-1], bytes([0xfe]) + valid[1:],
                    valid[:2] + b'\x02' + valid[3:],
                    valid[:5] + b'\x20' + valid[6:],
                    valid[:6] + b'\x10' + valid[7:]]:
            secs, fde = fixture_lsda(bad)
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                re115.parse_lsda(bad, secs, fde)
        secs, fde = fixture_lsda(valid)
        with self.assertRaises(ValueError):
            re115.parse_lsda(valid, [dict(secs[0], size=30)], fde)
        with self.assertRaises(ValueError):
            re115.parse_lsda(valid, secs, dict(fde, lsda=0x999))

    def test_copy_projection_requires_containment(self):
        self.assertEqual(re115.project_copy(0x28, 0x20, 0x40, 16, 8), 0x48)
        for params in [(0x27, 0x28, 0, 16, 8), (0x2f, 0x20, 0, 16, 2),
                       (0, 0, 0, 4, 0), (-1, 0, 0, 4, 1)]:
            with self.subTest(params=params), self.assertRaises(ValueError):
                re115.project_copy(*params)

    def test_bad_digest_aborts_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            binary = base / 'bad-node'
            binary.write_bytes(b'not the target')
            output = base / 'evidence'
            with patch.object(re115, 'TARGET', binary), self.assertRaises(ValueError):
                re115.main(['--out', str(output)])
            self.assertFalse(output.exists())
        with self.assertRaises(ValueError):
            re115.authenticate(b'bad', re115.TARGET_SHA256, None)
        with self.assertRaises(ValueError):
            re115.check_historical(b'bad')


class AuthenticatedTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A missing target is an error, not a skip or an alternate fixture.
        cls.data = re115.TARGET.read_bytes()
        re115.authenticate(cls.data)
        cls.secs, cls.index = re115.unwind_index(cls.data)
        _, cls.all_fdes = re115.eh_frame_records(cls.data, cls.secs)
        cls.output = re115.generate(cls.data)

    def test_authenticated_target_rejects_a_wrong_digest_of_the_same_size(self):
        with self.assertRaises(ValueError):
            re115.authenticate(self.data, '0' * 64, len(self.data))

    def test_generated_summary_and_locations(self):
        summary = json.loads(self.output['summary.json'])
        self.assertEqual(summary['target_sha256'], re115.TARGET_SHA256)
        self.assertEqual(summary['selected_fdes'], 15)
        self.assertEqual(summary['context_windows'], 22)
        self.assertEqual(summary['transfers'], 100)
        self.assertEqual(summary['decoded_operands'], 130)
        location = json.loads(self.output['location.json'])
        self.assertEqual((location['line'], location['column'], location['comparison_operand']), (123, 37, 1))
        self.assertEqual(location['reference_target_va'], location['address'])

    def test_every_target_fde_hash_rejects_a_changed_byte(self):
        for label, start, end, digest in re115.FDE_PINS:
            raw = re115.read_at(self.data, self.secs, start, end - start)
            secs = [section(start, len(raw))]
            self.assertEqual(re115.check_body(raw, secs, label, start, end, digest)[2], raw)
            bad = bytearray(raw)
            bad[len(bad) // 2] ^= 1
            with self.subTest(label=label), self.assertRaises(ValueError):
                re115.check_body(bad, secs, label, start, end, digest)

    def test_every_context_window_rejects_a_changed_byte(self):
        for label, start, end, digest in re115.CONTEXT_PINS:
            raw = re115.read_at(self.data, self.secs, start, end - start)
            secs = [section(start, len(raw))]
            re115.check_window(raw, secs, label, start, end, digest)
            bad = bytearray(raw)
            bad[len(bad) // 2] ^= 1
            with self.subTest(label=label), self.assertRaises(ValueError):
                re115.check_window(bad, secs, label, start, end, digest)

    def test_every_target_transfer_rejects_corruption(self):
        for label, va, kind, target, expected_hex in re115.TRANSFER_PINS:
            row = re115.checked_transfer(self.data, self.secs, label, va, kind, target, expected_hex)
            raw = bytes.fromhex(row[-1])
            fake = [section(va, len(raw))]
            changed = bytearray(raw)
            changed[-1] ^= 1
            with self.subTest(label=label, damage='displacement'), self.assertRaises(ValueError):
                re115.checked_transfer(changed, fake, label, va, kind, target, expected_hex)
            if kind == 'branch':
                # Invert only the condition and keep the displacement/target.
                changed = bytearray(raw)
                changed[1 if changed[0] == 0x0f else 0] ^= 1
                with self.subTest(label=label, damage='condition'), self.assertRaises(ValueError):
                    re115.checked_transfer(changed, fake, label, va, kind, target, expected_hex)
            changed = bytearray(raw)
            changed[0] = 0xcc
            with self.subTest(label=label, damage='opcode'), self.assertRaises(ValueError):
                re115.checked_transfer(changed, fake, label, va, kind, target, expected_hex)

    def test_every_target_operand_rejects_corruption(self):
        for label, va, pattern, at, width in re115.OPERAND_PINS:
            raw = bytes.fromhex(pattern)
            fake = [section(va, len(raw))]
            re115.checked_operand(raw, fake, label, va, pattern, at, width)
            for index in range(len(raw)):
                changed = bytearray(raw)
                changed[index] ^= 1
                with self.subTest(label=label, byte=index), self.assertRaises(ValueError):
                    re115.checked_operand(changed, fake, label, va, pattern, at, width)

    def test_extent_reconciliation_and_overlap_controls(self):
        label, start, end, digest = re115.FDE_PINS[0]
        fde = next(f for f in self.all_fdes if f['start'] == start)
        header = next(i for i in self.index if i['start'] == start)
        with patch.object(re115, 'FDE_PINS', ((label, start, end, digest),)):
            self.assertEqual(len(re115.selected_fdes(self.data, self.secs, [header], [fde])), 1)
            for headers, fdes in [([], [fde]), ([header, header], [fde]),
                                  ([dict(header, fde=header['fde'] + 1)], [fde]),
                                  ([header], [dict(fde, end=end - 1)]),
                                  ([header], [fde, dict(fde, start=start + 1)])]:
                with self.subTest(headers=headers, fdes=fdes), self.assertRaises(ValueError):
                    re115.selected_fdes(self.data, self.secs, headers, fdes)
            nonexec = [dict(s, flags=s['flags'] & ~4) for s in self.secs]
            with self.assertRaises(ValueError):
                re115.selected_fdes(self.data, nonexec, [header], [fde])

    def test_projected_relationships_and_broken_joins(self):
        rows = [re115.checked_operand(self.data, self.secs, *pin) for pin in re115.OPERAND_PINS]
        joins = re115.build_joins(rows)
        self.assertEqual(joins['task_capture']['saved_task_stack_offset'], '0x10')
        self.assertEqual(joins['task_capture']['pending_pointer_bridge_offset'], '0x30')
        self.assertEqual(joins['task_capture']['pending_row_stride'], '0x68')
        self.assertEqual((joins['gate']['inverse_mod_2_64'], joins['gate']['period']), (625, 10000))
        self.assertEqual((joins['end_result']['tracked_segments'], joins['end_result']['verified_copy_stages']), (5, 2))
        self.assertEqual(joins['end_result']['offset_in_engine_output'], '0x78')
        self.assertEqual(joins['end_result']['mixed_32_offset'], '0x40')
        self.assertEqual(joins['end_result']['raw_32_offset'], '0x60')
        self.assertEqual(joins['builder_heap']['raw_32_offset'], '0x88')
        self.assertEqual(joins['builder_heap']['height_offset'], '0xa8')
        self.assertEqual(joins['builder_heap']['output_record_offset_in_owner'], '0x6b0')
        for name in ['callback_task_apply_reload', 'bridge_task_load', 'bridge_pending_input', 'bridge_pending_save',
                     'bridge_stage_low_dst', 'engine_end_output_offset', 'gate_record_height',
                     'gate_mixed_second', 'builder_raw_second_stage', 'builder_heap_height_stage',
                     'owner_record_mid', 'restart_expected_second', 'restart_computed_second',
                     'gate_multiplier', 'gate_bound', 'aux_bridge_save', 'aux_old_head',
                     'aux_meta_word', 'aux_flag_second', 'aux_input_word_store',
                     'bridge_pending_row_stride', 'bridge_pending_match_offset',
                     'selector_raw_consumer', 'selector_mix_stage_source',
                     'selector_height_read', 'selector_state_pointer',
                     'selector_copy_mixed0_dst', 'engine_copy_raw1_src']:
            broken = [list(row) for row in rows]
            item = next(row for row in broken if row[0] == name)
            item[-1] = hex(int(item[-1], 16) + 1)
            with self.subTest(name=name), self.assertRaises(ValueError):
                re115.build_joins(broken)
        with self.assertRaises(ValueError):
            re115.build_joins(rows + [rows[0]])

    def test_auxiliary_normal_and_unwind_record_stores_match(self):
        rows = re115.checked_aux_replay(self.data, self.secs)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][-1], rows[1][-1])
        base, end = 0x4e3a871, 0x4e3a975
        raw = bytearray(re115.read_at(self.data, self.secs, base, end - base))
        fake = [section(base, len(raw))]
        re115.checked_aux_replay(raw, fake)
        raw[0x4e3a949 - base] ^= 1
        with self.assertRaises(ValueError):
            re115.checked_aux_replay(raw, fake)
        with self.assertRaises(ValueError):
            re115.checked_aux_replay(raw[:-1], [section(base, len(raw) - 1)])

    def test_release_call_is_covered_by_unwind_replay(self):
        rows = list(csv.DictReader(io.StringIO(self.output['unwind-links.tsv'].decode('ascii')),
                                   delimiter='\t'))
        call = next(row for row in rows if row['label'] == 'aux_release_previous')
        self.assertEqual((call['call_va'], call['status'], call['landing_va']),
                         ('0x4e3a86c', 'covered', '0x4e3a949'))
        stores = list(csv.DictReader(io.StringIO(self.output['aux-replay.tsv'].decode('ascii')),
                                     delimiter='\t'))
        self.assertEqual([row['start_va'] for row in stores], ['0x4e3a871', '0x4e3a949'])
        self.assertEqual(stores[0]['bytes'], stores[1]['bytes'])

    def test_output_is_stable_and_contains_no_host_path(self):
        self.assertEqual(set(self.output), {'aux-replay.tsv', 'boundary-relocations.tsv', 'context.tsv', 'functions.tsv',
                                           'joins.json', 'location.json', 'operands.tsv', 'summary.json',
                                           'transfers.tsv', 'unwind-links.tsv', 'unwind.tsv'})
        for name, content in self.output.items():
            with self.subTest(name=name):
                self.assertTrue(content.endswith(b'\n'))
                self.assertNotIn(str(ROOT).encode(), content)


if __name__ == '__main__':
    unittest.main()
