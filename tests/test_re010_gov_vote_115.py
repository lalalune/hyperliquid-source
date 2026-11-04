"""Static extraction and negative controls for the selected node 115 vote path."""
import csv
import io
import json
import unittest
from unittest import mock

from tools import re010_gov_vote_115 as vote


def rows(blob):
    return list(csv.DictReader(io.StringIO(blob.decode()), delimiter='\t'))


class Overlay:
    """Overlay only the requested bytes; do not make another ELF-sized copy."""
    def __init__(self, image, edits):
        self.image = image
        self.edits = edits

    def read(self, va, size, executable=False):
        result = bytearray(self.image.read(va, size, executable))
        for at, byte in self.edits.items():
            if va <= at < va + size:
                result[at - va] = byte
        return bytes(result)

    def offset(self, va, size, executable=False):
        return self.image.offset(va, size, executable)


class TargetEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = vote.BINARY.read_bytes()
        cls.image = vote.Image(cls.data)
        cls.records = vote.build(cls.data)
        cls.summary = json.loads(cls.records['identity.json'])

    def test_target_digest_accepts_authenticated_file(self):
        vote.verify_digest(self.data)

    def test_target_digest_rejects_wrong_expected_hash(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            vote.verify_digest(self.data, '0' * 64)

    def test_generated_file_set_and_counts(self):
        self.assertEqual(set(self.records), {
            'identity.json', 'functions.tsv', 'bodies.tsv', 'windows.tsv',
            'branches.tsv', 'calls.tsv', 'switches.tsv', 'fields.tsv',
            'immediates.tsv', 'decision-path.tsv', 'literals.tsv',
        })
        for key, name in [('selected_fde_count', 'functions.tsv'),
                          ('selected_byte_windows', 'windows.tsv'),
                          ('selected_branch_sites', 'branches.tsv'),
                          ('selected_call_sites', 'calls.tsv'),
                          ('selected_switch_entries', 'switches.tsv'),
                          ('field_descriptors', 'fields.tsv'),
                          ('decision_rows', 'decision-path.tsv'),
                          ('selected_literals', 'literals.tsv')]:
            self.assertEqual(self.summary[key], len(rows(self.records[name])))

    def test_selected_fdes_are_unique_and_bounded(self):
        fdes = rows(self.records['functions.tsv'])
        self.assertEqual(len(fdes), 17)
        self.assertEqual(len({r['start_va'] for r in fdes}), len(fdes))
        for fde in fdes:
            self.assertEqual(int(fde['end_va_exclusive'], 16) - int(fde['start_va'], 16),
                             int(fde['byte_length']))
            self.assertEqual(len(fde['sha256']), 64)

    def test_corrupted_function_body_rejected(self):
        name, start, end, digest = next(x for x in vote.FUNCTIONS if x[0] == 'vote_state_core')
        raw = bytearray(self.image.read(start, end - start, True))
        raw[len(raw) // 2] ^= 1
        with self.assertRaisesRegex(ValueError, 'body digest mismatch'):
            vote.validate_body(name, raw, digest)

    def test_corrupted_fde_extent_rejected_after_digest_gate(self):
        # Exercise the FDE check itself; the production CLI always verifies the
        # complete target digest before attempting to parse the FDE.
        fde_va = int(next(r for r in rows(self.records['functions.tsv'])
                          if r['name'] == 'vote_payload_decoder')['fde_va'], 16)
        off = self.image.offset(fde_va, 16)
        changed = bytearray(self.data)
        changed[off + 12] ^= 1  # first byte of sdata4 PC range
        with mock.patch.object(vote, 'verify_digest', lambda data: None):
            with self.assertRaisesRegex(ValueError, 'FDE range mismatch'):
                vote.build(changed)

    def test_corrupted_field_literal_rejected_after_digest_gate(self):
        # The production digest rejects this first; bypass it to test the
        # independent field-descriptor check against damaged read-only data.
        changed = bytearray(self.data)
        offset = self.image.offset(0x455050, 1)
        changed[offset] ^= 1
        with mock.patch.object(vote, 'verify_digest', lambda data: None):
            with self.assertRaisesRegex(ValueError, 'unexpected field descriptor'):
                vote.build(changed)

    def test_file_backed_rejects_bss(self):
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            self.image.offset(bss['address'], 1)

    def test_address_below_any_section_rejected(self):
        with self.assertRaises(ValueError):
            self.image.offset(0xffffffffffffffff, 1)

    def test_zero_and_overflow_ranges_rejected(self):
        for address, size in ((1, 0), (-1, 1), ((1 << 64) - 1, 2)):
            with self.subTest(address=address, size=size):
                with self.assertRaises(ValueError):
                    vote.file_offset(self.image.sections, address, size)

    def test_ambiguous_section_mapping_rejected(self):
        item = {'type': 1, 'address': 100, 'size': 8, 'offset': 0, 'flags': 4}
        with self.assertRaisesRegex(ValueError, 'uniquely'):
            vote.file_offset([item, dict(item)], 100, 1, True)

    def test_non_executable_section_rejected_as_code(self):
        ro = next(s for s in self.image.sections if s['name'] == '.rodata')
        with self.assertRaisesRegex(ValueError, 'suitable section'):
            self.image.offset(ro['address'], 1, True)

    def test_switch_index_and_target(self):
        switches = rows(self.records['switches.tsv'])
        action = next(r for r in switches if r['name'] == 'action_payload')
        self.assertEqual((int(action['index']), action['target_va']), (50, '0x2b81ad2'))
        validation = next(r for r in switches if r['name'] == 'validation_action')
        self.assertEqual((int(validation['index']), validation['target_va']), (50, '0x36c22a0'))

    def test_negative_switch_index_rejected(self):
        with self.assertRaisesRegex(ValueError, 'index out of bounds'):
            vote.table_entry(self.image, 0x607028, -1, 92)

    def test_upper_bound_switch_index_rejected(self):
        with self.assertRaisesRegex(ValueError, 'index out of bounds'):
            vote.table_entry(self.image, 0x607028, 92, 92)

    def test_corrupt_table_displacement_rejected(self):
        slot = 0x607028 + 50 * 4
        overlay = Overlay(self.image, {slot: 0xff, slot + 1: 0xff, slot + 2: 0xff, slot + 3: 0x7f})
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            vote.table_entry(overlay, 0x607028, 50, 92)

    def test_signature_selector_model_agrees_with_each_table_slot(self):
        entries = [r for r in rows(self.records['switches.tsv']) if r['name'] == 'signature_byte']
        self.assertEqual(len(entries), 29)
        for row in entries:
            value = int(row['index'])
            normalized = vote.signature_selector(value)
            expected = {0: '0x1536b5f', 1: '0x1536b49', None: '0x1536b50'}[normalized]
            with self.subTest(value=value):
                self.assertEqual(row['target_va'], expected)
        self.assertEqual(vote.branch(self.image, 0x1536b52)[1], 0x1536f22)

    def test_corrupt_branch_opcode_rejected(self):
        site = 0x3c34030
        with self.assertRaisesRegex(ValueError, 'unsupported branch'):
            vote.branch(Overlay(self.image, {site: 0x90}), site)

    def test_out_of_range_branch_destination_rejected(self):
        site = 0x3c34030
        overlay = Overlay(self.image, {site+2: 0xff, site+3: 0xff, site+4: 0xff, site+5: 0x7f})
        with self.assertRaisesRegex(ValueError, 'file-backed'):
            vote.branch(overlay, site)

    def test_corrupt_immediate_opcode_rejected(self):
        va = 0x3c343d3
        with self.assertRaisesRegex(ValueError, 'immediate instruction mismatch'):
            vote.immediate(Overlay(self.image, {va: 0x90}), va, '48c1e8', 1)

    def test_corrupt_direct_call_opcode_rejected(self):
        va = 0x3c3423d
        with self.assertRaisesRegex(ValueError, 'unsupported selected call'):
            vote.call(Overlay(self.image, {va: 0x90}), va)

    def test_relative_relocation_target(self):
        target, _ = self.image.relative(0x64e5bc0)
        self.assertEqual(target, 0x3c33f10)

    def test_missing_relocation_rejected(self):
        with self.assertRaisesRegex(ValueError, 'missing relocation'):
            self.image.relative(0)

    def test_nonrelative_relocation_rejected(self):
        slot = 0x64e5bc0
        saved = self.image.relocs[slot]
        try:
            self.image.relocs[slot] = (6, saved[1], saved[2])
            with self.assertRaisesRegex(ValueError, 'not symbol-free'):
                self.image.relative(slot)
        finally:
            self.image.relocs[slot] = saved

    def test_action_name_comparisons_cover_seven_bytes(self):
        first = self.image.read(0x2ba1507, 5, True)[1:]
        second = self.image.read(0x2ba150e, 5, True)[1:]
        def matches(value):
            return len(value) == 7 and value[:4] == first and value[3:] == second
        self.assertTrue(matches(b'govVote'))
        for bad in (b'govVot', b'govVotes', b'GovVote', b'govXote', b'govVotE', b'usdSend'):
            with self.subTest(value=bad):
                self.assertFalse(matches(bad))

    def test_dynamic_symbols_and_invalid_index(self):
        calls = {r['name']: r for r in rows(self.records['calls.tsv'])}
        self.assertEqual(calls['action_box_copy']['dynamic_symbol'], 'memcpy')
        self.assertEqual(calls['tree_shift_keys']['dynamic_symbol'], 'memmove')
        with self.assertRaisesRegex(ValueError, 'index out of bounds'):
            self.image.symbol(1 << 31)

    def test_diagnostic_formats_are_binary_literals(self):
        literals = {r['name']: bytes.fromhex(r['raw_hex']) for r in rows(self.records['literals.tsv'])}
        self.assertIn(b'missing field', literals['payload_missing_format'])
        self.assertIn(b'duplicate field', literals['content_duplicate_format'])
        self.assertEqual(literals['outer_action_field'], b'action')
        self.assertIn(b'duplicate field', literals['outer_duplicate_format'])

    def test_name_and_payload_tag_join(self):
        imms = {r['name']: int(r['value_decimal']) for r in rows(self.records['immediates.tsv'])}
        self.assertEqual(imms['name_ordinal'], 50)
        self.assertEqual(imms['decoded_tag'] - imms['validation_tag_bias'], 50)
        self.assertEqual(imms['context_action_box_size'], 240)

    def test_all_five_names_have_duplicate_and_missing_routes(self):
        fields = rows(self.records['fields.tsv'])
        self.assertEqual([f['name'] for f in fields],
                         ['signatureChainId', 'hyperliquidChain', 'id', 'choice', 'nonce'])
        for row in fields:
            self.assertTrue(row['duplicate_branch_va'])
            self.assertTrue(row['missing_guard_va'])
            self.assertTrue(row['primary_duplicate_branch_va'])
            self.assertTrue(row['primary_missing_guard_va'])
            self.assertEqual(bytes.fromhex(row['literal_hex']).decode(), row['name'])

    def test_validation_arm_is_not_a_function_entry(self):
        switches = rows(self.records['switches.tsv'])
        arm = int(next(r['target_va'] for r in switches if r['name'] == 'validation_action'), 16)
        callsite = next(r for r in rows(self.records['calls.tsv']) if r['name'] == 'validation_vote_body')
        self.assertEqual(arm, 0x36c22a0)
        self.assertGreater(int(callsite['site_va'], 16), arm)
        self.assertEqual(callsite['resolved_target_va'], '0x44f5650')
        self.assertNotEqual(arm, int(callsite['resolved_target_va'], 16))

    def test_parser_to_amount_and_writers_calls(self):
        calls = {r['name']: r for r in rows(self.records['calls.tsv'])}
        expected = {
            'outer_map_action_decode': '0x2b817d0', 'outer_sequence_action_decode': '0x2b817d0',
            'action_call_envelope': '0x1fccd80', 'content_map_name': '0x21dfc90',
            'action_to_primary_payload': '0x20aedb0', 'validation_vote_body': '0x44f5650',
            'validation_first_helper': '0x46e4ce0', 'validation_second_helper': '0x1536a90',
            'context_wrapper_to_core': '0x3c33f10',
            'lookup_amount': '0x4221a90', 'aggregate_amount': '0x434f410',
            'update_cursor_history': '0x4221ca0', 'insert_tree_record': '0x370a660',
            'tree_nonempty_insert': '0x3513d50', 'insert_compact_record': '0x454c990',
        }
        for name, target in expected.items():
            with self.subTest(name=name):
                self.assertEqual(calls[name]['resolved_target_va'], target)

    def test_success_and_early_result_operands(self):
        found = {r['name']: int(r['value_decimal']) for r in rows(self.records['immediates.tsv'])}
        self.assertEqual([found[x] for x in ('proposal_missing', 'duplicate_vote', 'no_amount',
                                             'proposal_expired', 'core_success')],
                         [0x114, 0x115, 0x116, 0x117, 0x1a2])


class StaticModels(unittest.TestCase):
    def test_validation_guard_order_and_success_continuation(self):
        self.assertEqual(vote.validation_prefix(False, True, False, False), 0x93)
        self.assertEqual(vote.validation_prefix(True, True, False, False), 0x15)
        self.assertEqual(vote.validation_prefix(True, False, False, False), 0x60)
        self.assertEqual(vote.validation_prefix(True, False, True, False), 0x90)
        self.assertIsNone(vote.validation_prefix(True, False, True, True))

    def test_signature_selector_boundaries(self):
        expected = {0: 0, 1: 1, 2: None, 26: None, 27: 0, 28: 1,
                    29: None, 34: None, 35: 0, 36: 1, 255: 0}
        for value, result in expected.items():
            with self.subTest(value=value):
                self.assertEqual(vote.signature_selector(value), result)
        for value in (-1, 256, True):
            with self.assertRaises(ValueError):
                vote.signature_selector(value)

    def test_cursor_equal_and_order(self):
        a = (2026, 12, 42)
        self.assertEqual(vote.cursor_cmp(a, a), 0)
        self.assertEqual(vote.cursor_cmp((2026, 12, 41), a), -1)
        self.assertEqual(vote.cursor_cmp((2026, 12, 43), a), 1)

    def test_cursor_signed_first_unsigned_remaining(self):
        self.assertLess(vote.cursor_cmp((0xffffffff, 0, 0), (0, 0, 0)), 0)
        self.assertGreater(vote.cursor_cmp((0, 0xffffffff, 0), (0, 0, 0)), 0)
        self.assertGreater(vote.cursor_cmp((0, 0, 0xffffffff), (0, 0, 0)), 0)

    def test_cursor_invalid_inputs(self):
        for a in ((-1, 0, 0), (0, 1 << 32, 0), (0, 0), (0, 0, 'a')):
            with self.subTest(cursor=a):
                with self.assertRaises(ValueError):
                    vote.cursor_cmp(a, (0, 0, 0))

    def test_cursor_update_retains_the_later_value(self):
        self.assertEqual(vote.updated_cursor((1, 2, 3), (1, 2, 4)), (1, 2, 4))
        self.assertEqual(vote.updated_cursor((1, 2, 4), (1, 2, 3)), (1, 2, 4))
        self.assertEqual(vote.updated_cursor((0xffffffff, 0, 0), (0, 0, 0)), (0, 0, 0))

    def test_sum_empty_zero_and_max(self):
        self.assertEqual(vote.checked_sum([]), 0)
        self.assertEqual(vote.checked_sum([0]), 0)
        self.assertEqual(vote.checked_sum([(1 << 64) - 1]), (1 << 64) - 1)

    def test_sum_overflow_is_not_saturation(self):
        self.assertIsNone(vote.checked_sum([(1 << 64) - 1, 1]))
        self.assertEqual(vote.checked_sum([(1 << 64) - 2, 1]), (1 << 64) - 1)

    def test_sum_invalid_amounts(self):
        for value in (-1, 1 << 64, 1.5, True):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    vote.checked_sum([value])

    def test_bonus_below_and_at_cutoff(self):
        a = (1, 0, 0)
        b = (2, 0, 0)
        self.assertEqual(vote.effective_amount((1 << 62) - 1, a, b),
                         (((1 << 62) - 1) * 4, 'multiply'))
        self.assertEqual(vote.effective_amount(1 << 62, a, b), (1 << 62, 'high_bits_preserve'))

    def test_bonus_expiry_equality_and_absent(self):
        t = (2, 0, 0)
        self.assertEqual(vote.effective_amount(7, t, t), (7, 'clear_or_absent'))
        self.assertEqual(vote.effective_amount(7, (3, 0, 0), t), (7, 'clear_or_absent'))
        self.assertEqual(vote.effective_amount(7, (1, 0, 0), None), (7, 'clear_or_absent'))
        self.assertEqual(vote.effective_amount(7, (0, 0, 0), (0, 4, 4)), (7, 'clear_or_absent'))

    def test_result_precedence(self):
        future = (2, 0, 0)
        now = (3, 0, 0)
        self.assertEqual(vote.vote_decision(False, now, future, True, []), (0x114, None))
        self.assertEqual(vote.vote_decision(True, now, future, True, []), (0x117, None))
        self.assertEqual(vote.vote_decision(True, future, future, True, []), (0x115, None))
        self.assertEqual(vote.vote_decision(True, future, future, False, []), (0x116, None))

    def test_success_amount_and_overflow_result(self):
        now, end = (1, 0, 0), (2, 0, 0)
        self.assertEqual(vote.vote_decision(True, now, end, False, [2, 3], end), (0x1a2, 20))
        self.assertEqual(vote.vote_decision(True, now, end, False, [(1 << 64) - 1, 1]), (0x116, None))


if __name__ == '__main__':
    unittest.main()
