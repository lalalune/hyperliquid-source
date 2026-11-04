"""Static, synthetic and corruption controls for the node 115 preflight packet."""

import json
import struct
import unittest
from unittest import mock

from tools import re21_preflight115 as p


class PreflightEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = p.TARGET.read_bytes()
        p.check_digest(cls.data, p.SHA115)
        cls.secs = p.sections(cls.data)
        cls.outputs = p.generate(cls.data)
        cls.fields = json.loads(cls.outputs['schedule.json'])['allocation_base_fields']
        cls.packet = p.ROOT / 'research/work-items/RE-021-precompile-preflight-115'

    def test_all_generated_files_match_packet(self):
        self.assertEqual(len(self.outputs), 15)
        for name, body in self.outputs.items():
            with self.subTest(name=name):
                self.assertEqual((self.packet / name).read_bytes(), body)

    def test_target_digest_and_bad_digest(self):
        p.check_digest(self.data, p.SHA115)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            p.check_digest(self.data, '0' * 64)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            p.generate(b'not an ELF')

    def test_no_legacy_binary_is_required(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            p.legacy_check(b'not a historical ELF')

    def test_selected_fde_index_and_body_evidence(self):
        functions = json.loads(self.outputs['functions.json'])
        self.assertEqual(len(functions), len(p.FUNCTIONS))
        self.assertEqual({x['start_va'] for x in functions}, {hex(row[1]) for row in p.FUNCTIONS})
        for f in functions:
            self.assertEqual(len(bytes.fromhex(f['raw_bytes'])), f['byte_count'])
            self.assertGreater(len(bytes.fromhex(f['fde_bytes'])), 8)
            self.assertEqual(f['section'], '.text')

    def test_missing_fde_fails_closed(self):
        with mock.patch.object(p, 'eh_frame_records', return_value=({}, [])):
            with self.assertRaisesRegex(ValueError, 'FDE'):
                p.selected_functions(self.data, self.secs)

    def test_duplicate_fde_fails_closed(self):
        _, rows = p.eh_frame_records(self.data, self.secs)
        duplicate = next(x for x in rows if x['start'] == p.FUNCTIONS[0][1])
        with mock.patch.object(p, 'eh_frame_records', return_value=({}, rows + [duplicate])):
            with self.assertRaisesRegex(ValueError, 'FDE'):
                p.selected_functions(self.data, self.secs)

    def test_text_window_mutation_is_rejected(self):
        name, va, text = p.PINS[0]
        _, off, _ = p.mapped(self.data, self.secs, va, 1)
        changed = bytearray(self.data)
        changed[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'window'):
            p.checked_windows(changed, self.secs, ((name, va, text),))

    def test_duplicate_window_name_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            p.checked_windows(self.data, self.secs, (p.PINS[0], p.PINS[0]))

    def test_sections_exclude_nobits_and_reject_ambiguity(self):
        blob = b'abcdefgh'
        file_sec = {'name': '.text', 'type': 1, 'address': 0x1000, 'offset': 0, 'size': 8}
        empty_sec = {'name': '.bss', 'type': 8, 'address': 0x1000, 'offset': 0, 'size': 8}
        self.assertEqual(p.take(blob, [empty_sec, file_sec], 0x1002, 3), b'cde')
        with self.assertRaisesRegex(ValueError, 'non-file-backed'):
            p.take(blob, [empty_sec], 0x1000, 1)
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            p.take(blob, [file_sec, dict(file_sec)], 0x1000, 1)
        with self.assertRaises(ValueError):
            p.take(blob, [file_sec], 0x1007, 2)
        with self.assertRaises(ValueError):
            p.take(blob, [file_sec], -1, 1)
        with self.assertRaises(ValueError):
            p.take(blob, [file_sec], 0x1000, 0)

    def test_real_bss_target_is_not_file_bytes(self):
        with self.assertRaisesRegex(ValueError, 'non-file-backed'):
            p.take(self.data, self.secs, 0x64ffe90, 8)

    def test_branch_decoding_and_corruption(self):
        sec = [{'name': '.text', 'type': 1, 'address': 0x1000, 'offset': 0, 'size': 16}]
        image = bytes.fromhex('e8030000000f8502000000eb00') + bytes(3)
        self.assertEqual(p.branch(image, sec, 0x1000)[0], 0x1008)
        self.assertEqual(p.branch(image, sec, 0x1005)[0], 0x100d)
        self.assertEqual(p.branch(image, sec, 0x100b)[0], 0x100d)
        with self.assertRaises(ValueError):
            p.branch(bytes(16), sec, 0x1000)
        with self.assertRaisesRegex(ValueError, 'destination'):
            p.edge_rows(image, sec, (('bad', 0x1000, 0x1009),))
        with self.assertRaises(ValueError):
            p.branch(image, sec, 0x100f)

    def test_rip_operand_and_corruption(self):
        sec = [{'name': '.text', 'type': 1, 'address': 0x1000, 'offset': 0, 'size': 6}]
        code = bytes.fromhex('ff150a000000')
        spec = (('call', 0x1000, 'ff15', 6, 2, 0x1010),)
        self.assertEqual(p.rip_rows(code, sec, spec)[0]['target_va'], '0x1010')
        with self.assertRaises(ValueError):
            p.rip_rows(bytes.fromhex('ff140a000000'), sec, spec)
        with self.assertRaises(ValueError):
            p.rip_rows(bytes.fromhex('ff150b000000'), sec, spec)

    def test_immediate_values_and_corruption(self):
        rows = p.immediate_rows(self.data, self.secs)
        self.assertEqual({x['name']: x['value'] for x in rows}['auxiliary count overflow shift'], 47)
        name, va, prefix, size, expected = p.IMMEDIATES[0]
        _, off, _ = p.mapped(self.data, self.secs, va + len(bytes.fromhex(prefix)), 1)
        changed = bytearray(self.data)
        changed[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'immediate value'):
            p.immediate_rows(changed, self.secs, ((name, va, prefix, size, expected),))

    def test_relative_relocation_rejects_type_addend_and_duplicates(self):
        row = struct.pack('<QQq', 0x2000, 8, 0x3000)
        sec = [{'name': '.rela.dyn', 'type': 4, 'offset': 0, 'size': len(row)}]
        self.assertEqual(p.relocations(row, sec, {0x2000: 0x3000})[0]['addend_va'], '0x3000')
        for bad in (struct.pack('<QQq', 0x2000, 1, 0x3000),
                    struct.pack('<QQq', 0x2000, 8, 0x3001)):
            with self.subTest(bad=bad.hex()), self.assertRaises(ValueError):
                p.relocations(bad, sec, {0x2000: 0x3000})
        duplicated = [dict(sec[0], size=48)]
        with self.assertRaises(ValueError):
            p.relocations(row + row, duplicated, {0x2000: 0x3000})
        with self.assertRaises(ValueError):
            p.relocations(row, sec, {0x2001: 0x3000})
        with self.assertRaises(ValueError):
            p.relocations(row, [dict(sec[0], size=23)], {0x2000: 0x3000})

    def test_lsda_valid_and_malformed_tables(self):
        hdr, rows = p.parse_lsda(bytes.fromhex('ffff010401020300'), 0x1000, 0x1020)
        self.assertEqual(hdr['callsite_byte_count'], 4)
        self.assertEqual(rows[0]['start_va'], '0x1001')
        self.assertEqual(rows[0]['end_va_exclusive'], '0x1003')
        self.assertEqual(rows[0]['landing_va'], '0x1003')
        for bad in ('', '0000010401020300', 'ffff020401020300',
                    'ffff0104010203', 'ffff010401300300', 'ffff010401022100',
                    'ffff010480808080'):
            with self.subTest(raw=bad), self.assertRaises(ValueError):
                p.parse_lsda(bytes.fromhex(bad), 0x1000, 0x1020)
        with self.assertRaises(ValueError):
            p.parse_lsda(bytes.fromhex('ffff010401020300'), 0x1000, 0x1000)

    def test_selected_exception_intervals_are_inside_fde(self):
        functions = {x['start_va']: x for x in json.loads(self.outputs['functions.json'])}
        for table in json.loads(self.outputs['exceptions.json']):
            f = functions[table['function_va']]
            lo, hi = int(f['start_va'], 16), int(f['end_va_exclusive'], 16)
            for row in table['call_sites']:
                self.assertTrue(lo <= int(row['start_va'], 16) <= int(row['end_va_exclusive'], 16) <= hi)
                if row['landing_va'] is not None:
                    self.assertTrue(lo <= int(row['landing_va'], 16) < hi)

    def test_dispatch_table_and_mutated_cell(self):
        tab = p.gate_table(self.data, self.secs)
        self.assertEqual(len(tab['validation_type_entries']), 5)
        self.assertEqual(tab['default_schedule_selector']['index'], 13)
        _, off, _ = p.mapped(self.data, self.secs, 0x60735c, 1)
        changed = bytearray(self.data)
        changed[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'table'):
            p.gate_table(changed, self.secs)

    def test_schedule_literal_mutation_is_rejected(self):
        _, off, _ = p.mapped(self.data, self.secs, 0x4568c0, 1)
        changed = bytearray(self.data)
        changed[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'coefficient'):
            p.schedule(changed, self.secs)

    def test_recipient_lineage_and_mutated_operand(self):
        rec = p.flow_lineage(self.data, self.secs)
        self.assertEqual(rec['recipient_context_offset'], '0x1dd')
        self.assertEqual(rec['input_pointer_context_offset'], '0x118')
        self.assertEqual(rec['input_length_context_offset'], '0x120')
        self.assertEqual(rec['first_key_frame_offset'], rec['lookup_key_frame_offset'])
        self.assertEqual(rec['first_key_frame_offset'], '0x90')
        self.assertEqual(rec['second_key_frame_offset'], '0xa4')
        _, off, _ = p.mapped(self.data, self.secs, 0x29a30d9 + 4, 1)
        changed = bytearray(self.data)
        changed[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'lineage'):
            p.flow_lineage(changed, self.secs)

    def test_source_suffixes_and_release_identity(self):
        sources = p.source_locations(self.data, self.secs)
        self.assertTrue(all(row['relative_suffix'].startswith('z_vendor/') for row in sources))
        self.assertTrue(any(row['relative_suffix'].endswith('pre_execution.rs') for row in sources))
        anchor = p.identity_anchor(self.data, self.secs)
        self.assertEqual(bytes.fromhex(anchor['key_bytes']), bytes(19) + b'\x09')
        self.assertEqual(anchor['callback_addend_va'], '0x5c165b0')

    def test_address_anchor_wrong_byte(self):
        _, off, _ = p.mapped(self.data, self.secs, 0x64c0750 + 19, 1)
        changed = bytearray(self.data)
        changed[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'anchor'):
            p.identity_anchor(changed, self.secs)

    def test_code_digest_copies_and_mutation(self):
        literals = p.code_digest_literals(self.data, self.secs)
        self.assertEqual(literals['first_comparison_half']['bytes'] +
                         literals['second_comparison_half']['bytes'],
                         literals['default_account_literal']['bytes'])
        _, off, _ = p.mapped(self.data, self.secs, 0x4585a0, 1)
        changed = bytearray(self.data)
        changed[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'literals mismatch'):
            p.code_digest_literals(changed, self.secs)

    def test_membership_layout_and_mutated_bound(self):
        layout = p.membership_layout(self.data, self.secs)
        self.assertEqual(layout['big_endian_suffix'], 9)
        self.assertEqual(layout['zero_prefix_bytes'], 18)
        self.assertEqual(layout['exclusive_suffix_bound'], 300)
        _, off, _ = p.mapped(self.data, self.secs, 0x5bdf987, 1)
        changed = bytearray(self.data)
        changed[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'membership operand'):
            p.membership_layout(changed, self.secs)

    def test_address_09_compact_bit_bound_and_backing(self):
        key = bytes(19) + b'\x09'
        self.assertEqual(p.membership_compact_model(key, 0, 10 << 3, [1 << 9]), 1)
        self.assertEqual(p.membership_compact_model(key, 0, 10 << 3, [0]), 0)
        self.assertEqual(p.membership_compact_model(key, 7, (10 << 3) | 7,
                                                    [0, 1 << 8]), 1)
        with self.assertRaises(IndexError):
            p.membership_compact_model(key, 0, 9 << 3, [0])
        with self.assertRaises(ValueError):
            p.membership_compact_model(key, 7, (10 << 3) | 7, [0])
        with self.assertRaises(ValueError):
            p.membership_compact_model(bytes(18) + b'\x01\x2c', 0, 400 << 3, [0] * 8)
        with self.assertRaises(ValueError):
            p.membership_compact_model(b'\x01' + bytes(18) + b'\x09', 0, 100, [0])

    def test_policy_miss_journal_truth_table(self):
        expected = {(0, 0): 'append-tag-0', (0, 1): 'no-tag-0',
                    (1, 0): 'result-byte-2', (1, 1): 'no-tag-0'}
        for (mode, member), outcome in expected.items():
            with self.subTest(mode=mode, member=member):
                self.assertEqual(p.loader_miss_model(mode, member), outcome)
        for invalid in (-1, 2, True):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                p.loader_miss_model(0, invalid)

    def test_account_hash_against_32_bit_limb_oracle(self):
        def fold(a, b):
            a0, a1 = a & 0xffffffff, a >> 32
            b0, b1 = b & 0xffffffff, b >> 32
            product = a0 * b0 + ((a0 * b1 + a1 * b0) << 32) + (a1 * b1 << 64)
            return (product & p.U64) ^ (product >> 64)
        keys = (bytes(20), bytes(19) + b'\x09', bytes(range(20)), bytes([255]) * 20)
        for key in keys:
            for seed, secret in ((0, 0), (1, 3), (p.U64, p.U64),
                                 (0x12345678abcdef01, 0xfedcba9876543210)):
                with self.subTest(key=key.hex(), seed=seed, secret=secret):
                    first = int.from_bytes(key[:8], 'little') ^ seed
                    second = int.from_bytes(key[8:16], 'little') ^ secret
                    inner = fold(first, second) ^ int.from_bytes(key[16:], 'little')
                    self.assertEqual(p.account_hash_model(key, seed, secret), fold(inner, secret))
        for bad in (b'', bytes(19), bytes(21), '0' * 20):
            with self.subTest(key=bad), self.assertRaises(ValueError):
                p.account_hash_model(bad, 0, 0)
        with self.assertRaises(ValueError):
            p.account_hash_model(bytes(20), -1, 0)

    def test_account_probe_collision_wrap_and_early_empty(self):
        key, other, seed, secret = bytes(19) + b'\x09', bytes(19) + b'\x08', 17, 39
        hashed = p.account_hash_model(key, seed, secret)
        first = hashed & 31
        second_group = (first + 16) & 31
        controls, keys = bytearray([0x80] * 32), [None] * 32
        controls[first] = hashed >> 57
        keys[first] = other
        controls[second_group] = hashed >> 57
        keys[second_group] = key
        self.assertEqual(p.account_probe_model(key, seed, secret, bytes(controls), keys), second_group)
        controls[(first + 15) & 31] = 0xff
        self.assertIsNone(p.account_probe_model(key, seed, secret, bytes(controls), keys))
        controls[(first + 15) & 31] = 0x81
        with self.assertRaises(ValueError):
            p.account_probe_model(key, seed, secret, bytes(controls), keys)
        with self.assertRaises(ValueError):
            p.account_probe_model(key, seed, secret, bytes(15), [None] * 15)
        with self.assertRaises(ValueError):
            p.account_probe_model(key, seed, secret, bytes(16), [None] * 16)

    def test_validation_prefix_boundaries(self):
        self.assertIsNone(p.prefix_model(8, 0, 0, 0))
        self.assertEqual(p.prefix_model(9, 0, 1, 0), (0x21, 0))
        self.assertIsNone(p.prefix_model(10, 1, 0, 0))
        self.assertEqual(p.prefix_model(11, 1, 0, 0), (0x21, 1))
        self.assertIsNone(p.prefix_model(11, 3, 0, 1))
        self.assertEqual(p.prefix_model(255, 2, 1, 1), (0x21, 0))
        for bad in (-1, 256, True):
            with self.subTest(mode=bad), self.assertRaises(ValueError):
                p.prefix_model(bad, 1, 0, 0)

    def test_type_fee_precedence_and_u128_boundaries(self):
        for kind in (0, 1):
            self.assertEqual(p.type_fee_model(kind, 9, 100, 10, True, False), 1)
            self.assertIsNone(p.type_fee_model(kind, 10, 100, 10, True, False))
        for kind in (2, 3, 4):
            self.assertEqual(p.type_fee_model(kind, 9, 11, 10, True, False), 0)
            self.assertEqual(p.type_fee_model(kind, 9, 9, 10, True, False), 1)
            self.assertIsNone(p.type_fee_model(kind, 10, 10, 10, True, False))
            self.assertIsNone(p.type_fee_model(kind, 0, p.U128, 10, False, True))
            self.assertEqual(p.type_fee_model(kind, 1 << 64, (1 << 64) + 1,
                                              0, True, False), 0)
        with self.assertRaises(ValueError):
            p.type_fee_model(5, 0, 0, 0, True, False)
        with self.assertRaises(ValueError):
            p.type_fee_model(2, p.U128 + 1, 0, 0, True, False)

    def test_type3_list_error_order(self):
        valid, invalid = b'\x01' + bytes(31), bytes(32)
        self.assertEqual(p.type3_list_model([], True, 0), 0x13)
        self.assertEqual(p.type3_list_model([invalid], True, 0), 0x16)
        self.assertEqual(p.type3_list_model([valid], True, 0), 0x15)
        self.assertIsNone(p.type3_list_model([valid], True, 1))
        self.assertIsNone(p.type3_list_model([valid], False, 0))
        with self.assertRaises(ValueError):
            p.type3_list_model([b'\x01'], True, 1)

    def test_213_byte_example_is_synthetic(self):
        payload = bytes.fromhex('0000000c') + bytes(208) + b'\x01'
        self.assertEqual(len(payload), 213)
        self.assertEqual(p.cost_model(payload, 0, 0, 0, False, self.fields),
                         {'tokens': 219, 'initial': 21876, 'floor': 23190})
        self.assertEqual(p.admission_model(21876, 23190, 21875, 13), 3)
        self.assertEqual(p.admission_model(21876, 23190, 21876, 13), 4)
        self.assertEqual(p.admission_model(21876, 23190, 23189, 13), 4)
        self.assertEqual(p.admission_model(21876, 23190, 23190, 13), 0x21)

    def test_cost_against_independent_count_formula(self):
        for size in (0, 1, 31, 32, 33, 64, 213, 257):
            payload = bytes((i * 29) % 256 for i in range(size))
            nz = sum(1 for byte in payload if byte != 0)
            z = size - nz
            for create in (False, True):
                with self.subTest(size=size, create=create):
                    expected = 21000 + 4 * z + 16 * nz + 2400 * 2 + 1900 * 3 + 25000
                    if create:
                        expected += 32000 + 2 * ((size + 31) // 32)
                    self.assertEqual(p.cost_model(payload, 2, 3, 1, create, self.fields),
                                     {'tokens': z + 4 * nz, 'initial': expected,
                                      'floor': 21000 + 10 * (z + 4 * nz)})

    def test_cost_invalid_inputs_and_overflow(self):
        for args in ((b'', -1, 0, 0, False), (b'', 0, -1, 0, False),
                     (b'', 0, 0, -1, False), (b'', True, 0, 0, False),
                     ('bad', 0, 0, 0, False), (b'', 0, 0, 0, 1)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                p.cost_model(*args, self.fields)
        for counts in ((p.U64, 0, 0), (0, p.U64, 0), (0, 0, p.U64)):
            with self.subTest(counts=counts), self.assertRaises(OverflowError):
                p.cost_model(b'X', *counts, False, self.fields)

    def test_admission_order_floor_and_ceiling(self):
        self.assertEqual(p.admission_model(100, 150, 99, 13), 3)
        self.assertEqual(p.admission_model(100, 150, 100, 13), 4)
        self.assertEqual(p.admission_model(100, 150, 150, 13), 0x21)
        self.assertEqual(p.admission_model(100, 150, 100, 11), 0x21)
        self.assertEqual(p.admission_model(100, 150, 151, 13, True, 149), 4)
        self.assertEqual(p.admission_model(100, 150, 151, 13, True, 150), 0x21)
        for bad in (-1, p.U64 + 1, True):
            with self.subTest(limit=bad), self.assertRaises(ValueError):
                p.admission_model(0, 0, bad, 13)

    def test_payment_unsigned_width_and_boundaries(self):
        self.assertEqual(p.payment_model(100, 3, 10, 71), (6, None))
        self.assertEqual(p.payment_model(101, 3, 10, 71), (0x21, 71))
        self.assertEqual(p.payment_model(p.U256, 0, p.U128, p.U256), (0x21, p.U256))
        self.assertEqual(p.payment_model(p.U256, 2, p.U128, 0), (7, None))
        self.assertEqual(p.payment_model(p.U256, 1, 1, p.U256), (7, None))
        for bad in (-1, p.U256 + 1, True):
            with self.subTest(balance=bad), self.assertRaises(ValueError):
                p.payment_model(bad, 1, 1, 0)

    def test_payment_against_small_integer_oracle(self):
        for balance in range(0, 32):
            for gas in range(0, 5):
                for cap in range(0, 5):
                    for value in range(0, 5):
                        actual = p.payment_model(balance, gas, cap, value)
                        expected = ((6, None) if balance < gas * cap + value
                                    else (0x21, balance - gas * cap))
                        self.assertEqual(actual, expected)

    def test_payment_adjusted_price_and_cap(self):
        args = (1000, 10, 20, 0, 2, True, 5, 3, 0, 0, False, 0)
        self.assertEqual(p.payment_extended_model(*args), ('return', 0x21, 920))
        args = (1000, 10, 20, 0, 4, True, 19, 10, 0, 0, False, 0)
        self.assertEqual(p.payment_extended_model(*args), ('return', 0x21, 800))
        args = (199, 10, 20, 0, 2, True, 1, 1, 0, 0, False, 0)
        self.assertEqual(p.payment_extended_model(*args), ('return', 6, None))
        args = (p.U256, 1, p.U128, 0, 2, True, p.U64, p.U128, 0, 0, False, 0)
        self.assertEqual(p.payment_extended_model(*args), ('return', 0x21, p.U256 - p.U128))

    def test_payment_type3_auxiliary_requirement_and_charge(self):
        args = (600000, 10, 20, 100, 3, True, 5, 3, 1, 3, True, 2)
        self.assertEqual(p.payment_extended_model(*args), ('return', 0x21, 337776))
        args = (393515, 10, 20, 100, 3, True, 5, 3, 1, 3, True, 2)
        self.assertEqual(p.payment_extended_model(*args), ('return', 6, None))
        args = (p.U256, 0, 0, 0, 3, False, 0, 0, 1, p.U128, True, p.U128)
        self.assertEqual(p.payment_extended_model(*args), ('return', 0x21, p.U256 - p.U128))
        args = (0, 0, 0, 0, 3, False, 0, 0, 1, 0, True, 1)
        self.assertEqual(p.payment_extended_model(*args), ('return', 0x21, 0))

    def test_payment_type3_overflow_order_and_disabled_auxiliary(self):
        args = (p.U256, 0, 0, 0, 3, False, 0, 0, 1 << 47, 0, False, 0)
        self.assertEqual(p.payment_extended_model(*args), ('error-helper', 'count-overflow', None))
        args = (p.U256, 0, 0, p.U256, 3, False, 0, 0, 1, 1, False, 0)
        self.assertEqual(p.payment_extended_model(*args), ('return', 7, None))
        args = (p.U256, 0, 0, p.U256, 3, False, 0, 0, 1, 0, True, 1)
        self.assertEqual(p.payment_extended_model(*args), ('error-helper', 'charge-overflow', None))
        args = (100, 0, 0, 0, 3, False, 0, 0, 1, 0, False, p.U128)
        self.assertEqual(p.payment_extended_model(*args), ('return', 0x21, 100))

    def test_models_reject_noncanonical_types(self):
        with self.assertRaises(ValueError):
            p.payment_model(1, 1, p.U128 + 1, 0)
        with self.assertRaises(ValueError):
            p.payment_model(1, p.U64 + 1, 0, 0)
        with self.assertRaises(ValueError):
            p.admission_model(0, 0, 0, 256)
        with self.assertRaises(ValueError):
            p.prefix_model(1, 1, -1, 0)

    def test_summary_is_local_selection_only(self):
        summary = json.loads(self.outputs['summary.json'])
        self.assertEqual(summary['selected_fde_count'], len(p.FUNCTIONS))
        self.assertEqual(summary['byte_windows'], len(p.PINS))
        self.assertEqual(summary['selected_direct_transfers'], len(p.EDGES))
        self.assertEqual(summary['relative_relocations'], len(p.RELATIVE_SLOTS))
        self.assertEqual(summary['immediate_operands'], len(p.IMMEDIATES))
        self.assertIn('no whole-EVM coverage', summary['scope'])


if __name__ == '__main__':
    unittest.main()
