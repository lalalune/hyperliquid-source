"""Static and synthetic controls for node94 precompile preparation evidence."""
import copy
import csv
import hashlib
import io
import json
import struct
import unittest
from unittest.mock import patch

from tools import precompile_prep94 as p


class StaticEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = p.Image((p.ROOT / 'artifacts/node/94/hl-node').read_bytes())
        cls.output = p.generate(cls.image)

    def altered(self):
        return copy.copy(self.image)

    def test_all_generated_files_match_retained_bytes(self):
        folder = p.ROOT / 'research/work-items/RE-021-precompile-preparation-94'
        self.assertEqual(len(self.output), 17)
        for name, expected in self.output.items():
            with self.subTest(name=name):
                self.assertEqual((folder / name).read_bytes(), expected)

    def test_digest_rejects_corrupted_image(self):
        altered = bytearray(self.image.data)
        altered[0x100] ^= 1
        self.assertNotEqual(hashlib.sha256(altered).hexdigest(), p.TARGET_SHA256)
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            p.Image(altered)

    def test_selected_fdes_match_index_and_do_not_overlap(self):
        for start, (end, _, _) in p.FUNCTIONS.items():
            self.assertEqual(self.image.fdes[start][0]['end'], end)
            for other in self.image.fdes.values():
                for fde in other:
                    if fde['start'] != start:
                        self.assertFalse(fde['start'] < end and start < fde['end'])

    def test_missing_duplicate_or_changed_fde_is_rejected(self):
        start = next(iter(p.FUNCTIONS))
        image = self.altered()
        image.fdes = dict(image.fdes)
        image.fdes[start] = []
        with self.assertRaisesRegex(ValueError, 'missing or duplicate FDE'):
            image.validate_functions()
        image.fdes[start] = [dict(self.image.fdes[start][0]), dict(self.image.fdes[start][0])]
        with self.assertRaisesRegex(ValueError, 'missing or duplicate FDE'):
            image.validate_functions()
        image.fdes[start] = [dict(self.image.fdes[start][0], end=p.FUNCTIONS[start][0]+1)]
        with self.assertRaisesRegex(ValueError, 'changed FDE extent'):
            image.validate_functions()

    def test_missing_or_wrong_unwind_index_is_rejected(self):
        start = next(iter(p.FUNCTIONS))
        image = self.altered()
        image.index = [x for x in self.image.index if x['start'] != start]
        with self.assertRaisesRegex(ValueError, 'not bound by unwind index'):
            image.validate_functions()
        image.index = [dict(x, fde=x['fde']+4) if x['start'] == start else x for x in self.image.index]
        with self.assertRaisesRegex(ValueError, 'not bound by unwind index'):
            image.validate_functions()

    def test_code_corruption_outside_semantic_windows_is_rejected(self):
        image = self.altered()
        orig = image.read
        first = next(iter(p.FUNCTIONS))
        end = p.FUNCTIONS[first][0]
        def corrupt(va, size):
            raw = orig(va, size)
            if va == first and size == end-first:
                return raw[:-1] + bytes([raw[-1] ^ 1])
            return raw
        image.read = corrupt
        with self.assertRaisesRegex(ValueError, 'changed function body'):
            image.validate_functions()

    def test_each_window_rejects_both_end_mutations(self):
        orig = self.image.read
        for owner, start, end, label, expected in p.WINDOWS:
            for idx in (0, end-start-1):
                with self.subTest(label=label, index=idx):
                    def bad(va, size, idx=idx):
                        raw = bytearray(orig(va, size))
                        raw[idx] ^= 1
                        return bytes(raw)
                    with patch.object(self.image, 'read', side_effect=bad):
                        with self.assertRaisesRegex(ValueError, 'window mismatch'):
                            p.verify_window(self.image, owner, start, end, expected)

    def test_window_range_must_stay_inside_fde(self):
        owner = next(iter(p.FUNCTIONS))
        with self.assertRaisesRegex(ValueError, 'window outside'):
            p.verify_window(self.image, owner, owner-1, owner+1, '0000')

    def test_file_backed_ranges_exclude_bss_and_crossings(self):
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        text = next(s for s in self.image.sections if s['name'] == '.text')
        for va, size in ((bss['address'], 1), (text['address']+text['size']-1, 2), (0, 0), (-1, 1), (1 << 64, 1)):
            with self.subTest(va=va, size=size):
                with self.assertRaises(ValueError):
                    self.image.offset(va, size)

    def test_ambiguous_section_mapping_is_rejected(self):
        image = self.altered()
        text = next(s for s in image.sections if s['name'] == '.text')
        image.sections = image.sections + [dict(text)]
        with self.assertRaisesRegex(ValueError, 'no unique'):
            image.read(text['address'], 1)

    def test_relocations_fail_closed(self):
        slot = 0x56be4d8
        info, addend, offset = self.image.relocations[slot]
        for bad in ((7, addend, offset), (info | (1 << 32), addend, offset), (info, addend+1, offset)):
            image = self.altered()
            image.relocations = dict(image.relocations)
            image.relocations[slot] = bad
            with self.assertRaises(ValueError):
                image.relative(slot, 0x276ec80)
        image.relocations.pop(slot)
        with self.assertRaisesRegex(ValueError, 'missing relocation'):
            image.relative(slot)

    def test_generator_rejects_changed_callback_relocation(self):
        image = self.altered()
        image.relocations = dict(image.relocations)
        info, target, off = image.relocations[0x56be508]
        image.relocations[0x56be508] = (info, target+1, off)
        with self.assertRaisesRegex(ValueError, 'wrong payer-precharge callback'):
            p.generate(image)

    def test_rip_displacements_and_wrong_slot(self):
        raw, info, target, _ = p.indirect_target(self.image, 0x279d8b4, 0x5774e70, 0x4ea2ec0)
        self.assertEqual(raw[:2], b'\xff\x15')
        self.assertEqual((info, target), (8, 0x4ea2ec0))
        with self.assertRaisesRegex(ValueError, 'RIP displacement mismatch'):
            p.indirect_target(self.image, 0x279d8b4, 0x5774e78, 0x4ea2ec0)

    def test_direct_transfers_signed_and_corrupt_forms(self):
        self.assertEqual(p.decode_transfer(0x1000, bytes.fromhex('75fc')), ('conditional', 0xffe))
        self.assertEqual(p.decode_transfer(0x1000, bytes.fromhex('e8fbffffff')), ('call', 0x1000))
        for bad in (b'', b'\x90\x00', b'\xe8\x00', b'\x0f\x84\x00'):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    p.decode_transfer(0x1000, bad)

    def test_all_transfers_decode_to_retained_targets(self):
        for site, label, expected, kind, target in p.BRANCHES:
            with self.subTest(label=label):
                self.assertEqual(p.decode_transfer(site, bytes.fromhex(expected)), (kind, target))

    def test_jump_table_byte_corruption_is_rejected(self):
        image = self.altered()
        original = image.read
        def bad(va, size):
            raw = original(va, size)
            if va == 0x3eeb7c:
                return bytes([raw[0] ^ 1]) + raw[1:]
            return raw
        image.read = bad
        with self.assertRaises(ValueError):
            p.generate(image)

    def test_prefix_corruption_is_rejected(self):
        image = self.altered()
        original = image.read
        def bad(va, size):
            if va == 0x7c5417:
                return b'\xef\x02'
            return original(va, size)
        image.read = bad
        with self.assertRaisesRegex(ValueError, 'unexpected delegation prefix'):
            p.generate(image)

    def test_frame_input_to_lookup_key_layout(self):
        rows, metadata = p.frame_layout(self.image)
        entries = {row[0]: row for row in rows}
        self.assertEqual(len(entries), 8)
        self.assertEqual((entries['lookup-key-first16'][3], entries['lookup-key-first16'][4],
                          entries['lookup-key-first16'][8]), ('0x13d', 16, '0x60'))
        self.assertEqual((entries['lookup-key-last4'][3], entries['lookup-key-last4'][4],
                          entries['lookup-key-last4'][8]), ('0x14d', 4, '0x70'))
        self.assertEqual((entries['second-address-first16'][8], entries['second-address-last4'][8]),
                         ('0x74', '0x84'))
        self.assertEqual((entries['payer-first16'][3], entries['payer-first16'][8]), ('0x128', '0x88'))
        self.assertEqual((entries['value-first16'][8], entries['value-last16'][8]), ('0x8', '0x18'))
        self.assertEqual((metadata['argument_variant_offset'], metadata['argument_variant_comparison']),
                         (0x13c, 0))
        self.assertEqual((metadata['frame_scheme_offset'], metadata['scheme_stored_value']), (0x9e, 0))
        self.assertEqual((metadata['allocation_size'], metadata['copy_size'], metadata['frame_tag']),
                         (160, 160, 0))

    def test_frame_mapping_rejects_changed_load_store_or_copy_shape(self):
        original = self.image.read
        for changed_site in (0x4e91cba, 0x4e91cd4, 0x4e91d52, 0x4e91db4, 0x4e91da4, 0x4e91d7b):
            with self.subTest(site=hex(changed_site)):
                def corrupt(va, size):
                    raw = original(va, size)
                    return raw[:-1] + bytes([raw[-1] ^ 1]) if va == changed_site else raw
                with patch.object(self.image, 'read', side_effect=corrupt):
                    with self.assertRaisesRegex(ValueError, 'frame shape mismatch'):
                        p.frame_layout(self.image)

    def test_validation_constructor_pairs_are_resolved_from_bytes(self):
        rows = {row[0]: row for row in p.validation_pairs(self.image)}
        self.assertEqual((rows['intrinsic-gas'][3], rows['intrinsic-gas'][6], rows['intrinsic-gas'][8]),
                         ('0x569c4f8', '0x8', '0x21b85e0'))
        self.assertEqual((rows['payer'][3], rows['payer'][6], rows['payer'][8]),
                         ('0x569c558', '0x18', '0x21b9db0'))
        self.assertEqual((rows['environment'][3], rows['environment'][6], rows['environment'][8]),
                         ('0x569c528', '0x28', '0x21b9430'))

    def test_validation_constructor_rejects_changed_lea_or_store(self):
        original = self.image.read
        for changed_site in (0x21c4d2a, 0x21c4d8f, 0x21c4d97, 0x21c4d9e, 0x21c4d61, 0x21c4da6):
            with self.subTest(site=hex(changed_site)):
                def corrupt(va, size):
                    raw = original(va, size)
                    return raw[:-1] + bytes([raw[-1] ^ 1]) if va == changed_site else raw
                with patch.object(self.image, 'read', side_effect=corrupt):
                    with self.assertRaisesRegex(ValueError, 'validation pair shape mismatch'):
                        p.validation_pairs(self.image)

    def test_dynamic_symbol_and_wrong_kind(self):
        symbol = p.dynamic_symbol(self.image, 0x576dfe0)
        self.assertEqual(symbol['symbol_name'], 'memcpy')
        image = self.altered()
        image.relocations = dict(image.relocations)
        _, addend, off = image.relocations[0x576dfe0]
        image.relocations[0x576dfe0] = (8, addend, off)
        with self.assertRaisesRegex(ValueError, 'not a GLOB_DAT'):
            p.dynamic_symbol(image, 0x576dfe0)

    def test_exception_landing_for_old_code_drop(self):
        lines = self.output['exception-sites.tsv'].decode().splitlines()
        rows = list(csv.DictReader(lines, delimiter='\t'))
        matches = [r for r in rows if r['owner_va'] == '0x279d5e0'
                   and int(r['start_va'],16) <= 0x279d9ba < int(r['end_va'],16)]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['landing_va'], '0x279db37')

    def test_exception_parser_rejects_bad_headers_and_ranges(self):
        class Fake:
            def __init__(self, data): self.data = data
            def named_section(self, name): return {'offset': 0, 'size': len(self.data)}
            def offset(self, va, size): return 0
        fde = {'start': 0x1000, 'end': 0x1004, 'lsda': 0x2000}
        rows, _ = p.exception_table(Fake(bytes.fromhex('ffff010400010100')), fde)
        self.assertEqual((rows[0][3], rows[0][6]), ('0x1000', '0x1001'))
        for raw in ('00ff010400010100', 'ffff020400010100', 'ffff010400090100',
                    'ffff010400010900', 'ffff010800010100'):
            with self.subTest(raw=raw):
                with self.assertRaises((ValueError, IndexError)):
                    p.exception_table(Fake(bytes.fromhex(raw)), fde)

    def test_model_constants_are_pinned_in_target_instructions(self):
        # Fixed opcodes at independently inspected instruction boundaries.
        for site, opcode, expected in (
            (0x4e90367, 0xba, 4), (0x4e9036c, 0xbe, 17),
            (0x4e903d4, 0xba, 2400), (0x4e903ee, 0xba, 1900),
            (0x4e90414, 0xb8, 53000), (0x4e90419, 0xb9, 21000),
            (0x4e90451, 0xb9, 25000), (0x4e90468, 0xb9, 10),
            (0x279da62, 0xb9, 12500),
        ):
            with self.subTest(site=hex(site)):
                raw = self.image.read(site, 5)
                self.assertEqual(raw[0], opcode)
                self.assertEqual(struct.unpack('<I', raw[1:])[0], expected)

    def test_validation_tag_stores_match_individual_target_bytes(self):
        records = list(csv.DictReader(self.output['tag-stores.tsv'].decode().splitlines(), delimiter='\t'))
        by_label = {r['label']: int(r['tag']) for r in records}
        self.assertEqual({k: by_label[k] for k in ('network-mismatch','priority-cap','minimum-price',
            'payer-nonce-above','payer-nonce-below','payer-amount-overflow','payer-insufficient',
            'payer-accepted')}, {'network-mismatch':12,'priority-cap':0,'minimum-price':1,
            'payer-nonce-above':9,'payer-nonce-below':10,'payer-amount-overflow':7,
            'payer-insufficient':6,'payer-accepted':25})

    def test_tables_and_counts_from_bytes(self):
        summary = json.loads(self.output['summary.json'])
        self.assertEqual(summary['selected_fdes'], 20)
        self.assertEqual(summary['selected_code_bytes'], 11745)
        self.assertEqual(summary['authorization_code_tag_window_entries'], 5)
        constants = json.loads(self.output['constants.json'])
        self.assertEqual(constants['constants'][1]['bytes'],
                         constants['constants'][2]['bytes'] + constants['constants'][3]['bytes'])
        self.assertEqual(constants['constants'][-1]['bytes'], 'ef01')


class InstructionDerivedModelTests(unittest.TestCase):
    def test_intrinsic_and_floor_gas_with_full_inputs(self):
        data = bytes.fromhex('0001ff')
        self.assertEqual(p.initial_gas(18, data, [0, 2], False, 2), (79636, 21090))
        self.assertEqual(p.initial_gas(18, data, [0, 2], True, 2), (111638, 21090))

    def test_gas_revision_thresholds(self):
        self.assertEqual(p.initial_gas(8, b'\xff', [], False, 0), (21068, 0))
        self.assertEqual(p.initial_gas(9, b'\xff', [], False, 0), (21016, 0))
        self.assertEqual(p.initial_gas(10, b'', [1], False, 0), (21000, 0))
        self.assertEqual(p.initial_gas(11, b'', [1], False, 0), (25300, 0))
        self.assertEqual(p.initial_gas(1, b'', [], True, 0), (21000, 0))
        self.assertEqual(p.initial_gas(2, b'', [], True, 0), (53000, 0))
        for n, extra in ((0,0),(1,2),(31,2),(32,2),(33,4)):
            a, _ = p.initial_gas(15, bytes(n), [], True, 0)
            b, _ = p.initial_gas(16, bytes(n), [], True, 0)
            self.assertEqual(b-a, extra)
        self.assertEqual(p.initial_gas(17, b'', [], False, 1), (21000, 0))
        self.assertEqual(p.initial_gas(18, b'', [], False, 1), (46000, 21000))

    def test_gas_limit_order_and_equality(self):
        initial, floor = p.initial_gas(18, b'\xff', [], False, 0)
        self.assertEqual((initial, floor), (21016, 21040))
        self.assertEqual(p.gas_limit_decision(initial-1, initial, floor), 3)
        self.assertEqual(p.gas_limit_decision(initial, initial, floor), 4)
        self.assertEqual(p.gas_limit_decision(floor-1, initial, floor), 4)
        self.assertEqual(p.gas_limit_decision(floor, initial, floor), 5)

    def test_gas_overflow_and_invalid_domain(self):
        with self.assertRaises(ValueError): p.initial_gas(18, b'', [p.U64_MAX], False, 0)
        with self.assertRaises(ValueError): p.initial_gas(18, b'', [], False, p.U64_MAX)
        with self.assertRaises(ValueError): p.initial_gas(256, b'', [], False, 0)
        with self.assertRaises(ValueError): p.gas_limit_decision(-1, 0, 0)

    def test_authorization_order_and_nonfatal_skips(self):
        def gate(**changes):
            v = dict(chain=10, network=10, nonce=1, recovered_tag=0, account_result=5,
                     code_tag=0, code_length=0, code_bound=0, account_nonce=1)
            v.update(changes)
            return p.authorization_decision(**v)
        self.assertEqual(gate(), 'apply')
        self.assertEqual(gate(chain=0), 'apply')
        self.assertEqual(gate(chain=11, recovered_tag=1), 'skip-chain')
        self.assertEqual(gate(nonce=p.U64_MAX, recovered_tag=1), 'skip-nonce-maximum')
        self.assertEqual(gate(recovered_tag=1, account_result=4), 'skip-recovery')
        self.assertEqual(gate(account_result=4), 'account-error')
        self.assertEqual(gate(code_tag=1, code_length=2, code_bound=1), 'bounds-failure')
        self.assertEqual(gate(code_tag=2, code_length=1), 'skip-code')
        self.assertEqual(gate(account_nonce=2), 'skip-nonce-mismatch')
        self.assertEqual(gate(code_tag=3, code_length=10), 'apply')
        self.assertEqual(gate(code_tag=4, code_length=10), 'apply')
        with self.assertRaises(ValueError): gate(code_tag=5)

    def test_existing_account_predicate(self):
        empty = bytes.fromhex('c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        zero = bytes(32)
        self.assertFalse(p.count_existing(zero, empty, 0, 0))
        self.assertFalse(p.count_existing(empty, empty, 0, 0))
        self.assertTrue(p.count_existing(empty, empty, 1, 0))
        self.assertTrue(p.count_existing(zero, empty, 0, 1))
        self.assertTrue(p.count_existing(bytes([1])+bytes(31), empty, 0, 0))
        with self.assertRaises(ValueError): p.count_existing(b'bad', empty, 0, 0)

    def test_precharge_saturation_nonce_and_modular_price(self):
        def calc(**changes):
            v = dict(balance=1000, gas=10, cap=20, base=7, priority=6, price_kind=1,
                     auxiliary_present=True, auxiliary_price=3, auxiliary_count=0,
                     nonce=4, call_variant=1)
            v.update(changes)
            return p.precharge(**v)
        self.assertEqual(calc(), {'price':13, 'charge':130, 'balance':870, 'nonce':5})
        self.assertEqual(calc(base=19)['price'], 20)
        self.assertEqual(calc(balance=100)['balance'], 0)
        self.assertEqual(calc(nonce=p.U64_MAX)['nonce'], p.U64_MAX)
        self.assertEqual(calc(call_variant=0)['nonce'], 4)
        self.assertEqual(calc(gas=2, cap=p.U256_MAX, price_kind=0)['charge'], p.U256_MAX)
        self.assertEqual(calc(base=p.U256_MAX, priority=1)['price'], 0)
        self.assertEqual(calc(auxiliary_count=1)['charge'], 130 + 3*(1 << 17))
        with self.assertRaises(ValueError): calc(auxiliary_present=False)
        with self.assertRaises(ValueError): calc(auxiliary_count=1 << 47)

    def test_authorization_refund_boundaries(self):
        self.assertEqual(p.authorization_refund(0), 0)
        self.assertEqual(p.authorization_refund(2), 25000)
        n = p.U64_MAX // 12500
        self.assertEqual(p.authorization_refund(n), n * 12500)
        with self.assertRaises(ValueError): p.authorization_refund(n+1)

    def test_payer_validation_order_override_and_boundaries(self):
        def validate(**changes):
            args = dict(code_check_disabled=False, code_tag=0, code_length=0, code_bound=0,
                        requested_nonce=3, account_nonce=3, gas_limit=5, cap=10, value=3,
                        auxiliary_cost=2, balance=55, balance_override=False)
            args.update(changes)
            return p.payer_validation(**args)
        self.assertEqual(validate(), (25,55))
        self.assertEqual(validate(balance=54), (6,54))
        self.assertEqual(validate(balance=54,balance_override=True), (25,55))
        self.assertEqual(validate(requested_nonce=2), (10,55))
        self.assertEqual(validate(requested_nonce=4), (9,55))
        self.assertEqual(validate(code_length=1,requested_nonce=2), (5,55))
        self.assertEqual(validate(code_tag=3,code_length=1), (25,55))
        self.assertEqual(validate(code_tag=4), ('bounds-or-invariant-failure',55))
        self.assertEqual(validate(code_tag=4,code_check_disabled=True), (25,55))
        self.assertEqual(validate(code_tag=1,code_length=2,code_bound=1), ('bounds-or-invariant-failure',55))
        self.assertEqual(validate(gas_limit=2,cap=p.U256_MAX), (7,55))
        self.assertEqual(validate(gas_limit=1,cap=p.U256_MAX,value=1,auxiliary_cost=0), (7,55))
        self.assertEqual(validate(gas_limit=0,value=0,auxiliary_cost=p.U256_MAX,balance=p.U256_MAX),
                         (25,p.U256_MAX))

    def test_delegation_prefix_and_every_address_byte(self):
        prefix = bytes.fromhex('ef01')
        address = bytes(19) + b'\x09'
        expected = prefix + b'\x00' + address
        self.assertEqual(p.delegation_bytes(prefix, address), expected)
        for bit in range(160):
            changed = bytearray(address)
            changed[bit // 8] ^= 1 << (bit % 8)
            self.assertNotEqual(p.delegation_bytes(prefix, bytes(changed)), expected)
        with self.assertRaises(ValueError): p.delegation_bytes(b'\xef\x02', address)
        with self.assertRaises(ValueError): p.delegation_bytes(prefix, address[:-1])


if __name__ == '__main__':
    unittest.main()
