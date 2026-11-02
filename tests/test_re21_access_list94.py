"""Static controls for the node #94 access-list preparation packet."""
import csv
import hashlib
import io
from pathlib import Path
import struct
import unittest

from tools import re21_access_list94 as r

EVIDENCE = r.ROOT / 'research/work-items/RE-021-access-list-preparation-94'


def tsv(blob):
    return list(csv.DictReader(io.StringIO(blob.decode('utf-8')), delimiter='\t'))


def independent_fold(a, b):
    mask32 = (1 << 32) - 1
    a0, a1 = a & mask32, a >> 32
    b0, b1 = b & mask32, b >> 32
    product = a0*b0 + ((a0*b1 + a1*b0) << 32) + ((a1*b1) << 64)
    return (product & r.MASK64) ^ (product >> 64)


def independent_slot_hash(raw, seed, secret0, secret1):
    number = int.from_bytes(raw, 'big')
    limbs = [(number >> (64*i)) & r.MASK64 for i in range(4)]
    x = independent_fold(limbs[3] ^ secret0, limbs[1] ^ secret1)
    y = independent_fold(limbs[0] ^ seed, limbs[2] ^ secret0)
    return independent_fold(x ^ y ^ 4, secret0)


def minimum_buckets(request):
    buckets = 4
    while True:
        capacity = buckets - 1 if buckets < 8 else buckets - buckets // 8
        if capacity >= request:
            return buckets
        buckets *= 2


class StaticEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = r.TARGET.read_bytes()
        r.authenticate(cls.data)
        cls.sec = r.sections(cls.data)
        cls.output = r.collect(cls.data)
        cls.instructions = {int(row['site_va'], 16): {'site': int(row['site_va'], 16),
                            'raw': bytes.fromhex(row['bytes']),
                            'kind': row['kind']}
                            for row in tsv(cls.output['instructions.tsv'])}

    def test_digest_is_exact(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), r.DIGEST)
        with self.assertRaisesRegex(ValueError, 'digest'):
            r.authenticate(self.data, '0' * 64)
        with self.assertRaisesRegex(ValueError, 'digest'):
            r.authenticate(b'corrupt image')

    def test_reproduced_files_match_packet(self):
        self.assertEqual(len(self.output), 15)
        for name, contents in self.output.items():
            with self.subTest(name=name):
                self.assertEqual((EVIDENCE / name).read_bytes(), contents)

    def test_selected_function_extents_and_returns(self):
        rows = tsv(self.output['functions.tsv'])
        self.assertEqual(len(rows), 47)
        actual = {row['start_va']: int(row['size']) for row in rows}
        for start, size in {'0x276fa70': 69, '0x27712d0': 69,
                            '0x2776950': 69, '0x278ed50': 3023,
                            '0x4e742e0': 1904}.items():
            self.assertEqual(actual[start], size)
        transfers = tsv(self.output['control-flow.tsv'])
        returns = [x['site_va'] for x in transfers
                   if x['fde_start'] == '0x278ed50' and x['kind'] == 'return']
        self.assertEqual(returns, ['0x278f8aa'])

    def test_descriptor_relocations(self):
        rows = tsv(self.output['descriptor.tsv'])
        self.assertEqual([(x['method_offset'], x['rela_addend_va']) for x in rows],
                         [('0x18', '0x2776950'), ('0x20', '0x27712d0'),
                          ('0x28', '0x276fa70')])
        self.assertTrue(all(x['file_bytes'] == '00' * 8 for x in rows))

    def test_all_selected_revision_descriptor_families(self):
        rows = tsv(self.output['revision-descriptors.tsv'])
        groups = {int(x['context_byte']): x for x in rows}
        self.assertEqual(sorted(groups), [0, 2, 4, 5, 6, 8, 9, 11, 12, 15, 16, 17, 18, 19, 255])
        methods = tsv(self.output['revision-methods.tsv'])
        self.assertEqual(len(methods), 45)
        for rev, row in groups.items():
            expected_calls = 0 if rev < 16 else 1 if rev < 18 else 2
            self.assertEqual(int(row['prior_set_calls']), expected_calls)
            if expected_calls == 2:
                self.assertEqual(row['fixed_key_va'], '0x3f040f')
                self.assertEqual(row['fixed_key_hex'], '25a219378dad9b3503c8268c9ca836a52427a4fb')
            else:
                self.assertEqual(row['fixed_key_va'], '')
        self.assertEqual(groups[9]['descriptor_va'], '0x56becf0')
        for rev in groups:
            family = [x for x in methods if int(x['context_byte']) == rev]
            self.assertEqual(len({x['masked_shape_sha256'] for x in family}), 1)
            self.assertEqual(len({x['raw_sha256'] for x in family}), 3)

    def test_changed_wrapper_revision_breaks_descriptor_grouping(self):
        data = bytearray(self.data)
        pos = r.offset_for(self.sec, 0x276fa78, 7, True)
        data[pos + 6] = 8
        with self.assertRaisesRegex(ValueError, 'descriptor does not have three methods'):
            r.selected_fdes(data, self.sec)

    def test_changed_wrapper_result_breaks_family_byte_shape(self):
        data = bytearray(self.data)
        pos = r.offset_for(self.sec, 0x276fa90, 3, True)
        data[pos + 2] = 4
        with self.assertRaisesRegex(ValueError, 'descriptor method byte shapes differ'):
            r.selected_fdes(data, self.sec)

    def test_relative_relocation_rejects_wrong_type_symbol_and_addend(self):
        valid = {'type': 8, 'symbol': 0, 'addend': 0x276fa70}
        self.assertIs(r.validate_relative(valid, 0x276fa70), valid)
        for field, value in [('type', 6), ('symbol', 1), ('addend', 0x276fa71)]:
            with self.subTest(field=field):
                bad = dict(valid, **{field: value})
                with self.assertRaises(ValueError):
                    r.validate_relative(bad, 0x276fa70)

    def test_duplicate_and_missing_relocations_rejected(self):
        entry = struct.pack('<QQq', 0x100, 8, 0x200)
        sec = [{'type': 4, 'offset': 0, 'size': len(entry)*2}]
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            r.scan_relocations(entry + entry, sec, {0x100})
        with self.assertRaisesRegex(ValueError, 'missing'):
            r.scan_relocations(entry + entry, sec, {0x101})
        with self.assertRaisesRegex(ValueError, 'truncated'):
            r.scan_relocations(entry, [{'type': 4, 'offset': 0, 'size': 23}], {0x100})

    def test_file_mapping_rejects_nobits_crossing_and_ambiguity(self):
        s = [{'type': 1, 'flags': 6, 'address': 100, 'offset': 10, 'size': 20}]
        self.assertEqual(r.offset_for(s, 101, 3, True), 11)
        with self.assertRaises(ValueError):
            r.offset_for(s, 119, 2)
        with self.assertRaises(ValueError):
            r.offset_for(s + [dict(s[0])], 101, 1)
        with self.assertRaises(ValueError):
            r.offset_for([dict(s[0], type=8)], 101, 1)
        with self.assertRaises(ValueError):
            r.offset_for([dict(s[0], flags=2)], 101, 1, True)
        with self.assertRaises(ValueError):
            r.offset_for(s, (1 << 64)-1, 2)
        bss = next(x for x in self.sec if x['name'] == '.bss')
        with self.assertRaises(ValueError):
            r.read_va(self.data, self.sec, bss['address'] + 0x100, 8)

    def test_shape_pin_detects_changed_code_byte(self):
        data = bytearray(self.data)
        pos = r.offset_for(self.sec, 0x278f713, 5, True)
        data[pos+4] ^= 1
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            r.check_pins(data, self.sec)

    def test_branch_destination_and_opcode_corruption(self):
        rows = r.inspect_decisions(self.instructions)
        self.assertEqual(len(rows), 29)
        bad = dict(self.instructions)
        row = dict(bad[0x278f46d])
        row['raw'] = row['raw'][:-1] + bytes([row['raw'][-1] ^ 1])
        bad[0x278f46d] = row
        with self.assertRaisesRegex(ValueError, 'branch'):
            r.inspect_decisions(bad)
        # A branch can retain its destination while reversing its predicate.
        bad = dict(self.instructions)
        row = dict(bad[0x278f46d])
        row['raw'] = bytes([row['raw'][0] ^ 1]) + row['raw'][1:]
        bad[0x278f46d] = row
        with self.assertRaisesRegex(ValueError, 'branch condition'):
            r.inspect_decisions(bad)
        bad = dict(self.instructions)
        bad.pop(0x278f46d)
        with self.assertRaisesRegex(ValueError, 'no instruction'):
            r.inspect_decisions(bad)

    def test_decoder_rejects_truncation_and_mid_instruction_branch(self):
        for data in (b'\x0f', b'\xe8\x01', b'\x0f\xff'):
            with self.subTest(data=data.hex()):
                with self.assertRaises(ValueError):
                    r.decode_stream(data, 0x1000)
        with self.assertRaisesRegex(ValueError, 'branch into instruction'):
            r.decode_stream(b'\xeb\xff\xc3', 0x1000)
        row = r.decode_stream(b'\xeb\x00\xc3', 0x1000)[0]
        self.assertEqual(r.transfer(row), ('jmp_rel8', 0x1002, None))

    def test_control_call_target_is_relocation_backed(self):
        row = next(x for x in tsv(self.output['control-flow.tsv'])
                   if x['site_va'] == '0x278f81e')
        self.assertEqual((row['kind'], row['slot_va']), ('call_indirect', '0x5773780'))
        rel = next(x for x in tsv(self.output['relocations.tsv'])
                   if x['slot_va'] == row['slot_va'])
        self.assertEqual((rel['type'], rel['addend']), ('8', '0x4e742e0'))
        calls = {x['site_va']: x for x in tsv(self.output['calls.tsv'])}
        self.assertEqual(calls['0x278f81e']['resolved_target_va'], '0x4e742e0')
        for site in ('0x276fa85', '0x27712e5', '0x2776965'):
            self.assertEqual(calls[site]['resolved_target_va'], '0x278ed50')
        self.assertEqual(calls['0x278ee3c']['resolved_target_va'], '0x27c4370')

    def test_layout_is_derived_from_selected_operands(self):
        layout = {row['field']: int(row['value']) for row in tsv(self.output['layout.tsv'])}
        self.assertEqual(layout['context environment pointer'], 0xd8)
        self.assertEqual((layout['environment outer pointer'], layout['environment outer count']),
                         (0x1f0, 0x1f8))
        self.assertEqual((layout['outer entry stride'], layout['outer address offset']), (48, 24))
        self.assertEqual((layout['outer slot pointer offset'], layout['outer slot count offset']), (8, 16))
        self.assertEqual((layout['account bucket stride'], layout['slot bucket stride']), (208, 104))
        self.assertEqual((layout['slot input advance'], layout['slot state offset']), (32, 96))
        self.assertEqual((layout['normal result byte'], layout['revision byte']), (5, 9))

    def test_exception_table_and_corrupt_header(self):
        import json
        saved = json.loads(self.output['exceptions.json'])
        self.assertEqual(len(saved['entries']), 12)
        match = next(e for e in saved['entries'] if e['start_va'] == '0x278f1d4')
        self.assertEqual(match['landing_va'], '0x278f901')
        fde = {'start': 0x278ed50, 'end': 0x278f91f, 'lsda': 0xa2399c}
        changed = bytearray(self.data)
        changed[r.offset_for(self.sec, fde['lsda'], 1)] ^= 1
        with self.assertRaisesRegex(ValueError, 'LSDA'):
            r.read_lsda(changed, self.sec, fde, set(self.instructions))

    def test_symbols_and_sht_nobits_seed(self):
        rels = tsv(self.output['relocations.tsv'])
        copy = next(x for x in rels if x['slot_va'] == '0x576dfe0')
        self.assertEqual((copy['type'], copy['symbol_name']), ('6', 'memcpy'))
        secret = next(x for x in rels if x['slot_va'] == '0x576e3e0')
        bss = next(x for x in self.sec if x['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        self.assertTrue(bss['address'] <= int(secret['addend'], 16) < bss['address'] + bss['size'])


class SyntheticModelTests(unittest.TestCase):
    def test_slot_byte_order(self):
        slot = bytes(range(32))
        self.assertEqual(r.normalized_slot(slot), int.from_bytes(slot, 'big').to_bytes(32, 'little'))
        for value in (b'', bytes(31), bytes(33), 'not bytes'):
            with self.assertRaises(ValueError):
                r.normalized_slot(value)

    def test_full_slot_hash_against_independent_limb_multiplication(self):
        raw = bytes(range(32))
        cases = [(0, 0, 0), (0, 1, 2), (r.MASK64, 0xdeadbeef, 0x1111111111111111),
                 (0x123456789abcdef0, 0xfedcba9876543210, 0x876543210fedcba9)]
        for seed, secret0, secret1 in cases:
            with self.subTest(seed=seed):
                self.assertEqual(r.slot_hash(raw, seed, secret0, secret1),
                                 independent_slot_hash(raw, seed, secret0, secret1))
        for bit in range(256):
            changed = bytearray(raw)
            changed[bit // 8] ^= 1 << (bit % 8)
            self.assertEqual(r.slot_hash(bytes(changed), *cases[-1]),
                             independent_slot_hash(bytes(changed), *cases[-1]))

    def test_slot_hash_rejects_bad_widths(self):
        for x in (-1, 1 << 64, True):
            with self.assertRaises(ValueError):
                r.slot_hash(bytes(32), x, 1, 2)

    def test_slot_hash_depends_on_each_synthetic_seed_word(self):
        key = bytes(range(32))
        baseline = r.slot_hash(key, 11, 13, 17)
        for words in ((12, 13, 17), (11, 14, 17), (11, 13, 18)):
            with self.subTest(words=words):
                self.assertNotEqual(r.slot_hash(key, *words), baseline)

    def test_probe_exact_match_precedes_empty(self):
        controls = bytearray([0xfe] * 64)
        key, wrong = bytes(range(32)), bytes(range(31)) + b'\xff'
        keys = [None] * 64
        h = (7 << 57) | 12
        controls[12] = controls[14] = 7
        controls[15] = 0xff
        keys[12], keys[14] = wrong, key
        self.assertEqual(r.probe(bytes(controls), keys, key, h), 14)
        keys[14] = wrong
        self.assertIsNone(r.probe(bytes(controls), keys, key, h))

    def test_probe_deleted_control_and_second_group(self):
        controls = bytearray([0xfe] * 64)
        keys = [None] * 64
        key, h = bytes(range(32)), (9 << 57) | 3
        controls[20] = 9
        controls[29] = 0xff
        keys[20] = key
        self.assertEqual(r.probe(bytes(controls), keys, key, h), 20)
        keys[20] = key[:-1] + b'\xff'
        self.assertIsNone(r.probe(bytes(controls), keys, key, h))

    def test_probe_rejects_a_candidate_with_any_single_key_bit_changed(self):
        controls = bytearray([0xfe] * 32)
        key, h = bytes(range(32)), (5 << 57) | 4
        controls[4], controls[5] = 5, 0xff
        keys = [None] * 32
        for bit in range(256):
            changed = bytearray(key)
            changed[bit // 8] ^= 1 << (bit % 8)
            keys[4] = bytes(changed)
            with self.subTest(bit=bit):
                self.assertIsNone(r.probe(bytes(controls), keys, key, h))

    def test_probe_rejects_malformed_or_unterminated_table(self):
        key = bytes(32)
        with self.assertRaises(ValueError):
            r.probe(bytes(15), [None]*15, key, 0)
        with self.assertRaises(ValueError):
            r.probe(bytes([0xfe])*16, [None]*16, key, 0)
        with self.assertRaises(ValueError):
            r.probe(bytes([0xff])*16, [None]*15, key, 0)
        with self.assertRaises(ValueError):
            r.probe(bytes([0xff])*16, [None]*16, key[:-1], 0)

    def test_reserve_small_and_large_boundaries(self):
        self.assertEqual(r.reserve_plan(0, 0, 1)['buckets'], 4)
        self.assertEqual(r.reserve_plan(0, 0, 7)['buckets'], 8)
        self.assertEqual(r.reserve_plan(0, 0, 14)['buckets'], 16)
        self.assertEqual(r.reserve_plan(0, 0, 15)['buckets'], 32)
        self.assertEqual(r.reserve_plan(15, 4, 3)['branch'], 'in_place')
        self.assertEqual(r.reserve_plan(15, 4, 4)['branch'], 'allocate')
        self.assertEqual(r.reserve_plan(0, 0, 15)['allocation_bytes'], 3376)

    def test_reserve_matches_independent_minimum_bucket_oracle(self):
        for mask in (0, 3, 7, 15, 31, 63, 127, 255):
            capacity = mask if mask < 8 else (mask + 1) * 7 // 8
            for count in sorted({0, capacity // 2, capacity}):
                for extra in range(65):
                    got = r.reserve_plan(mask, count, extra)
                    need = count + extra
                    if need <= capacity // 2:
                        self.assertEqual(got['branch'], 'in_place')
                    else:
                        expected = minimum_buckets(max(capacity + 1, need))
                        self.assertEqual(got['buckets'], expected)
                        self.assertEqual(got['allocation_bytes'],
                                         (expected * 104 + 15) // 16 * 16 + expected + 16)

    def test_reserve_overflow_and_invalid_controls(self):
        self.assertEqual(r.reserve_plan(0, 0, r.MASK64)['branch'], 'overflow')
        for args in ((7, 9, 0), (5, 0, 1), (0, 0, -1), (0, 0, True)):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    r.reserve_plan(*args)


if __name__ == '__main__':
    unittest.main()
