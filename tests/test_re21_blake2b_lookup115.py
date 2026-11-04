"""Static and synthetic controls for the node 115 BLAKE2b lookup packet."""
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'tools'))
import re21_blake2b_lookup115 as re21


def section(name, address, size, offset=0, kind=1, flags=0):
    return {'name': name, 'address': address, 'size': size,
            'offset': offset, 'type': kind, 'flags': flags}


def payload(rounds=0, flag=0, length=213):
    result = bytearray(length)
    if length >= 4:
        result[:4] = rounds.to_bytes(4, 'big')
    if length >= 213:
        result[212] = flag
    return bytes(result)


def fold_by_32bit_limbs(a, b):
    mask32 = (1 << 32) - 1
    a0, a1 = a & mask32, a >> 32
    b0, b1 = b & mask32, b >> 32
    p0 = a0 * b0
    middle = (p0 >> 32) + a0 * b1 + a1 * b0
    low = (p0 & mask32) | ((middle & mask32) << 32)
    high = (a1 * b1 + (middle >> 32)) & re21.MASK64
    return low ^ high


class ArtifactControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = re21.TARGET.read_bytes()
        cls.secs = re21.sections(cls.data)
        cls.results = re21.collect(cls.data)

    def test_authenticated_target_and_distinct_selected_fdes(self):
        self.assertEqual(re21.digest_checked(self.data), re21.SHA256)
        fs = self.results['functions']
        self.assertEqual(len(fs), len(re21.FUNCTIONS))
        self.assertEqual(len({row['start_va'] for row in fs}), len(fs))
        for row in fs:
            self.assertGreater(int(row['end_va'], 16), int(row['start_va'], 16))
            self.assertEqual(hashlib.sha256(bytes.fromhex(row['bytes'])).hexdigest(), row['sha256'])

    def test_digest_rejects_corrupted_bytes_and_wrong_expected(self):
        self.assertEqual(re21.digest_checked(b'abc', hashlib.sha256(b'abc').hexdigest()),
                         hashlib.sha256(b'abc').hexdigest())
        with self.assertRaises(ValueError):
            re21.digest_checked(b'abd', hashlib.sha256(b'abc').hexdigest())
        with self.assertRaises(ValueError):
            re21.digest_checked(self.data, '0' * 64)

    def test_nobits_unmapped_ambiguous_and_cross_boundary(self):
        blob = bytes(range(16))
        valid = section('.data', 0x1000, 8, 0)
        bss = section('.bss', 0x2000, 8, 8, kind=8)
        self.assertEqual(re21.read_va(blob, [valid, bss], 0x1002, 3)[0], b'\x02\x03\x04')
        for address, size in ((0x2000, 1), (0x3000, 1), (0x1007, 2), (-1, 1), (0x1000, 0), ((1 << 64) - 1, 2)):
            with self.subTest(address=address, size=size), self.assertRaises(ValueError):
                re21.read_va(blob, [valid, bss], address, size)
        with self.assertRaises(ValueError):
            re21.read_va(blob, [valid, dict(valid)], 0x1000, 1)
        with self.assertRaises(ValueError):
            re21.read_va(blob, [valid], 0x1000, 1, executable=True)
        broken = section('.broken', 0x1000, 8, 20)
        with self.assertRaises(ValueError):
            re21.read_va(blob, [broken], 0x1000, 1)

    def test_instruction_pin_tamper(self):
        original = bytes.fromhex('488b3e488db190000000e8f70600004885c07420')
        text = section('.text', 0x1000, len(original), flags=4)
        self.assertEqual(re21.check_pin(original, [text], 0x1000, original)['bytes'], original.hex())
        corrupt = bytearray(original)
        corrupt[3] ^= 1
        with self.assertRaises(ValueError):
            re21.check_pin(corrupt, [text], 0x1000, original)

    def test_relative_branch_opcode_bounds_and_signed_displacement(self):
        code = bytes.fromhex('e9020000009090c3ebf6')
        text = section('.text', 0x1000, len(code), flags=4)
        self.assertEqual(re21.rel32_or_rel8(code, [text], 0x1000, 'e9')['target_va'], '0x1007')
        self.assertEqual(re21.rel32_or_rel8(code, [text], 0x1008, 'eb')['target_va'], '0x1000')
        with self.assertRaises(ValueError):
            re21.rel32_or_rel8(code, [text], 0x1000, 'e8')
        with self.assertRaises(ValueError):
            re21.rel32_or_rel8(code, [text], 0x1000, '90')
        bad = bytes.fromhex('e97f0000009090c3ebf6')
        with self.assertRaises(ValueError):
            re21.rel32_or_rel8(bad, [text], 0x1000, 'e9')

    def test_missing_duplicate_and_zero_fde(self):
        sample = {'start': 10, 'end': 20}
        self.assertIs(re21.one_fde([sample], 10), sample)
        for rows in ([], [sample, sample], [{'start': 10, 'end': 10}]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                re21.one_fde(rows, 10)

    def test_dynamic_relocation_missing_duplicate_type_and_addend(self):
        raw = struct.pack('<QQq', 0x100, 8, 0x200)
        rel = section('.rela.dyn', 0, len(raw), kind=4)
        rows = re21.relocations(raw, [rel])
        self.assertEqual(re21.relative_reloc(rows, 0x100, 0x200)['addend_va'], '0x200')
        for altered, slot, target in ((rows, 0x101, None),
                                      ({0x100: (7, 0x200, 0)}, 0x100, None),
                                      ({0x100: (8, -1, 0)}, 0x100, None),
                                      (rows, 0x100, 0x201)):
            with self.subTest(altered=altered, slot=slot), self.assertRaises(ValueError):
                re21.relative_reloc(altered, slot, target)
        duplicate = raw + raw
        with self.assertRaises(ValueError):
            re21.relocations(duplicate, [section('.rela.dyn', 0, len(duplicate), kind=4)])

    def test_record_copy_shape_corruption_and_completeness(self):
        name, start, end, stack, rec_base, count = re21.COPY_GROUPS[0]
        code = re21.read_va(self.data, self.secs, start, end - start)[0]
        data = re21.read_va(self.data, self.secs, rec_base, 56 * count)[0]
        image = bytearray(code + data)
        secs = [section('.text', start, len(code), flags=4),
                section('.rodata', rec_base, len(data), offset=len(code))]
        rows = re21.copy_group(image, secs, name, start, end, stack, rec_base, count)
        self.assertEqual(sum(row['width'] for row in rows), 56 * count)
        bad_opcode = bytearray(image)
        bad_opcode[0] ^= 1
        with self.assertRaises(ValueError):
            re21.copy_group(bad_opcode, secs, name, start, end, stack, rec_base, count)
        bad_source = bytearray(image)
        bad_source[3] ^= 1
        with self.assertRaises(ValueError):
            re21.copy_group(bad_source, secs, name, start, end, stack, rec_base, count)
        bad_destination = bytearray(image)
        bad_destination[11] ^= 1
        with self.assertRaises(ValueError):
            re21.copy_group(bad_destination, secs, name, start, end, stack, rec_base, count)
        with self.assertRaises(ValueError):
            re21.copy_group(image, secs, name, start, end - 1, stack, rec_base, count)

    def test_conversion_table_corruption(self):
        base, target = 0x3000, 0x4000
        table = struct.pack('<i', target - base)
        blob = bytearray(table + b'\x90' * 8)
        secs = [section('.rodata', base, 4), section('.text', target, 8, offset=4, flags=4)]
        entries = re21.conversion_entries(blob, secs, base, 1, target, target + 8)
        self.assertEqual(entries[0]['target_va'], hex(target))
        blob[:4] = struct.pack('<i', target + 8 - base)
        with self.assertRaises(ValueError):
            re21.conversion_entries(blob, secs, base, 1, target, target + 8)
        with self.assertRaises(ValueError):
            re21.conversion_entries(blob, secs, base, 0, target, target + 8)

    def test_diagnostic_table_and_literal_corruption(self):
        case = self.results['diagnostic_cases'][0]
        table_va = int(case['entry_va'], 16)
        code_va = int(case['case_va'], 16)
        literal_va = int(case['literal_va'], 16)
        table = re21.read_va(self.data, self.secs, table_va, 4)[0]
        code = re21.read_va(self.data, self.secs, code_va, 13)[0]
        literal = re21.read_va(self.data, self.secs, literal_va, case['length'])[0]
        image = bytearray(table + code + literal)
        secs = [section('.table', table_va, 4),
                section('.text', code_va, len(code), offset=4, flags=4),
                section('.literal', literal_va, len(literal), offset=4 + len(code))]
        self.assertEqual(re21.diagnostic_entry(image, secs, 1)['literal'],
                         'wrong input length for blake2')
        corrupted = bytearray(image)
        corrupted[:4] = bytes(4)
        with self.assertRaises(ValueError):
            re21.diagnostic_entry(corrupted, secs, 1)
        corrupted = bytearray(image)
        corrupted[6:10] = bytes.fromhex('ffffffff')
        with self.assertRaises(ValueError):
            re21.diagnostic_entry(corrupted, secs, 1)
        corrupted = bytearray(image)
        corrupted[-1] = 0
        with self.assertRaises(ValueError):
            re21.diagnostic_entry(corrupted, secs, 1)

    def test_journal_entries_stop_at_documented_table_range(self):
        entries = self.results['journal_cases']
        self.assertEqual(len(entries), 12)
        self.assertEqual([entry['index'] for entry in entries], list(range(12)))
        self.assertEqual(len({entry['target_va'] for entry in entries}), 12)
        self.assertEqual(entries[6]['target_va'], '0x5be36f1')
        with self.assertRaises(ValueError):
            re21.conversion_entries(self.data, self.secs, 0x942248, 13, 0x5be3400, 0x5be3b49)

    def test_default_selector_link_and_corruption(self):
        segments = ((0x5be792e, 5, 4), (0x5be7ce0, 12, 4),
                    (0x29a12be, 8, 4), (0x29a12e1, 8, 4), (0x602d48, 15, 0))
        image = bytearray()
        secs = []
        for i, (va, size, flags) in enumerate(segments):
            chunk = re21.read_va(self.data, self.secs, va, size)[0]
            secs.append(section('segment' + str(i), va, size, len(image), flags=flags))
            image.extend(chunk)
        result = re21.default_selector(image, secs)
        self.assertEqual((result['context_field_offset'], result['selector_byte'], result['builder_mode']),
                         ('0x268', 13, 6))
        for changed in (4, 5 + 8):
            corrupt = bytearray(image)
            corrupt[changed] ^= 1
            with self.subTest(byte=changed), self.assertRaises(ValueError):
                re21.default_selector(corrupt, secs)

    def test_immediate_value_and_opcode_corruption(self):
        raw = bytearray(bytes.fromhex('48b80102030405060708'))
        secs = [section('.text', 0x1000, len(raw), flags=4)]
        expected = int.from_bytes(raw[2:], 'little')
        self.assertEqual(re21.movabs_immediate(raw, secs, 0x1000, '48b8', expected)['value'], hex(expected))
        raw[-1] ^= 1
        with self.assertRaises(ValueError):
            re21.movabs_immediate(raw, secs, 0x1000, '48b8', expected)
        raw[0] ^= 1
        with self.assertRaises(ValueError):
            re21.movabs_immediate(raw, secs, 0x1000, '48b8', expected)

    def test_record_09_and_lineage_are_derived_from_checked_bytes(self):
        records = self.results['records']
        row = records[11]
        self.assertEqual(row['record_va'], '0x64c0730')
        self.assertEqual(row['key_hex'], (bytes(19) + b'\x09').hex())
        self.assertEqual(row['callback_va'], '0x5c165b0')
        modes = self.results['derived_mode_records']
        key = row['key_hex']
        for mode, item in enumerate(modes):
            values = {r['key_hex']: r['callback_va'] for r in item['derived_entries']}
            self.assertEqual(values.get(key), None if mode < 2 else row['callback_va'])
        with self.assertRaises(ValueError):
            re21.derive_mode_records(records[:-1])

    def test_generated_files_match_fresh_collection(self):
        evidence = REPO / 'research/work-items/RE-021-blake2b-lookup-115'
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            re21.emit(self.data, out)
            self.assertGreater(len(list(out.iterdir())), 5)
            for fresh in sorted(out.iterdir()):
                with self.subTest(name=fresh.name):
                    self.assertEqual(fresh.read_bytes(), (evidence / fresh.name).read_bytes())


class SyntheticLookupControls(unittest.TestCase):
    seed = 0x0123456789abcdef
    word = 0xfedcba9876543210
    generic = b'\x80' + bytes(19)

    def lookup(self, key, direct, controls, buckets, **kwargs):
        return re21.model_lookup(key, direct, controls, buckets, self.seed, self.word, **kwargs)

    def test_multiply_fold_independent_limb_reference(self):
        values = (0, 1, 2, 0xffffffff, 0x100000000, 0x0123456789abcdef, re21.MASK64)
        for a in values:
            for b in values:
                with self.subTest(a=a, b=b):
                    self.assertEqual(re21.fold64(a, b), fold_by_32bit_limbs(a, b))
        key = self.generic
        first = int.from_bytes(key[:8], 'little') ^ self.seed
        second = int.from_bytes(key[8:16], 'little') ^ self.word
        last = int.from_bytes(key[16:], 'little')
        expected = fold_by_32bit_limbs(fold_by_32bit_limbs(first, second) ^ last, self.word)
        self.assertEqual(re21.key_hash(key, self.seed, self.word), expected)
        self.assertNotEqual(re21.key_hash(key, self.seed, self.word), re21.key_hash(key, self.seed ^ 1, self.word))
        for args in ((b'bad', 0, 0), (key, -1, 0), (key, 0, 1 << 64)):
            with self.assertRaises(ValueError):
                re21.key_hash(*args)

    def test_direct_bounds_prefix_and_miss_do_not_fall_back(self):
        direct = [None] * 300
        k9 = bytes(19) + b'\x09'
        direct[9] = 'nine'
        self.assertEqual(re21.direct_index(k9), 9)
        self.assertEqual(re21.direct_index(bytes(18) + (299).to_bytes(2, 'big')), 299)
        self.assertIsNone(re21.direct_index(bytes(18) + (300).to_bytes(2, 'big')))
        self.assertIsNone(re21.direct_index(b'\x01' + k9[1:]))
        self.assertEqual(self.lookup(k9, direct, [], []), 'nine')
        direct[9] = None
        h = re21.key_hash(k9, self.seed, self.word)
        controls = [0xff] * 16
        buckets = [None] * 16
        controls[h & 15] = h >> 57
        buckets[h & 15] = (k9, 'must-not-be-read')
        self.assertIsNone(self.lookup(k9, direct, controls, buckets))
        with self.assertRaises(ValueError):
            re21.direct_index(b'\0' * 19)
        with self.assertRaises(ValueError):
            self.lookup(k9, [], controls, buckets)

    def test_empty_map_and_group_match_before_empty(self):
        direct = [None] * 300
        self.assertIsNone(self.lookup(self.generic, direct, [], [], entry_count=0))
        h = re21.key_hash(self.generic, self.seed, self.word)
        controls = [0xff] * 32
        buckets = [None] * 32
        pos = h & 31
        match = (pos + 9) & 31
        controls[match] = h >> 57
        buckets[match] = (self.generic, 'match')
        self.assertEqual(self.lookup(self.generic, direct, controls, buckets, entry_count=1), 'match')
        with self.assertRaises(ValueError):
            self.lookup(self.generic, direct, controls, buckets, entry_count=-1)

    def test_deleted_controls_and_triangular_third_group(self):
        direct = [None] * 300
        h = re21.key_hash(self.generic, self.seed, self.word)
        pos = h & 63
        controls = [0x80] * 64
        buckets = [None] * 64
        match = (pos + 48 + 7) & 63
        controls[match] = h >> 57
        buckets[match] = (self.generic, 'third-group')
        self.assertEqual(self.lookup(self.generic, direct, controls, buckets), 'third-group')
        controls[match] = 0x80
        controls[(pos + 48 + 8) & 63] = 0xff
        self.assertIsNone(self.lookup(self.generic, direct, controls, buckets))

    def test_all_address_bits_are_compared_after_fingerprint_match(self):
        direct = [None] * 300
        key = self.generic
        h = re21.key_hash(key, self.seed, self.word)
        pos = h & 31
        for bit in range(160):
            changed = bytearray(key)
            changed[bit // 8] ^= 1 << (bit % 8)
            controls = [0xff] * 32
            buckets = [None] * 32
            controls[pos] = h >> 57
            buckets[pos] = (bytes(changed), 'wrong-key')
            with self.subTest(bit=bit):
                self.assertIsNone(self.lookup(key, direct, controls, buckets))

    def test_invalid_or_unterminated_synthetic_map(self):
        direct = [None] * 300
        for controls, buckets in (([0xff] * 15, [None] * 15), ([256] * 16, [None] * 16),
                                  ([0xff] * 16, [None] * 15), ([0x80] * 16, [None] * 16)):
            with self.subTest(length=len(controls)), self.assertRaises(ValueError):
                self.lookup(self.generic, direct, controls, buckets)


class InputAndStatusControls(unittest.TestCase):
    def test_length_precedes_other_failures(self):
        for length in (0, 212, 214):
            decision = re21.input_decision(payload(1, 2, length), 0)
            self.assertEqual(decision['result'], 'length-error')
            self.assertEqual(decision['word'], '0x8000000000000002')
            self.assertEqual(re21.frame_status(decision, 0), 0x31)

    def test_gas_precedes_invalid_flag(self):
        decision = re21.input_decision(payload(1, 2), 0)
        self.assertEqual(decision['result'], 'gas-error')
        self.assertEqual(decision['word'], '0x8000000000000001')
        self.assertEqual(re21.frame_status(decision, 0), 0x23)
        flag = re21.input_decision(payload(1, 2), 1)
        self.assertEqual(flag['result'], 'flag-error')
        self.assertEqual(flag['word'], '0x8000000000000003')
        self.assertEqual(re21.frame_status(flag, 1), 0x31)

    def test_rounds_endian_zero_maximum_and_equal_gas(self):
        for rounds, flag in ((0, 0), (0, 1), (1, 0), (0x1020304, 1), (0xffffffff, 1)):
            decision = re21.input_decision(payload(rounds, flag), rounds)
            with self.subTest(rounds=rounds, flag=flag):
                self.assertEqual(decision, {'result': 'provider-call', 'rounds': rounds, 'flag': flag})
                self.assertEqual(re21.frame_status(decision, rounds), 2)
        self.assertEqual(re21.input_decision(payload(0xffffffff), 0xfffffffe)['result'], 'gas-error')

    def test_invalid_gas_and_unrecognized_status(self):
        for gas in (-1, 1 << 64, '1'):
            with self.subTest(gas=gas), self.assertRaises(ValueError):
                re21.input_decision(payload(), gas)
            with self.assertRaises(ValueError):
                re21.frame_status({'result': 'length-error'}, gas)
        with self.assertRaises(ValueError):
            re21.frame_status({'result': 'unknown'}, 0)
        self.assertEqual(re21.frame_status({'result': 'provider-call', 'rounds': 2}, 1), 0x23)

    def test_depth_and_journal_counter_saturation(self):
        for before, after in ((0, 0), (1, 0), (2, 1), (re21.MASK64, re21.MASK64 - 1)):
            with self.subTest(before=before):
                self.assertEqual(re21.saturating_decrement(before), after)
        for invalid in (-1, 1 << 64, '1'):
            with self.assertRaises(ValueError):
                re21.saturating_decrement(invalid)


if __name__ == '__main__':
    unittest.main()
