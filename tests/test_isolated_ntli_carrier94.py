import hashlib
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import isolated_ntli_carrier94 as study


class CarrierEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = study.BINARY.read_bytes()
        cls.image = study.Image(cls.data)
        cls.pairs = study.read_pairs(cls.image)
        cls.magic = struct.unpack('<Q', cls.image.read(0x3bec4d2, 8))[0]

    def test_target_digest_and_wrong_digest(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), study.DIGEST)
        with self.assertRaises(ValueError):
            study.checked_target(b'wrong binary')

    def test_fde_matches_real_index_and_digest(self):
        for name in study.FUNCS:
            info = self.image.fde(name)
            self.assertEqual(info['sha256'], hashlib.sha256(bytes.fromhex(info['bytes_hex'])).hexdigest())

    def test_corrupted_body_is_rejected(self):
        original = self.image.read
        start, end, _ = study.FUNCS['signed_digits']
        def changed(va, size):
            data = original(va, size)
            if va == start and size == end-start:
                return bytes([data[0] ^ 1]) + data[1:]
            return data
        with patch.object(self.image, 'read', side_effect=changed):
            with self.assertRaises(ValueError):
                self.image.fde('signed_digits')

    def test_every_window_rejects_byte_change(self):
        for va, (_, expected) in study.WINDOWS.items():
            raw = self.image.read(va, len(bytes.fromhex(expected)))
            study.check_window(raw, expected)
            changed = bytes([raw[0] ^ 1]) + raw[1:]
            with self.assertRaises(ValueError):
                study.check_window(changed, expected)

    def test_direct_calls_and_wrong_opcode(self):
        self.assertEqual(self.image.direct_call(0x335938a), 0x3a75470)
        self.assertEqual(self.image.direct_call(0x3a757c2), 0x3b3fa20)
        self.assertEqual(self.image.direct_call(0x3a757e6), 0x3b3fa20)
        self.assertEqual(self.image.direct_call(0x374b30d), 0x3bec4a0)
        with patch.object(self.image, 'read', return_value=b'\x90\0\0\0\0'):
            with self.assertRaises(ValueError):
                self.image.direct_call(0x374b30d)

    def test_rip_references_and_displacement_mutation(self):
        self.assertEqual(self.image.rip_lea(0x3a75c34), 0x1df8f3)
        self.assertEqual(self.image.rip_lea(0x3a75b5a), 0x1e0fd5)
        self.assertEqual(self.image.rip_lea(0x374b2bb), 0x209f7c)
        original = self.image.read
        def changed(va, size):
            data = original(va, size)
            if va == 0x374b2bb and size == 7:
                return data[:3] + bytes([data[3] ^ 1]) + data[4:]
            return data
        with patch.object(self.image, 'read', side_effect=changed):
            self.assertNotEqual(self.image.rip_lea(0x374b2bb), 0x209f7c)
        with patch.object(self.image, 'read', return_value=b'\x90' * 7):
            with self.assertRaises(ValueError):
                self.image.rip_lea(0x374b2bb)

    def test_branch_targets_and_corrupt_opcode(self):
        self.assertEqual(self.image.branch(0x3a7575d)['target'], '0x3a75e89')
        self.assertEqual(self.image.branch(0x3b3fa6a)['target'], '0x3b3faf1')
        for site, target in ((0x374b234, '0x374b240'), (0x374b280, '0x374b3e7'),
                             (0x374b2ab, '0x374b3e7'), (0x374b2d3, '0x374b3f6'),
                             (0x374b2f2, '0x374b40f'), (0x3bec612, '0x3bec63b')):
            self.assertEqual(self.image.branch(site)['target'], target)
        with patch.object(self.image, 'read', return_value=b'\x90' * 6):
            with self.assertRaises(ValueError):
                self.image.branch(0x3a7575d)

    def test_two_jump_tables(self):
        self.assertEqual(self.image.table_targets(0x5b1e0c, 8), study.TAG_TARGETS)
        self.assertEqual(self.image.table_targets(0x5aa290, 3), [0x3a75558, 0x3a756e0, 0x3a75755])

    def test_three_field_relocations(self):
        rows = study.read_fields(self.image)
        self.assertEqual([r[-1] for r in rows], ['asset', 'isBuy', 'ntli'])
        with patch.dict(self.image.relative, {0x56f1c28: 0x209f7d}):
            with self.assertRaises(ValueError):
                study.read_fields(self.image)

    def test_field_missing_relocation(self):
        with patch.dict(self.image.relative, {0x56f1c28: None}):
            with self.assertRaises(ValueError):
                study.read_fields(self.image)

    def test_digit_table_corruption(self):
        original = self.image.read
        def changed(va, size):
            b = original(va, size)
            if va == 0x5b988d and size == 200:
                return b'X' + b[1:]
            return b
        with patch.object(self.image, 'read', side_effect=changed):
            with self.assertRaises(ValueError):
                study.read_pairs(self.image)

    def test_rejects_unbacked_and_cross_section_ranges(self):
        with self.assertRaises(ValueError):
            self.image.offset(0, 1)
        text = next(s for s in self.image.sections if s['name'] == '.text')
        with self.assertRaises(ValueError):
            self.image.offset(text['address'] + text['size'] - 1, 2)
        with self.assertRaises(ValueError):
            self.image.offset(-1, 1)
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        with self.assertRaises(ValueError):
            self.image.offset(bss['address'], 1)

    def test_presence_and_duplicate_selected_edges(self):
        expected = {(False, False, False): '0x3a75b90',
                    (True, False, False): '0x3a75a7c',
                    (True, True, False): '0x3a75c00',
                    (True, True, True): '0x3a75c64'}
        for args, target in expected.items():
            self.assertEqual(study.presence_walk(self.image, *args), target)
        for field, target in [('asset', '0x3a75b33'), ('isBuy', '0x3a75e52'), ('ntli', '0x3a75e89')]:
            self.assertEqual(study.duplicate_walk(self.image, field, True), target)
            self.assertNotEqual(study.duplicate_walk(self.image, field, False), target)
        with self.assertRaises(ValueError):
            study.presence_walk(self.image, 1, True, True)
        with self.assertRaises(ValueError):
            study.duplicate_walk(self.image, 'unknown', False)

    def test_corrupt_presence_guard_and_duplicate_branch_fail_closed(self):
        original = self.image.read
        for bad in (0x3a75a69, 0x3a7575d):
            def changed(va, size, bad=bad):
                data = original(va, size)
                return bytes([data[0] ^ 1]) + data[1:] if va == bad else data
            with patch.object(self.image, 'read', side_effect=changed):
                with self.assertRaises(ValueError):
                    if bad == 0x3a75a69:
                        study.presence_walk(self.image, True, True, True)
                    else:
                        study.duplicate_walk(self.image, 'ntli', True)

    def test_tag_boundary_payloads_against_actual_load_opcodes(self):
        for tag, (_, width, _) in enumerate(study.TAG_SHAPES, 1):
            target = study.TAG_TARGETS[tag - 1]
            code = self.image.read(target, 16)
            for x in (0, 1, (1 << (8*width-1))-1, 1 << (8*width-1), (1 << (8*width))-1):
                payload = x.to_bytes(width, 'little')
                self.assertEqual(study.decode_instruction_load(code, payload), study.decode_tag(tag, payload))

    def test_exhaustive_byte_integer_variants(self):
        for tag in (1, 5):
            code = self.image.read(study.TAG_TARGETS[tag-1], 16)
            for n in range(256):
                payload = bytes([n])
                self.assertEqual(study.decode_instruction_load(code, payload), study.decode_tag(tag, payload))

    def test_exhaustive_short_integer_variants(self):
        for tag in (2, 6):
            code = self.image.read(study.TAG_TARGETS[tag-1], 16)
            for n in range(1 << 16):
                payload = n.to_bytes(2, 'little')
                self.assertEqual(study.decode_instruction_load(code, payload), study.decode_tag(tag, payload))

    def test_u64_checked_high_bit_and_signed_extrema(self):
        self.assertEqual(study.decode_tag(4, (study.SIGN-1).to_bytes(8,'little')), ('accepted', study.SIGN-1))
        self.assertEqual(study.decode_tag(4, study.SIGN.to_bytes(8,'little')), ('diagnostic', None))
        self.assertEqual(study.decode_tag(8, study.SIGN.to_bytes(8,'little')), ('accepted', -study.SIGN))
        self.assertEqual(study.decode_tag(8, study.MASK.to_bytes(8,'little')), ('accepted', -1))

    def test_bad_value_width_and_other_tags(self):
        with self.assertRaises(ValueError):
            study.decode_tag(8, b'\x00')
        with self.assertRaises(ValueError):
            study.decode_instruction_load(self.image.read(study.TAG_TARGETS[0], 16), b'')
        self.assertEqual(study.decode_tag(0, b''), ('fallback', None))
        self.assertEqual(study.decode_tag(9, b''), ('fallback', None))

    def test_wrong_numeric_load_opcode_rejected(self):
        for target in study.TAG_TARGETS:
            raw = self.image.read(target, 16)
            with self.assertRaises(ValueError):
                study.decode_instruction_load(bytes([raw[0] ^ 0x20]) + raw[1:], b'\0' * 8)

    def test_power_of_ten_reciprocal_full_domain_bound(self):
        error = self.magic * 10000 - (1 << 75)
        self.assertEqual(error, 432)
        self.assertLess((study.SIGN // 10000) * error + 9999 * self.magic, 1 << 75)
        for value in (0, 1, 9999, 10000, study.SIGN-1, study.SIGN):
            self.assertEqual((value * self.magic) >> 75, value // 10000)
        # The preceding multiplier undershoots an exact multiple.
        self.assertNotEqual((10000 * (self.magic-1)) >> 75, 1)

    def test_pair_table_and_all_four_digit_remainders(self):
        for n in range(100):
            self.assertEqual(self.pairs[n*2:n*2+2], str(n).zfill(2).encode())
        for n in range(10000):
            high = ((n >> 2) * 0x147b) >> 17
            self.assertEqual(high, n // 100)
            self.assertEqual(self.pairs[2*high:2*high+2] + self.pairs[2*(n-high*100):2*(n-high*100)+2], str(n).zfill(4).encode())

    def test_digit_format_boundaries_and_negative_extremum(self):
        for n in [0, 1, 9, 10, 99, 100, 999, 1000, 9999, 10000, study.SIGN-1, study.SIGN, study.MASK]:
            signed = n if n < study.SIGN else n - (1 << 64)
            self.assertEqual(study.format_lift(n, self.pairs, self.magic).decode(), str(signed))
        self.assertEqual(study.format_lift(study.SIGN, self.pairs, self.magic), b'-9223372036854775808')

    def test_all_small_signed_decimal_values(self):
        for n in range(-10000, 10001):
            bits = n & study.MASK
            self.assertEqual(study.format_lift(bits, self.pairs, self.magic).decode(), str(n))

    def test_digit_format_on_deterministic_64bit_grid(self):
        x = 0x123456789abcdef0
        for _ in range(20000):
            x = (x * 6364136223846793005 + 1442695040888963407) & study.MASK
            value = x if x < study.SIGN else x - (1 << 64)
            self.assertEqual(study.format_lift(x, self.pairs, self.magic).decode(), str(value))

    def test_invalid_digit_input(self):
        for bad in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                study.format_lift(bad, self.pairs, self.magic)
        with self.assertRaises(ValueError):
            study.format_lift(0, b'bad', self.magic)
        with self.assertRaises(ValueError):
            study.format_lift(10000, self.pairs, self.magic-1)


if __name__ == '__main__':
    unittest.main()
