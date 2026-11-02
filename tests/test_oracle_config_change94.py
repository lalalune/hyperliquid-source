import hashlib
import random
import struct
import unittest
from fractions import Fraction

from tools import oracle_config_change94 as subject


class OracleConfigChangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.BINARY.read_bytes()
        cls.image, cls.functions, cls.links = subject.collect(cls.data)

    def test_artifact_digest(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), subject.SHA)

    def test_corrupt_digest_is_rejected_first(self):
        damaged = bytearray(self.data)
        damaged[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'digest'):
            subject.collect(damaged)

    def test_fde_intervals(self):
        for start, (end, _, _) in subject.FUNCTIONS.items():
            self.assertEqual(self.image.fdes[start], end)

    def test_wrong_fde_is_rejected(self):
        image = subject.Image(self.data)
        image.fdes[0x39783b0] += 1
        with self.assertRaisesRegex(ValueError, 'FDE'):
            image.check()

    def test_changed_subject_body_is_rejected(self):
        image = subject.Image(self.data)
        damaged = bytearray(self.data)
        damaged[image.offset(0x39783f8)] ^= 1
        image.data = damaged
        with self.assertRaisesRegex(ValueError, 'body'):
            image.check()

    def test_changed_dispatch_window_is_rejected(self):
        image = subject.Image(self.data)
        damaged = bytearray(self.data)
        damaged[image.offset(0x2358074)] ^= 1
        image.data = damaged
        with self.assertRaisesRegex(ValueError, 'window'):
            image.check()

    def test_reject_unbacked_and_crossing_ranges(self):
        with self.assertRaises(ValueError):
            self.image.read(0xfffffffffffffff0, 32)
        with self.assertRaises(ValueError):
            self.image.read(0, 0)
        text = next(s for s in self.image.sections if s['name'] == '.text')
        with self.assertRaises(ValueError):
            self.image.read(text['address'] + text['size'] - 1, 2, True)

    def test_nobits_is_never_backed(self):
        sec = next(s for s in self.image.sections if s['name'] == '.bss' and s['type'] == 8)
        with self.assertRaises(ValueError):
            self.image.read(sec['address'], 1)

    def test_tag_and_exact_diagnostic(self):
        self.assertEqual(self.links['raw_tag'], '0x6e')
        self.assertEqual(self.links['jump_destination_va'], '0x235801f')
        self.assertIn('SetReferenceOracleConfig', self.links['variant_text'])
        self.assertEqual(self.links['unvalidated_type'], 'UnvalidatedReferenceOracleConfigChange')

    def test_relative_targets(self):
        self.assertEqual(self.image.relative32(0x1f571bc, b'\xe8'), 0x1eeb7d0)
        self.assertEqual(self.image.relative32(0x235baa6, b'\xe8'), 0x3bff4c0)
        with self.assertRaises(ValueError):
            self.image.relative32(0x1f571bc, b'\xff\x15')

    def test_relocation_and_indirect_call(self):
        slot = self.image.relative32(0x2358074, b'\xff\x15')
        self.assertEqual(self.image.relocs[slot], 0x39783b0)
        self.assertEqual(self.image.relative32(0x235af95, b'\xff\x15'), slot)

    def test_corrupted_indirect_relocation(self):
        altered = bytearray(self.data)
        section = next(s for s in self.image.sections if s['name'] == '.rela.d' + 'yn')
        for off in range(section['offset'], section['offset'] + section['size'], 24):
            where, info, _ = struct.unpack_from('<QQq', altered, off)
            if where == 0x5773dc8 and info & 0xffffffff == 8:
                altered[off + 16] ^= 1
                break
        else:
            self.fail('relative relocation missing')
        with self.assertRaisesRegex(ValueError, 'digest'):
            subject.collect(altered)
        image = subject.Image(altered)
        self.assertNotEqual(image.relocs[0x5773dc8], 0x39783b0)

    def test_branch_targets_and_corrupted_opcode(self):
        for va in subject.BRANCHES:
            self.assertTrue(self.image.branch(va)['target'].startswith('0x'))
        image = subject.Image(self.data)
        damaged = bytearray(self.data)
        damaged[image.offset(0x39783d1)] = 0x90
        image.data = damaged
        with self.assertRaisesRegex(ValueError, 'conditional'):
            image.branch(0x39783d1)

    def test_all_ieee_classes_against_exact_rationals(self):
        rng = random.Random(941104)
        words = [0, 1, 0x3fefffffffffffff, 0x3ff0000000000000,
                 0x8000000000000000, 0x8000000000000001,
                 0x7ff0000000000000, 0x7ff0000000000001,
                 0xfff0000000000000, 0xfff8000000000000]
        words += [rng.getrandbits(64) for _ in range(4096)]
        for bits in words:
            sign, exp, mant = bits >> 63, (bits >> 52) & 2047, bits & ((1 << 52)-1)
            if exp == 2047:
                with self.assertRaises(ValueError):
                    subject.float_class(bits)
                continue
            else:
                sig = mant if exp == 0 else mant + (1 << 52)
                power = (-1074 if exp == 0 else exp - 1075)
                value = Fraction(sig * (-1 if sign else 1))
                value *= Fraction(2 ** power) if power >= 0 else Fraction(1, 2 ** -power)
                expected = 0 <= value < 1
            self.assertEqual(subject.float_class(bits)[1], expected, f'{bits:016x}')

    def test_fraction_boundaries(self):
        for bits in (0, 1, 0x3fefffffffffffff, 0x8000000000000000):
            self.assertTrue(subject.float_class(bits)[1])
        for bits in (0x3ff0000000000000, 0x8000000000000001, 0xbff0000000000000):
            self.assertFalse(subject.float_class(bits)[1])
        for bits in (0x7ff0000000000001, 0xfff8000000000000, 0x7ff0000000000000):
            with self.assertRaises(ValueError):
                subject.float_class(bits)

    def test_finite_domain_partition(self):
        intervals = [(0, 0x3fefffffffffffff, True),
                     (0x3ff0000000000000, 0x7fefffffffffffff, False),
                     (0x8000000000000000, 0x8000000000000000, True),
                     (0x8000000000000001, 0xffefffffffffffff, False)]
        self.assertEqual(sum(b-a+1 for a,b,_ in intervals), 2 * 2047 * (1 << 52))
        for lo,hi,result in intervals:
            self.assertEqual(subject.float_class(lo)[1], result)
            self.assertEqual(subject.float_class(hi)[1], result)

    def test_corrupted_entry_name_gate(self):
        image = subject.Image(self.data)
        altered = bytearray(self.data)
        altered[image.offset(0x235af44)] ^= 1
        image.data = altered
        with self.assertRaisesRegex(ValueError, 'window'):
            image.check()

    def test_bad_float_width(self):
        for bits in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                subject.float_class(bits)

    def test_cap_boundaries(self):
        L = subject.LIMIT
        self.assertEqual(subject.gate(0, 0, 0, False, 1, L-1, 0), 'success_0x186')
        self.assertEqual(subject.gate(0, 0, 0, False, 1, L, 0), 'cap_0x13f')
        self.assertEqual(subject.gate(0, 0, 0, False, 0, L, 0), 'success_0x186')
        self.assertEqual(subject.gate(0, 0, 0, False, 2, L, 0), 'cap_0x13f')

    def test_failure_precedence(self):
        a = (1, 101, 0x55, False, 1, subject.LIMIT, 0x3ff0000000000000)
        self.assertEqual(subject.gate(*a), 'length_0x143')
        self.assertEqual(subject.gate(1,100,0x55,False,1,subject.LIMIT,a[-1]), 'parser_0x55')
        self.assertEqual(subject.gate(1,100,0x186,False,1,subject.LIMIT,a[-1]), 'conversion_0xab')
        self.assertEqual(subject.gate(1,100,0x186,True,1,subject.LIMIT,a[-1]), 'cap_0x13f')
        self.assertEqual(subject.gate(1,100,0x186,True,1,subject.LIMIT-1,a[-1]), 'fraction_0x13f')

    def test_invalid_integer_range(self):
        with self.assertRaises(ValueError):
            subject.gate(0, 0, 0, 0, 0, -1, 0)
        with self.assertRaises(ValueError):
            subject.gate(0, 1 << 64, 0, 0, 0, 0, 0)

    def test_default_field_merge(self):
        for f in (0,1,2):
            for n in (0,1,2):
                for m in (0,1,2,3,255):
                    got = subject.merged((11,22,1), (f,33,n,44,m))
                    self.assertEqual(got, (33 if f else 11, 44 if n else 22, 1 if m == 3 else m))

    def test_mode_three_is_preserve_not_zero(self):
        self.assertEqual(subject.merged((8,9,2),(0,11,0,12,3)), (8,9,2))
        self.assertEqual(subject.merged((8,9,2),(1,11,1,12,0)), (11,12,0))


if __name__ == '__main__':
    unittest.main()
