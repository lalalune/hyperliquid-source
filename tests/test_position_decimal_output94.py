import hashlib
import random
import struct
import unittest
from unittest import mock

from tools import position_decimal_output94 as p


class PositionDecimalOutputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = p.BINARY.read_bytes()
        p.verify_digest(cls.data)
        cls.secs = p.elf_index.sections(cls.data)
        cls.facts = p.describe(cls.data)

    def test_artifact_digest(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), p.SHA256)
        with self.assertRaises(ValueError):
            p.verify_digest(b'wrong artifact')

    def test_all_field_keys_and_offsets(self):
        rows = self.facts['fields']
        self.assertEqual([r['key'] for r in rows], [
            'coin', 'szi', 'leverage', 'entryPx', 'positionValue', 'unrealizedPnl',
            'returnOnEquity', 'liquidationPx', 'marginUsed', 'maxLeverage', 'cumFunding'])
        self.assertEqual([r['record_offset'] for r in rows],
                         ['0x20', '0x48', '0x38', '0x0', '0x50', '0x58', '0x60', '0x10', '0x68', '0x88', '0x70'])
        self.assertEqual(sum(r['class'] == 'optional_float' for r in rows), 2)
        self.assertEqual(sum(r['class'] == 'float_writer' for r in rows), 5)

    def test_outer_type_and_position(self):
        self.assertEqual([r['key'] for r in self.facts['outer_fields']], ['type', 'position'])
        self.assertEqual([r['text'] for r in self.facts['outer_type']], ['FAssetPosition', 'oneWay'])
        self.assertEqual(self.facts['optional_tag_compare']['equal'], 1)
        self.assertEqual(self.facts['optional_tag_compare']['other_target_va'], '0x29fa4c5')

    def test_format_descriptor_and_callback(self):
        descriptor = self.facts['format_descriptor']
        self.assertEqual(descriptor['tag'], '0xc5')
        self.assertEqual(descriptor['options'], '0x70000020')
        self.assertEqual(descriptor['immediate_second_u16'], 10)
        self.assertEqual(descriptor['float_callback_va'], '0x1571d50')

    def test_all_failure_bitmasks_and_first_error(self):
        counts = [0] * 12
        for mask in range(2048):
            first = p.first_failure(mask)
            expected = (mask & -mask).bit_length() - 1 if mask else None
            self.assertEqual(first, expected)
            counts[11 if first is None else first] += 1
        self.assertEqual(counts, [1024, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1, 1])
        for invalid in (-1, 2048, None):
            with self.assertRaises(ValueError):
                p.first_failure(invalid)

    def test_branch_encodings(self):
        rows = self.facts['branches']
        self.assertEqual(len(rows), 21)
        self.assertTrue(all(r['target_va'] == '0x2a3d26a' for r in rows[:10]))
        self.assertEqual(rows[10]['target_va'], '0x2a3d28d')
        self.assertEqual(rows[10]['encoding'], '7423')

    def test_optional_sentinel_and_key_lengths(self):
        rows = {r['site_va']: r for r in self.facts['branches']}
        self.assertEqual(rows['0x29fa3eb']['condition'], 'o')
        self.assertEqual(rows['0x29fa3eb']['target_va'], '0x29fa5ac')
        self.assertEqual(rows['0x29fa5b0']['condition'], 'ne')
        self.assertEqual(rows['0x29fa5b0']['target_va'], '0x29fa5de')
        self.assertEqual([f['key_length'] for f in self.facts['fields']
                          if f['class'] == 'optional_float'], [7, 13])
        self.assertEqual(p.read(self.data, self.secs, 0x29fa3e6, 5), bytes.fromhex('31c0483b07'))
        self.assertEqual(p.read(self.data, self.secs, 0x29fa5ac, 4), bytes.fromhex('4883fb1e'))

    def test_corrupt_subject_instruction_rejected(self):
        changed = bytearray(self.data)
        changed[p.offset(self.secs, 0x29fa47b, 1)] ^= 1
        with self.assertRaises(ValueError):
            p.describe(changed)

    def test_corrupt_field_literal_rejected(self):
        changed = bytearray(self.data)
        changed[p.offset(self.secs, 0x42065b, 1)] ^= 1
        with self.assertRaises(ValueError):
            p.describe(changed)

    def test_corrupt_descriptor_rejected(self):
        changed = bytearray(self.data)
        changed[p.offset(self.secs, 0x20ad58, 1)] ^= 1
        with self.assertRaises(ValueError):
            p.describe(changed)

    def test_changed_relocation_type_rejected(self):
        changed = bytearray(self.data)
        sec = next(s for s in self.secs if s['name'] == '.rela.dyn')
        matches = [i for i in range(sec['offset'], sec['offset'] + sec['size'], 24)
                   if struct.unpack_from('<Q', changed, i)[0] == 0x56d5450]
        self.assertEqual(len(matches), 1)
        struct.pack_into('<Q', changed, matches[0] + 8, 7)
        with self.assertRaises(ValueError):
            p.relocation(changed, self.secs, 0x56d5450)

    def test_corrupt_callback_relocation_rejected(self):
        changed = bytearray(self.data)
        sec = next(s for s in self.secs if s['name'] == '.rela.dyn')
        matches = [i for i in range(sec['offset'], sec['offset'] + sec['size'], 24)
                   if struct.unpack_from('<Q', changed, i)[0] == 0x576ea18]
        self.assertEqual(len(matches), 1)
        addend = struct.unpack_from('<q', changed, matches[0] + 16)[0]
        struct.pack_into('<q', changed, matches[0] + 16, addend + 1)
        with self.assertRaises(ValueError):
            p.describe(changed)

    def test_duplicate_fde_rejected(self):
        cies, fdes = p.fde_extents.eh_frame_records(self.data, self.secs)
        row = next(r for r in fdes if r['start'] == 0x2a3d0a0)
        with mock.patch.object(p.fde_extents, 'eh_frame_records', return_value=(cies, fdes + [row])):
            with self.assertRaises(ValueError):
                p.describe(self.data)

    def test_unmapped_and_nobits_fail(self):
        with self.assertRaises(ValueError):
            p.offset(self.secs, 0xffffffffffffffff, 1)
        bss = next(s for s in self.secs if s['name'] == '.bss')
        with self.assertRaises(ValueError):
            p.offset(self.secs, bss['address'], 1)
        with self.assertRaises(ValueError):
            p.offset(self.secs, 0, 0)

    def test_bad_branch_and_call_encodings(self):
        with self.assertRaises(ValueError):
            p.branch(self.data, self.secs, 0x29fa47b)
        with self.assertRaises(ValueError):
            p.rel32(self.data, self.secs, 0x2a342b0, b'\xe8')

    def test_finite_model_boundaries(self):
        expected = {
            0: '0.0', 0x8000000000000000: '0.0', 0x3ff0000000000000: '1.0',
            0x3da5fd7fe1796495: '0.0', 0x3ddb7cdfd9d7bdbb: '0.0000000001',
            0x3f40000000000000: '0.0004882812', 0x3f58000000000000: '0.0014648438',
            0xbfd5555555555555: '-0.3333333333',
        }
        for bits, text in expected.items():
            self.assertEqual(p.ideal_fixed_ten(bits), text)
        for bits in (0x7ff0000000000000, 0xfff0000000000000, 0x7ff8000000000001, -1, 1 << 64):
            with self.assertRaises(ValueError):
                p.ideal_fixed_ten(bits)

    def test_conditional_zero_interval_full_binary64_domain(self):
        rows = p.conditional_zero_region(10)
        self.assertEqual(rows[0]['last_bits'], '3dcb7cdfd9d7bdba')
        self.assertEqual(rows[1]['last_bits'], 'bdcb7cdfd9d7bdba')
        self.assertEqual(rows[0]['first_outside_bits'], '3dcb7cdfd9d7bdbb')
        self.assertEqual(rows[1]['first_outside_bits'], 'bdcb7cdfd9d7bdbb')
        self.assertEqual(rows[0]['patterns'], rows[1]['patterns'])
        with self.assertRaises(ValueError):
            p.conditional_zero_region(9)

    def test_model_against_independent_python_formatter(self):
        # Model comparison only, not a target-execution claim.
        rng = random.Random(934015)
        checked = 0
        for _ in range(2048):
            bits = rng.getrandbits(64)
            if bits >> 52 & 0x7ff == 0x7ff:
                continue
            value = struct.unpack('<d', bits.to_bytes(8, 'little'))[0]
            rendered = format(value, '.10f')
            rendered = rendered.rstrip('0')
            if rendered.endswith('.'):
                rendered += '0'
            if rendered == '-0.0':
                rendered = '0.0'
            self.assertEqual(p.ideal_fixed_ten(bits), rendered)
            checked += 1
        self.assertGreater(checked, 2000)

    def test_reproducible_in_memory(self):
        first = p.outputs(self.data)
        second = p.outputs(self.data)
        self.assertEqual(first, second)
        self.assertEqual(sorted(first), ['branches.tsv', 'conditional-model.tsv', 'conditional-zero-region.tsv', 'evidence.json', 'failure-model.tsv', 'fields.tsv', 'optional-entry-classes.tsv', 'tag-classes.tsv', 'windows.tsv'])


if __name__ == '__main__':
    unittest.main()
