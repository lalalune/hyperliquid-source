"""Tests of the #115 three-digit leaf and its fail-closed evidence generator."""
import json
import mmap
from pathlib import Path
import re
import shutil
import struct
import tempfile
import unittest

from tools import node115_three_digit_decimal as bind


class ThreeDigitDecimalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet = bind.PACKET
        cls.records = json.loads((cls.packet/'records.json').read_text())
        cls.body = bytes.fromhex(cls.records['function']['body_hex'])

    def test_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            bind.generate(bind.TARGET, out)
            for name in ('records.json', 'MANIFEST.sha256'):
                self.assertEqual((out/name).read_bytes(), (self.packet/name).read_bytes())

    def test_readme_counts(self):
        readme = (self.packet/'README.md').read_text()
        section = readme.split('<!-- counts:start -->')[1].split('<!-- counts:end -->')[0]
        found = dict((key, int(value)) for key, value in re.findall(r'^\| ([a-z_0-9]+) \| (\d+) \|$', section, re.M))
        self.assertEqual(found, self.records['counts'])

    def test_exact_instruction_coverage_and_edges(self):
        rows = bind.decode(self.body)
        self.assertEqual(rows, self.records['function']['instructions'])
        self.assertEqual(sum(len(bytes.fromhex(x['bytes'])) for x in rows), bind.END-bind.START)
        self.assertEqual([x['target'] for x in rows if 'target' in x], [0x179b396, 0x179b399])
        self.assertEqual(sum(x['instruction'] == 'ret' for x in rows), 2)

    def test_all_canonical_values(self):
        for n in range(100, 1000):
            self.assertEqual(bind.model(3, str(n).encode()), n)

    def test_all_byte_values_in_each_position(self):
        # Compare the independent high-level model with the actual low-byte
        # range-check equations extracted from the instruction operands.
        for pos in range(3):
            for value in range(256):
                b = bytearray(b'123')
                b[pos] = value
                a, x, y = b
                invalid = ((a - 58) & 255) < 247 or ((x - 48) & 255) >= 10 or ((y - 48) & 255) >= 10
                expected = 0 if invalid else ((a-48) & 255)*100 + (((x-48) & 255)*10 & 255) + ((y-48) & 255)
                self.assertEqual(bind.model(3, b), expected, (pos, value))

    def test_length_and_boundaries(self):
        for length in (0, 1, 2, 4, 2**64-1):
            self.assertEqual(bind.model(length, b''), 0)
        for data in (b'000', b'099', b' 10', b'1000', b':00', b'1/0', b'10:', b'\xff00'):
            if len(data) == 3:
                self.assertEqual(bind.model(3, data), 0)
        with self.assertRaises(ValueError):
            bind.model(3, b'12')
        self.assertEqual(bind.model(3, b'1000'), 100)
        self.assertEqual(bind.model(3, b'999'), 999)

    def test_corrupted_window_and_branch_are_rejected(self):
        for offset in (0, 15, 24, 53, len(self.body)-1):
            bad = bytearray(self.body)
            bad[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                bind.decode(bad)
        bad = bytearray(self.body)
        bad[5] ^= 1
        with self.assertRaises(ValueError):
            bind.decode(bad)

    def test_shifted_fde_and_bad_cie_rejected(self):
        frame = self.records['function']['fde']
        raw = bytearray.fromhex(frame['raw_hex'])
        struct.pack_into('<i', raw, 8, struct.unpack_from('<i', raw, 8)[0]+1)
        with self.assertRaises(ValueError):
            bind.check_frame(raw, bind.FDE, bind.CIE, bind.START, bind.END)
        raw = bytearray.fromhex(frame['raw_hex'])
        raw[4] ^= 1
        with self.assertRaises(ValueError):
            bind.check_frame(raw, bind.FDE, bind.CIE, bind.START, bind.END)

    def test_wrong_direct_call_target_rejected(self):
        raw = bytearray.fromhex(self.records['confirmed_caller']['bytes'])
        raw[1] ^= 1
        with self.assertRaises(ValueError):
            bind.check_call(raw)

    def test_digest_rejects_same_size_actual_window_mutation_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)/'mutant'
            shutil.copyfile(bind.TARGET, target)
            with target.open('r+b') as f:
                with mmap.mmap(f.fileno(), 0) as data:
                    data[self.records['function']['file_offset']] ^= 1
            out = Path(tmp)/'out'
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                bind.generate(target, out)
            self.assertFalse(out.exists())

    def test_wrong_digest_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, out = Path(tmp)/'wrong', Path(tmp)/'out'
            target.write_bytes(b'not the target')
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                bind.generate(target, out)
            self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
