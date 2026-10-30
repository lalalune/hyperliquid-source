"""Actual node94 static controls; no inferred reference implementation is executed."""
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import api_suffix_static as api
from fde_extents import fde_extents


@unittest.skipUnless(api.TARGET.stat().st_size == 91774280, 'materialize the pinned node94 capture')
class ApiSuffixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = api.TARGET.read_bytes()
        cls.image = api.Image(cls.data)
        cls.expected = api.analyze(cls.data)

    def test_actual_table_and_literal_bindings(self):
        self.assertEqual(self.expected['function']['bytes'], 1052)
        self.assertEqual(len(self.expected['dispatch']['arm_vas']), 6)
        self.assertEqual(self.expected['dispatch']['valid_tag_to_arm_index'],
                         {'0': 5, '1': 5, '2': 0, '3': 1, '4': 2, '5': 3, '6': 4})
        self.assertEqual(self.expected['source']['line'], 90)
        self.assertFalse(self.expected['captured_binary_executed'])

    def test_actual_instruction_table_literal_and_source_corruptions(self):
        # Each in-memory mutation is below the digest gate, checking the relevant
        # structural control rather than merely failing the whole-file hash.
        for va in [0x1450af7, 0x219998, 0x1450b18, 0x219d3d, 0x1450dff + 3,
                   0x2272d11, 0x2006b8, 0x566ab30 + 8, 0x1450d51]:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                changed[self.image.offset(va, 1)] ^= 1
                with self.assertRaises(ValueError):
                    api.analyze(changed)

    def test_fde_boundary_corruption_rejected(self):
        _, frames, _ = fde_extents(self.data)
        frame = next(f for f in frames if f['start'] == api.START)
        changed = bytearray(self.data)
        offset = self.image.offset(frame['fde'] + 12, 4)
        struct.pack_into('<i', changed, offset, api.END - api.START + 1)
        with self.assertRaisesRegex(ValueError, 'FDE extent'):
            api.analyze(changed)

    @unittest.skipUnless(shutil.which('objdump') and shutil.which('readelf'), 'GNU binutils required')
    def test_real_cli_packet_is_reproducible(self):
        packet = ROOT / 'research/work-items/RE-001-api-suffix-dispatch-94'
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'output'
            result = api.generate(api.TARGET, output)
            self.assertEqual(result, self.expected)
            for name in ('records.json', 'function.objdump.txt', 'caller.objdump.txt', 'frames.txt'):
                self.assertEqual((output / name).read_bytes(), (packet / name).read_bytes(), name)

    def test_digest_gate_rejects_wrong_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'wrong.elf'
            path.write_bytes(b'not a captured executable')
            with self.assertRaises(ValueError):
                api.generate(path, Path(directory) / 'out')
            self.assertFalse((Path(directory) / 'out').exists())


if __name__ == '__main__':
    unittest.main()
