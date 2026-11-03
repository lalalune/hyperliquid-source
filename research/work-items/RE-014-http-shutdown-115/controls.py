#!/usr/bin/env python3
"""Corrupt real capture bytes/export records; no target execution or emulation."""
import copy
import gzip
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('shutdown115', HERE/'verify.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class CorruptionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (v.ROOT/'artifacts/node/115/hl-node').read_bytes()
        cls.image = v.Image(cls.data)
        cls.exports = json.loads(gzip.decompress((HERE/'capstone.json.gz').read_bytes()))
        cls.records = json.loads((HERE/'records.json').read_text())
        v.require(len(cls.data) == v.SIZE and v.hashlib.sha256(cls.data).hexdigest() == v.DIGEST,
                  'Controls require the real pinned115 input')

    def test_real_capture_positive(self):
        v.check_observations(self.image)
        self.assertEqual(v.check_exports(self.image, self.exports, self.records)['bytes'], 15620)

    def test_capture_semantic_corruptions(self):
        # Calls the observer directly, so failures cannot be attributed to an outer SHA check.
        controls = [('shutdown-how', 0x5ce0b3a), ('class7-branch', 0x5ce0b63),
                    ('raw-result-register', 0x5ce0b73), ('shutdown-import-call', 0x2b04519),
                    ('errno-import-call', 0x2b04524), ('classifier-call', 0x2b04536),
                    ('cleanup-call', 0x2b04546), ('cleanup-lowtag', 0x5cdf71c),
                    ('field-offset', 0x2b04560), ('field-clear', 0x2b0456a),
                    ('zero-output-tag', 0x2b04580), ('nonzero-output-tag', 0x2b04949),
                    ('errno107-dispatch', 0x94c95c)]
        for name, va in controls:
            with self.subTest(name=name):
                data = bytearray(self.data); off = self.image.offset(va, 1); data[off] ^= 1
                with self.assertRaises(ValueError):
                    v.check_observations(v.Image(data))

    def test_wrong_import_symbol_is_rejected(self):
        data = bytearray(self.data)
        # This touches actual dynstr, without modifying the call-site bytes.
        pos = data.index(b'__errno_location\0'); data[pos] = ord('X')
        with self.assertRaisesRegex(ValueError, 'Import relocation changed'):
            v.check_observations(v.Image(data))

    def test_export_instruction_byte_corruption(self):
        rows = copy.deepcopy(self.exports)
        rows['0x5ce0b30']['instructions'][0]['bytes'] = '51'
        with self.assertRaisesRegex(ValueError, 'Export address/byte mismatch'):
            v.check_exports(self.image, rows, self.records)

    def test_export_instruction_gap(self):
        rows = copy.deepcopy(self.exports)
        rows['0x5ce0b30']['instructions'].pop(1)
        with self.assertRaisesRegex(ValueError, 'Export address/byte mismatch'):
            v.check_exports(self.image, rows, self.records)

    def test_wrong_fde_extent(self):
        rows = copy.deepcopy(self.records)
        rows['ranges'][0]['end'] = hex(int(rows['ranges'][0]['end'], 16)-1)
        with self.assertRaisesRegex(ValueError, 'FDE extent or LSDA changed'):
            v.check_exports(self.image, self.exports, rows)

    def test_wrong_cie(self):
        rows = copy.deepcopy(self.exports)
        rows['0x5ce0b30']['cie']['fde_encoding'] = 0
        with self.assertRaisesRegex(ValueError, 'Export unwind metadata changed'):
            v.check_exports(self.image, rows, self.records)


if __name__ == '__main__':
    unittest.main(verbosity=2)
