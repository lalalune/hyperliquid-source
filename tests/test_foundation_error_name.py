"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_error_name as error_name
from elf_index import sections


class ErrorNameEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not error_name.TARGET.is_file() or error_name.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = error_name.inspect(error_name.TARGET)
        cls.data = error_name.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def offset(self, va):
        s = next(s for s in self.sections if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return bytes(data)

    def test_identity_and_window(self):
        self.assertEqual(self.result['window'], (0x14b4e20, 0x14b4e48))
        self.assertEqual(self.result['body_sha256'],
                         '33f2a5831269ac71c310ca2e526e7cac1e66416b90fae6f50d5423d3e89355c4')
        self.assertEqual(self.result['relocation_slots'], ['0x566de38'])
        self.assertEqual(self.result['direct_callers'], [])

    def test_body_lock(self):
        bad = self.mutated(0x14b4e20, b'\x90')
        with self.assertRaises(ValueError):
            error_name.analyze(bad)

    def test_padding_lock(self):
        bad = self.mutated(0x14b4e48, b'\x90')
        with self.assertRaises(ValueError):
            error_name.analyze(bad)

    def test_fde_lock(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        bad = bytearray(self.data)
        bad[eh['offset'] + 0xdbe0 + 8] ^= 0x01
        with self.assertRaises(ValueError):
            error_name.analyze(bytes(bad))

    def test_name_lock(self):
        bad = self.mutated(0x21bf92, b'\x00')
        with self.assertRaises(ValueError):
            error_name.analyze(bad)

    def test_second_name_lock(self):
        bad = self.mutated(0x21bfa3, b'\x00')
        with self.assertRaises(ValueError):
            error_name.analyze(bad)

    def test_xor_constant_lock(self):
        bad = self.mutated(0x14b4e26, b'\x02')
        with self.assertRaises(ValueError):
            error_name.analyze(bad)

    def test_length_constant_lock(self):
        bad = self.mutated(0x14b4e2e, b'\x0f')
        with self.assertRaises(ValueError):
            error_name.analyze(bad)

    def test_select_edges(self):
        self.assertEqual(error_name.select(0), (0x21bf92, 17))
        self.assertEqual(error_name.select(1), (0x21bfa3, 14))
        self.assertEqual(error_name.select(2), (0x21bfa3, 23))
        self.assertEqual(error_name.select(3), (0x21bfa3, 20))
        self.assertEqual(error_name.select(4), (0x21bfa3, 29))
        self.assertEqual(error_name.select(255), (0x21bfa3, 776))

    def test_name_slices(self):
        first = self.data[self.offset(0x21bf92):self.offset(0x21bf92) + 17]
        second = self.data[self.offset(0x21bfa3):self.offset(0x21bfa3) + 14]
        self.assertEqual(first, b'invalid character')
        self.assertEqual(second, b'invalid length')
        spanning = self.data[self.offset(0x21bfa3):self.offset(0x21bfa3) + 23]
        self.assertEqual(spanning, b'invalid lengthSystemTim')

    def test_evidence_json_matches(self):
        packet = Path(__file__).resolve().parents[1] / 'research/work-items/foundation-error-name-94'
        retained = json.loads((packet / 'evidence.json').read_text())
        self.assertEqual(retained['function']['sha256'], self.result['body_sha256'])
        self.assertEqual(retained['incoming_pattern_scan']['relocation_slots'],
                         self.result['relocation_slots'])
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'], [])
