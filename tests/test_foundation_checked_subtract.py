"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_checked_subtract as checked_subtract
from elf_index import sections


class CheckedSubtractEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not checked_subtract.TARGET.is_file() or checked_subtract.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = checked_subtract.inspect(checked_subtract.TARGET)
        cls.data = checked_subtract.TARGET.read_bytes()
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
        self.assertEqual(self.result['window'], (0x2760a10, 0x2760a67))
        self.assertEqual(self.result['body_sha256'],
                         '29e3e8147b0e797ec3a26155cf5346c29f3e36254bd5fc004380e3d151afd8d1')
        self.assertEqual(self.result['relocation_slots'], [])
        self.assertEqual(self.result['direct_callers'],
                         [0x2760924, 0x276095c, 0x2760998])

    def test_body_lock(self):
        bad = self.mutated(0x2760a10, b'\x90')
        with self.assertRaises(ValueError):
            checked_subtract.analyze(bad)

    def test_subtract_lock(self):
        # Word-0 subtract opcode at offset 3.
        bad = self.mutated(0x2760a13, b'\x31')
        with self.assertRaises(ValueError):
            checked_subtract.analyze(bad)

    def test_borrow_trick_lock(self):
        # add $0xff,%al at offset 39: flipping the constant breaks the trick.
        bad = self.mutated(0x2760a10 + 40, b'\xfe')
        with self.assertRaises(ValueError):
            checked_subtract.analyze(bad)

    def test_fde_lock(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        bad = bytearray(self.data)
        bad[eh['offset'] + 0xa0cd0 + 8] ^= 0x01
        with self.assertRaises(ValueError):
            checked_subtract.analyze(bytes(bad))

    def test_next_fde_lock(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        bad = bytearray(self.data)
        bad[eh['offset'] + 0x40fce8 + 8] ^= 0x01
        with self.assertRaises(ValueError):
            checked_subtract.analyze(bytes(bad))

    def test_padding_lock(self):
        bad = self.mutated(0x2760a67, b'\x90')
        with self.assertRaises(ValueError):
            checked_subtract.analyze(bad)

    def test_caller_lock(self):
        # Flipping a caller call target must change the incoming-call list.
        bad = self.mutated(0x2760924 + 1, b'\x01')
        with self.assertRaises(ValueError):
            checked_subtract.analyze(bad)

    def test_subtract_rule_edges(self):
        self.assertEqual(checked_subtract.build(b'\x00' * 32, b'\x00' * 32),
                         (1, b'\x00' * 32, b'\x00' * 32))
        self.assertEqual(checked_subtract.build(b'\x00' * 32, b'\x01' + b'\x00' * 31),
                         (0, None, b'\xff' * 32))
        self.assertEqual(checked_subtract.build(b'\xff' * 32, b'\x01' + b'\x00' * 31),
                         (1, b'\xfe' + b'\xff' * 31, b'\xfe' + b'\xff' * 31))
        m = (1 << 192).to_bytes(32, 'little')
        s = (1).to_bytes(32, 'little')
        self.assertEqual(checked_subtract.build(m, s),
                         (1, ((1 << 192) - 1).to_bytes(32, 'little'),
                          ((1 << 192) - 1).to_bytes(32, 'little')))
        # Equal top words with a low-word borrow: failure, minuend still rewritten.
        m = (1 << 192).to_bytes(32, 'little')
        s = ((1 << 192) + 1).to_bytes(32, 'little')
        self.assertEqual(checked_subtract.build(m, s),
                         (0, None, ((1 << 256) - 1).to_bytes(32, 'little')))
        with self.assertRaises(ValueError):
            checked_subtract.build(b'\x00' * 31, b'\x00' * 32)

    def test_evidence_json_matches(self):
        retained = json.loads((Path(__file__).resolve().parents[1] /
            'research/work-items/foundation-checked-subtract-94/evidence.json'
        ).read_text())
        self.assertEqual(retained['function']['sha256'], self.result['body_sha256'])
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'],
                         [hex(c) for c in self.result['direct_callers']])


if __name__ == '__main__':
    unittest.main()
