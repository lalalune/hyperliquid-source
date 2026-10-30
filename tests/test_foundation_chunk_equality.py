"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_chunk_equality as chunk
from elf_index import sections


class ChunkEqualityEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not chunk.TARGET.is_file() or chunk.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = chunk.inspect(chunk.TARGET)
        cls.data = chunk.TARGET.read_bytes()
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
        self.assertEqual(self.result['window'], (0x14b52b0, 0x14b52d1))
        self.assertEqual(self.result['body_sha256'],
                         '144441a09d34c95917862103ef8752f34e7970796b0827f4c2d67c0a3a07bc62')
        self.assertEqual(self.result['relocation_slots'], ['0x566e618'])
        self.assertEqual(self.result['direct_callers'], [])

    def test_body_lock(self):
        bad = self.mutated(0x14b52b0, b'\x90')
        with self.assertRaises(ValueError):
            chunk.analyze(bad)

    def test_padding_lock(self):
        bad = self.mutated(0x14b52d1, b'\x90')
        with self.assertRaises(ValueError):
            chunk.analyze(bad)

    def test_fde_lock(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        bad = bytearray(self.data)
        bad[eh['offset'] + 0xde88 + 8] ^= 0x01
        with self.assertRaises(ValueError):
            chunk.analyze(bytes(bad))

    def test_constant_lock(self):
        bad = self.mutated(0x208300, b'\x00')
        with self.assertRaises(ValueError):
            chunk.analyze(bad)

    def test_slot_lock(self):
        bad = self.mutated(0x566e618, struct.pack('<Q', 1))
        with self.assertRaises(ValueError):
            chunk.analyze(bad)

    def test_decide_edges(self):
        self.assertEqual(chunk.decide(chunk.CONSTANT), 'base+0x38')
        first = bytearray(chunk.CONSTANT)
        first[0] ^= 0x01
        self.assertEqual(chunk.decide(first), 'zero')
        last = bytearray(chunk.CONSTANT)
        last[15] ^= 0x80
        self.assertEqual(chunk.decide(last), 'zero')
        self.assertEqual(chunk.decide(bytes(16)), 'zero')
        with self.assertRaises(ValueError):
            chunk.decide(bytes(15))

    def test_retained_evidence_matches(self):
        packet = Path(__file__).resolve().parents[1] / 'research/work-items/foundation-chunk-equality-94'
        retained = json.loads((packet / 'evidence.json').read_text())
        self.assertEqual(retained['target_sha256'], chunk.SHA256)
        self.assertEqual(retained['function']['start_va'], '0x14b52b0')
        self.assertEqual(retained['function']['end_va_exclusive'], '0x14b52d1')
        self.assertEqual(retained['function']['bytes'], 33)
        self.assertEqual(retained['function']['sha256'], self.result['body_sha256'])
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'], [])
        self.assertEqual(retained['incoming_pattern_scan']['relocation_slots'],
                         self.result['relocation_slots'])
        window = (packet / 'window.objdump.txt').read_text()
        self.assertIn('14b52b0:', window)
        self.assertIn('movdqu (%rsi),%xmm0', window)
        self.assertIn('pcmpeqb', window)
        self.assertIn('pmovmskb %xmm0,%ecx', window)
        self.assertIn('cmove  %rdx,%rax', window)
        frames = (packet / 'frames.txt').read_text()
        self.assertIn('pc=00000000014b52b0..00000000014b52d1', frames)
        self.assertIn('pc=00000000014b52e0..00000000014b5301', frames)


if __name__ == '__main__':
    unittest.main()
