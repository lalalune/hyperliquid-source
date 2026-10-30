"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_tagged_copy as tagged_copy
from elf_index import sections


class TaggedCopyEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not tagged_copy.TARGET.is_file() or tagged_copy.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = tagged_copy.inspect(tagged_copy.TARGET)
        cls.data = tagged_copy.TARGET.read_bytes()
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
        self.assertEqual(self.result['window'], (0x22155a0, 0x22155c0))
        self.assertEqual(self.result['body_sha256'],
                         '0bddd01c00d5d54bdb1badbcffae15d636eeae992b72c7d60d09f2f7ec16967b')
        self.assertEqual(self.result['relocation_slots'], [])
        self.assertEqual(self.result['direct_callers'], [])

    def test_body_lock(self):
        bad = self.mutated(0x22155a0, b'\x90')
        with self.assertRaises(ValueError):
            tagged_copy.analyze(bad)

    def test_tag_lock(self):
        bad = self.mutated(0x22155b4, b'\x15')
        with self.assertRaises(ValueError):
            tagged_copy.analyze(bad)

    def test_fde_lock(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        bad = bytearray(self.data)
        bad[eh['offset'] + 0x573cc + 8] ^= 0x01
        with self.assertRaises(ValueError):
            tagged_copy.analyze(bytes(bad))

    def test_next_fde_lock(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        bad = bytearray(self.data)
        bad[eh['offset'] + 0x573e0 + 8] ^= 0x01
        with self.assertRaises(ValueError):
            tagged_copy.analyze(bytes(bad))

    def test_no_padding_lock(self):
        # The next FDE starts exactly at the FDE end; moving its PC must fail.
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        bad = bytearray(self.data)
        bad[eh['offset'] + 0x573e0 + 12] ^= 0x01
        with self.assertRaises(ValueError):
            tagged_copy.analyze(bytes(bad))

    def test_copy_rule_edges(self):
        self.assertEqual(tagged_copy.build(b'\x00' * 32),
                         struct.pack('<Q', 0x8000000000000014) + b'\x00' * 32)
        self.assertEqual(tagged_copy.build(bytes(range(32))),
                         struct.pack('<Q', 0x8000000000000014) + bytes(range(32)))
        self.assertEqual(tagged_copy.build(b'\xff' * 32),
                         struct.pack('<Q', 0x8000000000000014) + b'\xff' * 32)
        with self.assertRaises(ValueError):
            tagged_copy.build(b'\x00' * 31)

    def test_retained_evidence(self):
        packet = Path(__file__).resolve().parents[1] / 'research/work-items/foundation-tagged-copy-94/evidence.json'
        retained = json.loads(packet.read_text())
        self.assertEqual(retained['target_sha256'], tagged_copy.SHA256)
        self.assertEqual(retained['function']['start_va'], '0x22155a0')
        self.assertEqual(retained['function']['end_va_exclusive'], '0x22155c0')
        self.assertEqual(retained['function']['bytes'], 32)
        self.assertEqual(retained['function']['sha256'], self.result['body_sha256'])
        self.assertEqual(retained['function']['padding_bytes'], 0)
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'], [])
        self.assertEqual(retained['incoming_pattern_scan']['relocation_slots'], [])

    def test_window_disassembly(self):
        packet = Path(__file__).resolve().parents[1] / 'research/work-items/foundation-tagged-copy-94/window.objdump.txt'
        window = packet.read_text()
        self.assertIn('22155a0:', window)
        self.assertIn('mov    %rdi,%rax', window)
        self.assertIn('movups (%rsi),%xmm0', window)
        self.assertIn('movups 0x10(%rsi),%xmm1', window)
        self.assertIn('movups %xmm1,0x18(%rdi)', window)
        self.assertIn('movups %xmm0,0x8(%rdi)', window)
        self.assertIn('movabs $0x8000000000000014,%rcx', window)
        self.assertIn('mov    %rcx,(%rdi)', window)
        self.assertIn('22155bf:', window)
        self.assertIn('ret', window)

    def test_frames_retained(self):
        packet = Path(__file__).resolve().parents[1] / 'research/work-items/foundation-tagged-copy-94/frames.txt'
        frames = packet.read_text()
        self.assertIn('pc=00000000022155a0..00000000022155c0', frames)
        self.assertIn('pc=00000000022155c0..0000000002215859', frames)
