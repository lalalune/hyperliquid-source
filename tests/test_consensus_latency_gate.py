import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from consensus_latency_gate import analyze, check_identity
from elf_index import sections

PACKET = ROOT / 'research/work-items/RE-001-consensus-latency-gate-94'


class ConsensusLatencyGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
        check_identity(cls.data)
        cls.secs = sections(cls.data)

    def offset(self, va):
        s = next(s for s in self.secs if s['type'] != 8
                 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def test_complete_report_reproduces(self):
        self.assertEqual(analyze(self.data), json.loads((PACKET / 'records.json').read_text(encoding='utf-8')))

    def test_identity_gate_rejects_corruption(self):
        data = bytearray(self.data)
        data[self.offset(0x4a116d0)] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            check_identity(data)

    def test_instruction_controls_below_digest_gate(self):
        for va in (0x4a1142c, 0x4a1155f, 0x4a115cf, 0x4a116c6,
                   0x4a116ce, 0x4a116d0, 0x4a116dd, 0x13c9f7e,
                   0x13c9f86, 0x13c9f8f, 0x13c9f95):
            with self.subTest(va=hex(va)):
                data = bytearray(self.data)
                data[self.offset(va)] ^= 1
                with self.assertRaisesRegex(ValueError, 'Control changed'):
                    analyze(data)

    def test_data_and_table_controls_below_digest_gate(self):
        for va in (0x703834, 0x4a1149c, 0x1fd775, 0x1e0787, 0x1fea2d, 0x5736738):
            with self.subTest(va=hex(va)):
                data = bytearray(self.data)
                data[self.offset(va)] ^= 1
                with self.assertRaises(ValueError):
                    analyze(data)

    def test_relocation_retarget_is_rejected(self):
        rel = next(s for s in self.secs if s['name'] == '.rela.dyn')
        for slot in (0x5736728, 0x576e8f8, 0x576efb0):
            data = bytearray(self.data)
            offset = next(o for o in range(rel['offset'], rel['offset'] + rel['size'], 24)
                          if struct.unpack_from('<Q', data, o)[0] == slot)
            addend = struct.unpack_from('<q', data, offset + 16)[0]
            struct.pack_into('<q', data, offset + 16, addend + 1)
            with self.subTest(slot=hex(slot)), self.assertRaisesRegex(ValueError, 'relocation'):
                analyze(data)

    def test_retained_native_export_is_complete_and_byte_bound(self):
        report = analyze(self.data)
        lines = (PACKET / 'capstone-5.0.6.txt').read_text(encoding='utf-8').splitlines()
        decoded = {}
        for line in lines:
            if line.startswith('#') or not line.strip():
                continue
            address, raw, _ = line.split('\t', 2)
            self.assertNotIn(int(address, 16), decoded)
            decoded[int(address, 16)] = bytes.fromhex(raw)
        for window in report['windows']:
            start, end = int(window['start_va'], 16), int(window['end_va_exclusive'], 16)
            cursor = start
            chunks = []
            while cursor < end:
                raw = decoded[cursor]
                self.assertTrue(raw)
                chunks.append(raw)
                cursor += len(raw)
            self.assertEqual(cursor, end)
            body = b''.join(chunks)
            self.assertEqual(hashlib.sha256(body).hexdigest(), window['sha256'])
            self.assertEqual(body, self.data[self.offset(start):self.offset(start) + end - start])
        self.assertEqual(len(decoded), 301)


if __name__ == '__main__':
    unittest.main()
