import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from build_name_guards import analyze, check_identity, signed_boundary_branch
from elf_index import sections

PACKET = ROOT / 'research/work-items/RE-001-build-name-guards-94'


class BuildNameGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
        check_identity(cls.data)
        cls.secs = sections(cls.data)

    def offset(self, va):
        sec = next(s for s in self.secs if s['type'] != 8
                   and s['address'] <= va < s['address'] + s['size'])
        return sec['offset'] + va - sec['address']

    def test_complete_report_reproduces(self):
        self.assertEqual(analyze(self.data), json.loads((PACKET / 'records.json').read_text(encoding='utf-8')))

    def test_code_and_data_corruptions_below_digest_gate(self):
        for va in (0x143efe8, 0x143eff0, 0x143eff3, 0x143eff8, 0x143f00a,
                   0x143f01a, 0x143f020, 0x143f022, 0x143f11f, 0x143f124,
                   0x143f126, 0x143f1f6, 0x2194aa, 0x2194b0, 0x200676,
                   0x566a0a0, 0x566a0b8):
            with self.subTest(va=hex(va)):
                data = bytearray(self.data)
                data[self.offset(va)] ^= 1
                with self.assertRaises(ValueError):
                    analyze(data)

    def test_relocation_retargets_are_rejected(self):
        rel = next(s for s in self.secs if s['name'] == '.rela.dyn')
        for slot in (0x566a090, 0x566a0a8):
            data = bytearray(self.data)
            off = next(o for o in range(rel['offset'], rel['offset'] + rel['size'], 24)
                       if struct.unpack_from('<Q', data, o)[0] == slot)
            addend = struct.unpack_from('<q', data, off + 16)[0]
            struct.pack_into('<q', data, off + 16, addend + 1)
            with self.subTest(slot=hex(slot)), self.assertRaisesRegex(ValueError, 'relocation'):
                analyze(data)

    def test_identity_rejects_changed_capture(self):
        data = bytearray(self.data)
        data[self.offset(0x143f126)] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            check_identity(data)

    def test_isolated_signed_condition_covers_all_byte_values(self):
        # Independent bit-prefix form vs architectural CMP/JL flag equations.
        for byte in range(256):
            self.assertEqual(signed_boundary_branch(byte), byte & 0xc0 == 0x80)
        self.assertEqual(sum(signed_boundary_branch(b) for b in range(256)), 64)

    def test_native_export_covers_original_scope(self):
        window = analyze(self.data)['windows'][0]
        decoded = {}
        for line in (PACKET / 'capstone-5.0.6.txt').read_text(encoding='utf-8').splitlines():
            if line.startswith('#') or not line.strip():
                continue
            address, raw, _ = line.split('\t', 2)
            self.assertNotIn(int(address, 16), decoded)
            decoded[int(address, 16)] = bytes.fromhex(raw)
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


if __name__ == '__main__':
    unittest.main()
