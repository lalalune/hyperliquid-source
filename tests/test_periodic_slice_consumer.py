import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from periodic_slice_consumer import analyze, check_identity
from elf_index import sections

PACKET = ROOT / 'research/work-items/RE-001-periodic-slice-consumer-94'


class PeriodicSliceConsumer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
        check_identity(cls.data)
        cls.secs = sections(cls.data)
        rel = next(s for s in cls.secs if s['name'] == '.rela.dyn')
        cls.relocations = {struct.unpack_from('<Q', cls.data, off)[0]: off
                           for off in range(rel['offset'], rel['offset'] + rel['size'], 24)}

    def offset(self, va):
        sec = next(s for s in self.secs if s['type'] != 8
                   and s['address'] <= va < s['address'] + s['size'])
        return sec['offset'] + va - sec['address']

    def test_complete_report_reproduces(self):
        self.assertEqual(analyze(self.data), json.loads((PACKET / 'records.json').read_text(encoding='utf-8')))

    def test_identity_rejects_corruption(self):
        data = bytearray(self.data)
        data[self.offset(0x432f9f2)] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            check_identity(data)

    def test_code_and_literal_controls_below_identity_gate(self):
        for va in (0x432f9f2, 0x432fa34, 0x432fa42, 0x432fa6d,
                   0x432fa80, 0x432fa84, 0x432facd, 0x432faf8,
                   0x432fb1b, 0x144a8b5, 0x144ab79, 0x144abdb,
                   0x144ac18, 0x219c50, 0x219c52, 0x1ef2de,
                   0x5666bf0, 0x1e451a, 0x5752298):
            with self.subTest(va=hex(va)):
                data = bytearray(self.data)
                data[self.offset(va)] ^= 1
                with self.assertRaises(ValueError):
                    analyze(data)

    def test_scoped_relocation_retargets(self):
        for slot in (0x576e990, 0x5666be0, 0x5752288, 0x576e8d0, 0x576e8d8, 0x576dfe0):
            data = bytearray(self.data)
            off = self.relocations[slot]
            info = struct.unpack_from('<Q', data, off + 8)[0]
            if info == 8:
                value = struct.unpack_from('<q', data, off + 16)[0]
                struct.pack_into('<q', data, off + 16, value + 1)
            else:
                struct.pack_into('<Q', data, off + 8, info + (1 << 32))
            with self.subTest(slot=hex(slot)), self.assertRaises(ValueError):
                analyze(data)

    def test_named_import_string_corruptions(self):
        sym = next(s for s in self.secs if s['name'] == '.dynsym')
        strings = next(s for s in self.secs if s['name'] == '.dynstr')
        for slot in (0x576e8d0, 0x576e8d8, 0x576dfe0):
            data = bytearray(self.data)
            info = struct.unpack_from('<Q', data, self.relocations[slot] + 8)[0]
            nameoff = struct.unpack_from('<I', data, sym['offset'] + (info >> 32) * 24)[0]
            data[strings['offset'] + nameoff] ^= 1
            with self.subTest(slot=hex(slot)), self.assertRaisesRegex(ValueError, 'import'):
                analyze(data)

    def test_complete_native_export_is_byte_bound(self):
        report = analyze(self.data)
        decoded = {}
        for line in (PACKET / 'capstone-5.0.6.txt').read_text(encoding='utf-8').splitlines():
            if line.startswith('#') or not line.strip():
                continue
            address, raw, _ = line.split('\t', 2)
            self.assertNotIn(int(address, 16), decoded)
            decoded[int(address, 16)] = bytes.fromhex(raw)
        total = 0
        for window in report['windows']:
            start, end = int(window['start_va'], 16), int(window['end_va_exclusive'], 16)
            cursor = start
            chunks = []
            while cursor < end:
                raw = decoded[cursor]
                self.assertTrue(raw)
                chunks.append(raw)
                total += 1
                cursor += len(raw)
            self.assertEqual(cursor, end)
            body = b''.join(chunks)
            self.assertEqual(hashlib.sha256(body).hexdigest(), window['sha256'])
            self.assertEqual(body, self.data[self.offset(start):self.offset(start) + end - start])
        self.assertEqual(total, 427)
        self.assertEqual(len(decoded), total)


if __name__ == '__main__':
    unittest.main()
