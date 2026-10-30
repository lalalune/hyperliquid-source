"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_reserve_grow as rg
from elf_index import sections


class ReserveGrowEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not rg.TARGET.is_file() or rg.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        # Authenticate once; structural mutation controls intentionally bypass
        # the identity gate so each downstream evidence check is exercised.
        cls.result = rg.inspect(rg.TARGET)
        cls.data = rg.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def offset(self, va):
        s = next(s for s in self.sections if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return data

    def test_retained_record_matches_authenticated_target(self):
        record = rg.ROOT / 'research/work-items/foundation-reserve-grow-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_window_and_gate_from_retained_bytes(self):
        window = self.result['windows'][0]
        self.assertEqual(window['start_va'], '0x1520ce0')
        self.assertEqual(window['fde_end_va_exclusive'], '0x1520d41')
        self.assertEqual(window['fde_bytes'], 97)
        self.assertEqual(window['fde_section_offset'], '0x153f4')
        w = self.data[self.offset(0x1520ce0):self.offset(0x1520ce0) + 97]
        # ja at window offset 0x15, displacement 0x16, to the slow arm at 0x39.
        self.assertEqual(w[21], 0x77)
        self.assertEqual(0x1520ce0 + 0x15 + 2 + w[22], 0x1520d19)
        # Retry jump at window offset 0x5f back to the fast path at 0x17.
        self.assertEqual(w[0x5f], 0xeb)
        self.assertEqual(0x1520ce0 + 0x5f + 2 + struct.unpack_from('<b', w, 0x60)[0], 0x1520cf7)
        behavior = self.result['behavior']
        self.assertEqual(behavior['capacity_boundaries'],
                         {'10/4/5': 'fast', '10/4/6': 'fast', '10/4/7': 'slow', '0/0/0': 'fast', '0/0/1': 'slow'})
        self.assertEqual(behavior['padding'], 'fifteen int3 bytes follow the window before the next FDE start')

    def test_memcpy_slot_and_grow_callee_locked_but_not_decoded(self):
        slot = self.result['memcpy_slot']
        self.assertEqual(slot['slot'], '0x576dfe0')
        self.assertEqual(slot['relocation'], 'R_X86_64_GLOB_DAT')
        self.assertEqual(slot['symbol'], 'memcpy@GLIBC_2.14')
        self.assertEqual(slot['symbol_index'], 6)
        self.assertEqual(slot['addend'], 0)
        callee = self.result['grow_callee']
        self.assertEqual(callee['start_va'], '0x1564e60')
        self.assertEqual(callee['fde_end_va_exclusive'], '0x1564eee')
        self.assertFalse(callee['body_decoded'])
        self.assertFalse(callee['runtime_target_named'])
        self.assertIsNone(self.result['inferred_label'])
        # Both call displacements resolve to the claimed targets.
        w = self.data[self.offset(0x1520ce0):self.offset(0x1520ce0) + 97]
        self.assertEqual(0x1520ce0 + 0x21 + 6 + struct.unpack_from('<i', w, 0x23)[0], 0x576dfe0)
        self.assertEqual(0x1520ce0 + 0x50 + 5 + struct.unpack_from('<i', w, 0x51)[0], 0x1564e60)

    def test_identity_rejects_mutation(self):
        with self.assertRaises(ValueError):
            rg.analyze(self.mutated(0x1520ce0, b'\x90'))
        with self.assertRaises(ValueError):
            rg.analyze(self.mutated(0x1520cf2, b'\x48\x39\xd0'))

    def test_gate_rejects_mutation(self):
        # Flip the ja opcode to jb: the branch target lock still holds, but
        # the opcode lock must fail.
        with self.assertRaises(ValueError):
            rg.analyze(self.mutated(0x1520cf5, b'\x72'))
        # Change the slow-arm branch displacement: target lock must fail.
        with self.assertRaises(ValueError):
            rg.analyze(self.mutated(0x1520cf6, b'\x21'))

    def test_calls_reject_mutation(self):
        # Memcpy slot displacement off by one.
        with self.assertRaises(ValueError):
            rg.analyze(self.mutated(0x1520d03, b'\xda\xd2\x24\x04'))
        # Grow call displacement off by one.
        with self.assertRaises(ValueError):
            rg.analyze(self.mutated(0x1520d31, b'\x2a\x41\x04\x00'))
        # Retry jump displacement off by one.
        with self.assertRaises(ValueError):
            rg.analyze(self.mutated(0x1520d40, b'\xb5'))

    def test_padding_and_fde_reject_mutation(self):
        with self.assertRaises(ValueError):
            rg.analyze(self.mutated(0x1520d41, b'\x00'))
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        fde_range_va = eh['address'] + 0x153f4 + 12
        with self.assertRaises(ValueError):
            rg.analyze(self.mutated(fde_range_va, b'\x62\x00\x00\x00'))


if __name__ == '__main__':
    unittest.main()
