"""Target-grounded controls for the static foundation packet (no node execution)."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_unsigned_clamp as clamp_mod
from elf_index import sections


class UnsignedClampEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not clamp_mod.TARGET.is_file() or clamp_mod.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.data = clamp_mod.TARGET.read_bytes()
        cls.sections = sections(cls.data)
        cls.packet = Path(__file__).resolve().parents[1] / 'research/work-items/foundation-unsigned-clamp-94'

    def offset(self, va):
        s = next(s for s in self.sections if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return bytes(data)

    def test_window_bytes_match_locked_body(self):
        body = self.data[self.offset(0x15e4f70):self.offset(0x15e4f70) + 69]
        self.assertEqual(body, clamp_mod.BODY)
        self.assertEqual(hashlib.sha256(body).hexdigest(),
                         '1b7701b64e3f85801c9ee03ff1b4f5882c2cf90f520e99d0929fc010fd9304f3')

    def test_padding_is_int3_only(self):
        pad = self.data[self.offset(0x15e4fb5):self.offset(0x15e4fb5) + 11]
        self.assertEqual(pad, b'\xcc' * 11)
        window = (self.packet / 'window.objdump.txt').read_text()
        self.assertIn('15e4fb5:', window)
        self.assertIn('int3', window)

    def test_fde_records_and_ranges(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        for offset, raw, start, end in [(0x1e1f0, clamp_mod.FDE, 0x15e4f70, 0x15e4fb5),
                                        (0x3102ec, clamp_mod.CALLER_FDE, 0x15e4610, 0x15e4913)]:
            record = self.data[eh['offset'] + offset:eh['offset'] + offset + len(raw)]
            self.assertEqual(record, raw)
            pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
            extent = struct.unpack_from('<I', record, 12)[0]
            self.assertEqual((pc, pc + extent), (start, end))

    def test_caller_setup_and_call_target(self):
        setup = self.data[self.offset(0x15e4827):self.offset(0x15e4827) + 11]
        self.assertEqual(setup, clamp_mod.SETUP)
        call = setup[6:11]
        self.assertEqual(call[0], 0xe8)
        self.assertEqual(0x15e482d + 5 + struct.unpack_from('<i', call, 1)[0], 0x15e4f70)
        caller = (self.packet / 'caller.objdump.txt').read_text()
        self.assertIn('15e482d:', caller)
        self.assertIn('call   15e4f70', caller)

    def test_formula_edges(self):
        c = clamp_mod.clamp
        self.assertEqual(c(0, 99, 5, 7), 5)
        self.assertEqual(c(0, 99, 9, 3), 3)
        self.assertEqual(c(1, 10, 4, 100), 6)
        self.assertEqual(c(1, 3, 9, 100), 0)
        self.assertEqual(c(1, 10, 4, 2), 2)
        self.assertEqual(c(2, 10, 4, 100), 0)
        self.assertEqual(c(0x100000001, 10, 4, 100), 6)
        self.assertEqual(c(0x100000000, 10, 4, 100), 0)

    def test_mutated_window_byte_fails(self):
        with self.assertRaisesRegex(ValueError, 'instruction window changed'):
            clamp_mod.analyze(self.mutated(0x15e4f70, b'\x90'))

    def test_mutated_padding_fails(self):
        with self.assertRaisesRegex(ValueError, 'padding changed'):
            clamp_mod.analyze(self.mutated(0x15e4fb5, b'\x90'))

    def test_mutated_caller_call_fails_before_scan(self):
        with self.assertRaisesRegex(ValueError, 'Caller setup and call bytes changed'):
            clamp_mod.analyze(self.mutated(0x15e482d, b'\x90'))

    def test_mutated_gate_opcode_fails(self):
        # The gate bytes sit inside the locked body, so the body lock fires
        # first — same pattern as packets #12/#13 for in-body call bytes.
        with self.assertRaisesRegex(ValueError, 'instruction window changed'):
            clamp_mod.analyze(self.mutated(0x15e4f87, b'\x90'))

    def test_checker_check_passes(self):
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1] / 'tools/foundation_unsigned_clamp.py'),
             '--check', str(self.packet / 'evidence.json')],
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Foundation unsigned-clamp evidence reproduces exactly.', result.stdout)

    def test_retained_evidence_matches_tool(self):
        retained = json.loads((self.packet / 'evidence.json').read_text())
        self.assertEqual(retained['function']['start_va'], '0x15e4f70')
        self.assertEqual(retained['function']['end_va_exclusive'], '0x15e4fb5')
        self.assertEqual(retained['function']['bytes'], 69)
        self.assertEqual(retained['function']['sha256'],
                         '1b7701b64e3f85801c9ee03ff1b4f5882c2cf90f520e99d0929fc010fd9304f3')
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'], ['0x15e482d'])

    def test_mutated_retained_json_fails(self):
        retained = json.loads((self.packet / 'evidence.json').read_text())
        retained['function']['bytes'] = 70
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as fh:
            json.dump(retained, fh)
            tmp = fh.name
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1] / 'tools/foundation_unsigned_clamp.py'),
             '--check', tmp],
            capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
