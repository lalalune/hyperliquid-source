"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_flag_or as flag_or_mod
from elf_index import sections


class FlagOrEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not flag_or_mod.TARGET.is_file() or flag_or_mod.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.data = flag_or_mod.TARGET.read_bytes()
        cls.sections = sections(cls.data)
        cls.packet = Path(__file__).resolve().parents[1] / 'research/work-items/foundation-flag-or-94'

    def offset(self, va):
        s = next(s for s in self.sections if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return bytes(data)

    def test_window_bytes_match_locked_body(self):
        body = self.data[self.offset(0x15625e0):self.offset(0x15625e0) + 21]
        self.assertEqual(body, flag_or_mod.BODY)

    def test_padding_is_int3_only(self):
        pad = self.data[self.offset(0x15625f5):self.offset(0x15625f5) + 11]
        self.assertEqual(pad, b'\xcc' * 11)
        window = (self.packet / 'window.objdump.txt').read_text()
        self.assertIn('15625f5:', window)
        self.assertIn('int3', window)

    def test_fde_records_and_ranges(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        for offset, raw, start, end in [(0x17e18, flag_or_mod.FDE, 0x15625e0, 0x15625f5),
                                        (0x17e2c, flag_or_mod.NEXT_FDE, 0x1562600, 0x156268b)]:
            record = self.data[eh['offset'] + offset:eh['offset'] + offset + len(raw)]
            self.assertEqual(record, raw)
            pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
            extent = struct.unpack_from('<I', record, 12)[0]
            self.assertEqual((pc, pc + extent), (start, end))
        frames = (self.packet / 'frames.txt').read_text()
        self.assertIn('pc=00000000015625e0..00000000015625f5', frames)
        self.assertIn('pc=0000000001562600..000000000156268b', frames)

    def test_instruction_bytes_at_fixed_offsets(self):
        body = self.data[self.offset(0x15625e0):self.offset(0x15625e0) + 21]
        self.assertEqual(body[0:4], bytes.fromhex('400fb6c6'))
        self.assertEqual(body[4:11], bytes.fromhex('488d0d01f1cefe'))
        self.assertEqual(0x15625eb + struct.unpack_from('<i', body, 7)[0], 0x2516ec)
        self.assertEqual(body[11:14], bytes.fromhex('8b0481'))
        self.assertEqual(body[14:20], bytes.fromhex('0987a0010000'))
        self.assertEqual(body[20], 0xc3)
        window = (self.packet / 'window.objdump.txt').read_text()
        self.assertIn('15625e0:', window)
        self.assertIn('movzbl %sil,%eax', window)
        self.assertIn('or     %eax,0x1a0(%rdi)', window)

    def test_table_is_permutation_of_bits_0_to_19(self):
        table = self.data[self.offset(0x2516ec):self.offset(0x2516ec) + 80]
        self.assertEqual(table, flag_or_mod.TABLE)
        entries = struct.unpack_from('<20I', table, 0)
        self.assertEqual(sorted(entries), [1 << b for b in range(20)])
        self.assertEqual(entries[8], 0x200)
        self.assertEqual(entries[9], 0x800)
        self.assertEqual(entries[16], 0x40000)
        self.assertEqual(entries[17], 0x80000)
        self.assertEqual(entries[18], 0x100)
        self.assertEqual(entries[19], 0x400)

    def test_table_tail_not_single_bit(self):
        tail = self.data[self.offset(0x2516ec) + 80:self.offset(0x2516ec) + 80 + 80]
        entries = struct.unpack_from('<20I', tail, 0)
        self.assertEqual(entries[0], 0x01314a6c)
        for value in entries:
            self.assertGreater(bin(value).count('1'), 1)

    def test_relocation_slots_name_window(self):
        relsec = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[relsec['offset']:relsec['offset'] + relsec['size']]
        slots = []
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and addend == 0x15625e0:
                slots.append(address)
        self.assertEqual(slots, flag_or_mod.SLOTS)
        for slot in slots:
            stored = struct.unpack_from('<Q', self.data, self.offset(slot))[0]
            self.assertEqual(stored, 0)

    def test_no_direct_callers(self):
        text = next(s for s in self.sections if s['name'] == '.text')
        code = self.data[text['offset']:text['offset'] + text['size']]
        direct = []
        pos = 0
        while (pos := code.find(b'\xe8', pos)) >= 0:
            rel = struct.unpack_from('<i', code, pos + 1)[0]
            if text['address'] + pos + 5 + rel == 0x15625e0:
                direct.append(text['address'] + pos)
            pos += 1
        self.assertEqual(direct, [])

    def test_formula_edges(self):
        f = flag_or_mod.flag_or
        self.assertEqual(f(0, 0), 1)
        self.assertEqual(f(7, 0xff), 0xff)
        self.assertEqual(f(8, 0), 0x200)
        self.assertEqual(f(18, 0), 0x100)
        self.assertEqual(f(19, 0), 0x400)
        self.assertEqual(f(0, 0x200), 0x201)
        with self.assertRaises(ValueError):
            f(20, 0)

    def test_mutated_window_byte_fails(self):
        with self.assertRaisesRegex(ValueError, 'instruction window changed'):
            flag_or_mod.analyze(self.mutated(0x15625e0, b'\x90'))

    def test_mutated_padding_fails(self):
        with self.assertRaisesRegex(ValueError, 'padding changed'):
            flag_or_mod.analyze(self.mutated(0x15625f5, b'\x90'))

    def test_mutated_table_entry_fails(self):
        with self.assertRaisesRegex(ValueError, 'Flag table changed'):
            flag_or_mod.analyze(self.mutated(0x2516ec, b'\x02'))

    def test_mutated_table_address_fails(self):
        # The table-address bytes sit inside the locked body, so the body
        # lock fires first — same pattern as packets #12/#13 for in-body bytes.
        with self.assertRaisesRegex(ValueError, 'instruction window changed'):
            flag_or_mod.analyze(self.mutated(0x15625e7, b'\x90'))

    def test_checker_check_passes(self):
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1] / 'tools/foundation_flag_or.py'),
             '--check', str(self.packet / 'evidence.json')],
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Foundation flag-OR evidence reproduces exactly.', result.stdout)

    def test_retained_evidence_matches_tool(self):
        retained = json.loads((self.packet / 'evidence.json').read_text())
        self.assertEqual(retained['function']['start_va'], '0x15625e0')
        self.assertEqual(retained['function']['end_va_exclusive'], '0x15625f5')
        self.assertEqual(retained['function']['bytes'], 21)
        self.assertEqual(retained['function']['sha256'],
                         'c48b9983005a58f1c858edc6a302c0222147d2d005a697d636fb111b70eefa37')
        self.assertEqual(retained['function']['table_sha256'],
                         'fb3961af04b609f76f0c04787ab793b2f55e817831617aa2e2e1ca3338af822c')
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'], [])
        self.assertEqual(retained['incoming_pattern_scan']['relocation_slots'],
                         ['0x5672668', '0x5673070', '0x5673830', '0x5673958'])

    def test_mutated_retained_json_fails(self):
        retained = json.loads((self.packet / 'evidence.json').read_text())
        retained['function']['bytes'] = 22
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as fh:
            json.dump(retained, fh)
            tmp = fh.name
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1] / 'tools/foundation_flag_or.py'),
             '--check', tmp],
            capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
