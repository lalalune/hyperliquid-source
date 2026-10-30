"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_tagged_pointer as tagged_mod
from elf_index import sections


class TaggedPointerEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not tagged_mod.TARGET.is_file() or tagged_mod.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.data = tagged_mod.TARGET.read_bytes()
        cls.sections = sections(cls.data)
        cls.packet = Path(__file__).resolve().parents[1] / 'research/work-items/foundation-tagged-pointer-94'

    def offset(self, va):
        s = next(s for s in self.sections if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return bytes(data)

    def test_window_bytes_match_locked_body(self):
        body = self.data[self.offset(0x15d65b0):self.offset(0x15d65b0) + 67]
        self.assertEqual(body, tagged_mod.BODY)

    def test_padding_is_int3_only(self):
        pad = self.data[self.offset(0x15d65f3):self.offset(0x15d65f3) + 13]
        self.assertEqual(pad, b'\xcc' * 13)
        window = (self.packet / 'window.objdump.txt').read_text()
        self.assertIn('15d65f3:', window)
        self.assertIn('int3', window)

    def test_fde_records_and_ranges(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        for offset, raw, start, end in [(0x1d860, tagged_mod.FDE, 0x15d65b0, 0x15d65f3),
                                        (0x1d874, tagged_mod.NEXT_FDE, 0x15d6600, 0x15d6603)]:
            record = self.data[eh['offset'] + offset:eh['offset'] + offset + len(raw)]
            self.assertEqual(record, raw)
            pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
            extent = struct.unpack_from('<I', record, 12)[0]
            self.assertEqual((pc, pc + extent), (start, end))
        frames = (self.packet / 'frames.txt').read_text()
        self.assertIn('pc=00000000015d65b0..00000000015d65f3', frames)
        self.assertIn('pc=00000000015d6600..00000000015d6603', frames)

    def test_instruction_bytes_at_fixed_offsets(self):
        body = self.data[self.offset(0x15d65b0):self.offset(0x15d65b0) + 67]
        self.assertEqual(body[0:3], bytes.fromhex('488b0f'))
        self.assertEqual(body[3:13], bytes.fromhex('48ba0200000000000080'))
        self.assertEqual(body[16:18], bytes.fromhex('731a'))
        self.assertEqual(0x15d65c2 + struct.unpack_from('<b', body, 17)[0], 0x15d65dc)
        self.assertEqual(body[27:29], bytes.fromhex('7012'))
        self.assertEqual(0x15d65cd + struct.unpack_from('<b', body, 28)[0], 0x15d65df)
        self.assertEqual(body[29:39], bytes.fromhex('48ba0100000000000080'))
        self.assertEqual(body[42:44], bytes.fromhex('750f'))
        self.assertEqual(0x15d65dc + struct.unpack_from('<b', body, 43)[0], 0x15d65eb)
        self.assertEqual(0x15d65ea + struct.unpack_from('<i', body, 54)[0], 0x5676ba8)
        self.assertEqual(0x15d65f2 + struct.unpack_from('<i', body, 62)[0], 0x5676c20)
        window = (self.packet / 'window.objdump.txt').read_text()
        self.assertIn('15d65b0:', window)
        self.assertIn('mov    (%rdi),%rcx', window)
        self.assertIn('lea    0x40a05be(%rip),%rdx', window)
        self.assertIn('lea    0x40a062e(%rip),%rdx', window)

    def test_no_calls_inside_window(self):
        body = self.data[self.offset(0x15d65b0):self.offset(0x15d65b0) + 67]
        self.assertNotIn(b'\xe8', body)

    def test_relocation_slot_names_window(self):
        relsec = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[relsec['offset']:relsec['offset'] + relsec['size']]
        slots = []
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and addend == 0x15d65b0:
                slots.append(address)
        self.assertEqual(slots, tagged_mod.SLOTS)
        for slot in slots:
            stored = struct.unpack_from('<Q', self.data, self.offset(slot))[0]
            self.assertEqual(stored, 0)

    def test_pointer_targets_are_data_rel_ro_zero(self):
        for ptr in (0x5676ba8, 0x5676c20):
            sec = next(s for s in self.sections if s['address'] <= ptr < s['address'] + s['size'])
            self.assertEqual(sec['name'], '.data.rel.ro')
            stored = struct.unpack_from('<Q', self.data, self.offset(ptr))[0]
            self.assertEqual(stored, 0)

    def test_no_direct_callers(self):
        text = next(s for s in self.sections if s['name'] == '.text')
        code = self.data[text['offset']:text['offset'] + text['size']]
        direct = []
        pos = 0
        while (pos := code.find(b'\xe8', pos)) >= 0:
            rel = struct.unpack_from('<i', code, pos + 1)[0]
            if text['address'] + pos + 5 + rel == 0x15d65b0:
                direct.append(text['address'] + pos)
            pos += 1
        self.assertEqual(direct, [])

    def test_decision_tree_edges(self):
        f = tagged_mod.decide
        self.assertEqual(f(0), ('base', 0x5676c20))
        self.assertEqual(f(2), ('base', 0x5676c20))
        self.assertEqual(f(0x7fffffffffffffff), ('base', 0x5676c20))
        self.assertEqual(f(0x8000000000000000), ('base+8', 0x5676ba8))
        self.assertEqual(f(0x8000000000000001), ('zero', 0x8000000000000001))
        self.assertEqual(f(0x8000000000000002), ('zero', 0x8000000000000002))
        self.assertEqual(f(0xffffffffffffffff), ('zero', 0x8000000000000002))
        # The two tag paths differ in rdx; they are not one (0, 0) pair.
        self.assertNotEqual(f(0x8000000000000001)[1], f(0x8000000000000002)[1])
        with self.assertRaises(ValueError):
            f(1 << 64)

    def test_mutated_window_byte_fails(self):
        with self.assertRaisesRegex(ValueError, 'instruction window changed'):
            tagged_mod.analyze(self.mutated(0x15d65b0, b'\x90'))

    def test_mutated_padding_fails(self):
        with self.assertRaisesRegex(ValueError, 'padding changed'):
            tagged_mod.analyze(self.mutated(0x15d65f3, b'\x90'))

    def test_mutated_branch_displacement_fails(self):
        # Branch displacements sit inside the locked body, so the body lock
        # fires first — same pattern as packets #12/#13 for in-body bytes.
        with self.assertRaisesRegex(ValueError, 'instruction window changed'):
            tagged_mod.analyze(self.mutated(0x15d65c1, b'\x00'))

    def test_checker_check_passes(self):
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1] / 'tools/foundation_tagged_pointer.py'),
             '--check', str(self.packet / 'evidence.json')],
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Foundation tagged-pointer evidence reproduces exactly.', result.stdout)

    def test_retained_evidence_matches_tool(self):
        retained = json.loads((self.packet / 'evidence.json').read_text())
        self.assertEqual(retained['function']['start_va'], '0x15d65b0')
        self.assertEqual(retained['function']['end_va_exclusive'], '0x15d65f3')
        self.assertEqual(retained['function']['bytes'], 67)
        self.assertEqual(retained['function']['sha256'],
                         'f8548c0db5a25d2029154e8376b5552643221c8cc6cbab4e7b719fd502ea745e')
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'], [])
        self.assertEqual(retained['incoming_pattern_scan']['relocation_slots'],
                         ['0x5678ee8'])

    def test_mutated_retained_json_fails(self):
        retained = json.loads((self.packet / 'evidence.json').read_text())
        retained['function']['bytes'] = 68
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as fh:
            json.dump(retained, fh)
            tmp = fh.name
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1] / 'tools/foundation_tagged_pointer.py'),
             '--check', tmp],
            capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
