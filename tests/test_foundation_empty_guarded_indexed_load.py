"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_empty_guarded_indexed_load as mod
from elf_index import sections


class EmptyGuardedIndexedLoadEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not mod.TARGET.is_file() or mod.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.data = mod.TARGET.read_bytes()
        cls.sections = sections(cls.data)
        cls.packet = (Path(__file__).resolve().parents[1]
                      / 'research/work-items/foundation-empty-guarded-indexed-load-94')

    def offset(self, va):
        s = next(s for s in self.sections if s['type'] != 8
                 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return bytes(data)

    def test_window_bytes_match_locked_body(self):
        body = self.data[self.offset(0x4fec800):self.offset(0x4fec800) + 35]
        self.assertEqual(body, mod.BODY)

    def test_padding_is_int3_only(self):
        pad = self.data[self.offset(0x4fec823):self.offset(0x4fec823) + 13]
        self.assertEqual(pad, b'\xcc' * 13)
        window = (self.packet / 'window.objdump.txt').read_text()
        self.assertIn('4fec823:', window)
        self.assertIn('int3', window)

    def test_fde_records_and_ranges(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        for offset, raw, start, end in [(0x28f04c, mod.FDE, 0x4fec800, 0x4fec823),
                                        (0x28f060, mod.NEXT_FDE, 0x4fec830, 0x4fec844)]:
            record = self.data[eh['offset'] + offset:eh['offset'] + offset + len(raw)]
            self.assertEqual(record, raw)
            pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
            extent = struct.unpack_from('<I', record, 12)[0]
            self.assertEqual((pc, pc + extent), (start, end))
        frames = (self.packet / 'frames.txt').read_text()
        self.assertIn('pc=0000000004fec800..0000000004fec823', frames)
        self.assertIn('pc=0000000004fec830..0000000004fec844', frames)

    def test_field_offsets_and_stride(self):
        body = self.data[self.offset(0x4fec800):self.offset(0x4fec800) + 35]
        self.assertEqual(struct.unpack_from('<I', body, 7)[0], 0x988)
        self.assertEqual(struct.unpack_from('<I', body, 14)[0], 0x990)
        # shl $0x4,%rsi -> element stride 16
        self.assertEqual(body[20:23], bytes.fromhex('48c1e6'))
        self.assertEqual(body[23], 4)

    def test_empty_guard_branch_target(self):
        body = self.data[self.offset(0x4fec800):self.offset(0x4fec800) + 35]
        self.assertEqual(body[18], 0x74)
        self.assertEqual(0x4fec812 + 2 + struct.unpack_from('<b', body, 19)[0],
                         0x4fec820)

    def test_single_direct_caller_no_tail_jump(self):
        text = next(s for s in self.sections if s['name'] == '.text')
        code = self.data[text['offset']:text['offset'] + text['size']]
        direct, tail = [], []
        pos = 0
        while (pos := code.find(b'\xe8', pos)) >= 0:
            rel = struct.unpack_from('<i', code, pos + 1)[0]
            if text['address'] + pos + 5 + rel == 0x4fec800:
                direct.append(text['address'] + pos)
            pos += 1
        pos = 0
        while (pos := code.find(b'\xe9', pos)) >= 0:
            rel = struct.unpack_from('<i', code, pos + 1)[0]
            if text['address'] + pos + 5 + rel == 0x4fec800:
                tail.append(text['address'] + pos)
            pos += 1
        self.assertEqual(direct, [0x4fb2546])
        self.assertEqual(tail, [])
        # The single caller forwards its 2nd/3rd args and null-checks the
        # result (test %rax,%rax ; je), which is the empty-guard return path.
        caller = self.data[self.offset(0x4fb2546):self.offset(0x4fb2546) + 11]
        self.assertEqual(caller[0], 0xe8)
        self.assertEqual(0x4fb2546 + 5 + struct.unpack_from('<i', caller, 1)[0],
                         0x4fec800)
        self.assertEqual(caller[5:8], bytes.fromhex('4885c0'))  # test %rax,%rax
        self.assertEqual(caller[8], 0x74)  # je (null check)

    def test_no_relocation_names_window(self):
        relsec = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[relsec['offset']:relsec['offset'] + relsec['size']]
        window_slots = []
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and addend == 0x4fec800:
                window_slots.append(address)
        self.assertEqual(window_slots, [])

    def test_decoded_rule_edges(self):
        self.assertEqual(mod.indexed_load(True), 0)
        self.assertEqual(mod.indexed_load(True, 0x1234), 0)
        self.assertEqual(mod.indexed_load(False, 0x1234), 0x1234)
        # A non-empty element whose first qword is 0 also returns 0: the empty
        # guard is not the only source of a 0 result.
        self.assertEqual(mod.indexed_load(False, 0), 0)
        self.assertEqual(mod.indexed_load(False, mod.MASK64), mod.MASK64)
        self.assertEqual(mod.element_offset(0), 0)
        self.assertEqual(mod.element_offset(1), 0x10)
        self.assertEqual(mod.element_offset(7), 0x70)

    def test_corruption_body_byte_fails(self):
        with self.assertRaises(ValueError):
            mod.analyze(self.mutated(0x4fec800, b'\x90'))

    def test_corruption_begin_offset_fails(self):
        # Flip the begin field displacement 0x988 -> 0x998.
        with self.assertRaises(ValueError):
            mod.analyze(self.mutated(0x4fec807, struct.pack('<I', 0x998)))

    def test_corruption_stride_fails(self):
        # Flip shl $0x4 -> shl $0x5 (stride 32).
        with self.assertRaises(ValueError):
            mod.analyze(self.mutated(0x4fec817, b'\x05'))

    def test_corruption_padding_byte_fails(self):
        with self.assertRaises(ValueError):
            mod.analyze(self.mutated(0x4fec823, b'\x90'))

    def test_corruption_retained_evidence_fails(self):
        evidence = json.loads((self.packet / 'evidence.json').read_text())
        evidence['function']['sha256'] = '0' * 64
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as tmp:
            json.dump(evidence, tmp)
            tmp_path = tmp.name
        import subprocess
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1]
                                 / 'tools' / 'foundation_empty_guarded_indexed_load.py'),
             '--check', tmp_path], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_tool_check_passes(self):
        import subprocess
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1]
                                 / 'tools' / 'foundation_empty_guarded_indexed_load.py'),
             '--check', str(self.packet / 'evidence.json')],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Foundation empty-guarded indexed-load evidence reproduces exactly.',
                      proc.stdout)


if __name__ == '__main__':
    unittest.main()
