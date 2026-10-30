"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_tzcnt_gate as gate_mod
from elf_index import sections


class TzcntGateEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not gate_mod.TARGET.is_file() or gate_mod.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.data = gate_mod.TARGET.read_bytes()
        cls.sections = sections(cls.data)
        cls.packet = Path(__file__).resolve().parents[1] / 'research/work-items/foundation-tzcnt-gate-94'

    def offset(self, va):
        s = next(s for s in self.sections if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return bytes(data)

    def test_window_bytes_match_locked_body(self):
        body = self.data[self.offset(0x14bf180):self.offset(0x14bf180) + 39]
        self.assertEqual(body, gate_mod.BODY)

    def test_padding_is_int3_only(self):
        pad = self.data[self.offset(0x14bf1a7):self.offset(0x14bf1a7) + 9]
        self.assertEqual(pad, b'\xcc' * 9)
        window = (self.packet / 'window.objdump.txt').read_text()
        self.assertIn('14bf1a7:', window)
        self.assertIn('int3', window)

    def test_fde_records_and_ranges(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        for offset, raw, start, end in [(0xe49c, gate_mod.FDE, 0x14bf180, 0x14bf1a7),
                                        (0xe4b0, gate_mod.NEXT_FDE, 0x14bf1b0, 0x14bf1d1)]:
            record = self.data[eh['offset'] + offset:eh['offset'] + offset + len(raw)]
            self.assertEqual(record, raw)
            pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
            extent = struct.unpack_from('<I', record, 12)[0]
            self.assertEqual((pc, pc + extent), (start, end))
        frames = (self.packet / 'frames.txt').read_text()
        self.assertIn('pc=00000000014bf180..00000000014bf1a7', frames)
        self.assertIn('pc=00000000014bf1b0..00000000014bf1d1', frames)

    def test_instruction_bytes_at_fixed_offsets(self):
        body = self.data[self.offset(0x14bf180):self.offset(0x14bf180) + 39]
        self.assertEqual(body[0:4], bytes.fromhex('4883fe11'))
        self.assertEqual(body[4:7], bytes.fromhex('0f92c0'))
        self.assertEqual(body[7:10], bytes.fromhex('4839fe'))
        self.assertEqual(body[10:13], bytes.fromhex('0f96c1'))
        self.assertEqual(body[13:15], bytes.fromhex('84c8'))
        self.assertEqual(body[15:17], bytes.fromhex('7510'))
        self.assertEqual(body[17:22], bytes.fromhex('f3480fbcf6'))
        self.assertEqual(body[22:25], bytes.fromhex('4885f6'))
        self.assertEqual(body[25:27], bytes.fromhex('7406'))
        self.assertEqual(body[27:33], bytes.fromhex('ff25eff02a04'))
        self.assertEqual(body[33:39], bytes.fromhex('ff2531ee2a04'))

    def test_branch_and_jump_targets(self):
        body = self.data[self.offset(0x14bf180):self.offset(0x14bf180) + 39]
        self.assertEqual(0x14bf18f + 2 + struct.unpack_from('<b', body, 16)[0], 0x14bf1a1)
        self.assertEqual(0x14bf199 + 2 + struct.unpack_from('<b', body, 26)[0], 0x14bf1a1)
        self.assertEqual(0x14bf1a1 + struct.unpack_from('<i', body, 29)[0], 0x576e290)
        self.assertEqual(0x14bf1a7 + struct.unpack_from('<i', body, 35)[0], 0x576dfd8)

    def test_dispatch_slots_and_targets(self):
        relsec = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[relsec['offset']:relsec['offset'] + relsec['size']]
        rels = {}
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            rels[address] = (info, addend)
        self.assertEqual(rels[0x576dfd8], (8, 0x54c06b0))
        self.assertEqual(rels[0x576e290], (8, 0x54c2670))
        for slot in (0x576dfd8, 0x576e290):
            s = next(s for s in self.sections if s['address'] <= slot < s['address'] + s['size'])
            self.assertEqual(s['name'], '.got')
            self.assertEqual(struct.unpack_from('<Q', self.data[self.offset(slot):self.offset(slot) + 8], 0)[0], 0)
        for target in (0x54c06b0, 0x54c2670):
            s = next(s for s in self.sections if s['address'] <= target < s['address'] + s['size'])
            self.assertEqual(s['name'], '.text')
            self.assertEqual(self.data[self.offset(target):self.offset(target) + 4], bytes.fromhex('f30f1efa'))
        window_slots = [a for a, (info, addend) in rels.items() if info == 8 and addend == 0x14bf180]
        self.assertEqual(window_slots, [0x576fd50])
        s = next(s for s in self.sections if s['address'] <= 0x576fd50 < s['address'] + s['size'])
        self.assertEqual(s['name'], '.got')
        self.assertEqual(struct.unpack_from('<Q', self.data[self.offset(0x576fd50):self.offset(0x576fd50) + 8], 0)[0], 0)

    def test_no_direct_callers(self):
        text = next(s for s in self.sections if s['name'] == '.text')
        code = self.data[text['offset']:text['offset'] + text['size']]
        direct = []
        pos = 0
        while (pos := code.find(b'\xe8', pos)) >= 0:
            rel = struct.unpack_from('<i', code, pos + 1)[0]
            if text['address'] + pos + 5 + rel == 0x14bf180:
                direct.append(text['address'] + pos)
            pos += 1
        self.assertEqual(direct, [])

    def test_dispatch_edges(self):
        d = gate_mod.dispatch
        self.assertEqual(d(0, 0), 'A')
        self.assertEqual(d(16, 16), 'A')
        self.assertEqual(d(15, 16), 'B')
        self.assertEqual(d(100, 17), 'A')
        self.assertEqual(d(100, 18), 'B')
        self.assertEqual(d(5, 3), 'A')
        self.assertEqual(d(0xffffffffffffffff, 0x8000000000000000), 'B')
        self.assertEqual(gate_mod.tzcnt(0), 64)
        self.assertEqual(gate_mod.tzcnt(1), 0)
        self.assertEqual(gate_mod.tzcnt(16), 4)

    def test_corruption_body_byte_fails(self):
        with self.assertRaises(ValueError):
            gate_mod.analyze(self.mutated(0x14bf180, b'\x90'))

    def test_corruption_padding_byte_fails(self):
        with self.assertRaises(ValueError):
            gate_mod.analyze(self.mutated(0x14bf1a7, b'\x90'))

    def test_corruption_slot_file_value_fails(self):
        with self.assertRaises(ValueError):
            gate_mod.analyze(self.mutated(0x576dfd8, struct.pack('<Q', 1)))

    def test_corruption_retained_evidence_fails(self):
        evidence = json.loads((self.packet / 'evidence.json').read_text())
        evidence['function']['sha256'] = '0' * 64
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as tmp:
            json.dump(evidence, tmp)
            tmp_path = tmp.name
        # Direct --check path: retained hash must match the computed body hash.
        import subprocess
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1] / 'tools' / 'foundation_tzcnt_gate.py'),
             '--check', tmp_path], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_tool_check_passes(self):
        import subprocess
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1] / 'tools' / 'foundation_tzcnt_gate.py'),
             '--check', str(self.packet / 'evidence.json')], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Foundation tzcnt-gate evidence reproduces exactly.', proc.stdout)


if __name__ == '__main__':
    unittest.main()
