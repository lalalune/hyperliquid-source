"""Target-grounded controls for the static tagged-count-with-cap packet (no node execution)."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import tagged_count_min_cap as mod
from elf_index import sections


class TaggedCountMinCapEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not mod.TARGET.is_file() or mod.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.data = mod.TARGET.read_bytes()
        cls.sections = sections(cls.data)
        cls.packet = (Path(__file__).resolve().parents[1]
                      / 'research/work-items/tagged-count-min-cap-94')

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
        body = self.data[self.offset(0x22c3f10):self.offset(0x22c3f10) + 69]
        self.assertEqual(body, mod.BODY)

    def test_padding_is_int3_only(self):
        pad = self.data[self.offset(0x22c3f55):self.offset(0x22c3f55) + 11]
        self.assertEqual(pad, b'\xcc' * 11)
        window = (self.packet / 'window.objdump.txt').read_text()
        self.assertIn('22c3f55:', window)
        self.assertIn('int3', window)

    def test_fde_records_and_ranges(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        for offset, raw, start, end in [(0x62e80, mod.FDE, 0x22c3f10, 0x22c3f55),
                                        (0x62e94, mod.NEXT_FDE, 0x22c3f60, 0x22c3f65)]:
            record = self.data[eh['offset'] + offset:eh['offset'] + offset + len(raw)]
            self.assertEqual(record, raw)
            pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
            extent = struct.unpack_from('<I', record, 12)[0]
            self.assertEqual((pc, pc + extent), (start, end))
        frames = (self.packet / 'frames.txt').read_text()
        self.assertIn('pc=00000000022c3f10..00000000022c3f55', frames)
        self.assertIn('pc=00000000022c3f60..00000000022c3f65', frames)

    def test_field_offsets_and_tag_immediate(self):
        body = self.data[self.offset(0x22c3f10):self.offset(0x22c3f10) + 69]
        # tag == 1 immediate (cmp $0x1,%eax)
        self.assertEqual(body[8:10], bytes.fromhex('83f8'))
        self.assertEqual(body[10], 1)
        # field_a = [rdi+0x10] on the tag-one arm
        self.assertEqual(body[16], 0x10)
        # field_b = [rdi+0x18] on tag-one and tag-zero arms
        self.assertEqual(body[22], 0x18)
        self.assertEqual(body[42], 0x18)
        # cap = [rdi+0x28] on all three arms
        self.assertEqual(body[30], 0x28)
        self.assertEqual(body[46], 0x28)
        self.assertEqual(body[60], 0x28)

    def test_branch_targets(self):
        body = self.data[self.offset(0x22c3f10):self.offset(0x22c3f10) + 69]
        self.assertEqual(body[6], 0x74)  # je -> tag-zero arm
        self.assertEqual(0x22c3f10 + 0x6 + 2 + struct.unpack_from('<b', body, 7)[0],
                         0x22c3f37)
        self.assertEqual(body[11], 0x75)  # jne -> default arm
        self.assertEqual(0x22c3f10 + 0xb + 2 + struct.unpack_from('<b', body, 12)[0],
                         0x22c3f47)

    def test_saturating_and_cap_opcodes(self):
        body = self.data[self.offset(0x22c3f10):self.offset(0x22c3f10) + 69]
        # tag-one arm: sub then cmovae implements usub_sat
        self.assertEqual(body[19:22], bytes.fromhex('482b4f'))  # sub 0x18(%rdi),%rcx
        self.assertEqual(body[23:27], bytes.fromhex('480f43c1'))  # cmovae %rcx,%rax
        # every arm caps with cmp %rax,%rcx ; cmovb %rcx,%rax
        self.assertEqual(body[31:34], bytes.fromhex('4839c1'))
        self.assertEqual(body[34:38], bytes.fromhex('480f42c1'))
        self.assertEqual(body[47:50], bytes.fromhex('4839c1'))
        self.assertEqual(body[50:54], bytes.fromhex('480f42c1'))
        self.assertEqual(body[61:64], bytes.fromhex('4839c1'))
        self.assertEqual(body[64:68], bytes.fromhex('480f42c1'))

    def test_pure_leaf_no_calls_or_indirect(self):
        body = self.data[self.offset(0x22c3f10):self.offset(0x22c3f10) + 69]
        self.assertNotIn(b'\xe8', body)
        self.assertNotIn(b'\xe9', body)
        self.assertNotIn(b'\xff', body)

    def test_single_direct_caller_no_tail_jump(self):
        text = next(s for s in self.sections if s['name'] == '.text')
        code = self.data[text['offset']:text['offset'] + text['size']]
        direct, tail = [], []
        pos = 0
        while (pos := code.find(b'\xe8', pos)) >= 0:
            rel = struct.unpack_from('<i', code, pos + 1)[0]
            if text['address'] + pos + 5 + rel == 0x22c3f10:
                direct.append(text['address'] + pos)
            pos += 1
        pos = 0
        while (pos := code.find(b'\xe9', pos)) >= 0:
            rel = struct.unpack_from('<i', code, pos + 1)[0]
            if text['address'] + pos + 5 + rel == 0x22c3f10:
                tail.append(text['address'] + pos)
            pos += 1
        self.assertEqual(direct, [0x227d52d])
        self.assertEqual(tail, [])
        # The caller forwards a pointer into rdi and stores the returned count.
        caller = self.data[self.offset(0x227d52d):self.offset(0x227d52d) + 15]
        self.assertEqual(caller[0], 0xe8)
        self.assertEqual(0x227d52d + 5 + struct.unpack_from('<i', caller, 1)[0],
                         0x22c3f10)
        # mov %rax,0x28(%rsp) stores the result just after the call.
        self.assertEqual(caller[10:15], bytes.fromhex('4889442428'))

    def test_no_relocation_names_window(self):
        relsec = next(s for s in self.sections if s['name'] == '.rela.dyn')
        raw = self.data[relsec['offset']:relsec['offset'] + relsec['size']]
        window_slots = []
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if info == 8 and addend == 0x22c3f10:
                window_slots.append(address)
        self.assertEqual(window_slots, [])

    def test_decoded_rule_edges(self):
        self.assertEqual(mod.tagged_count(0, 0, 5, 10), 5)
        self.assertEqual(mod.tagged_count(0, 0, 20, 10), 10)
        self.assertEqual(mod.tagged_count(1, 30, 10, 100), 20)
        # underflow saturates to 0 rather than wrapping to a huge unsigned
        self.assertEqual(mod.tagged_count(1, 10, 30, 100), 0)
        self.assertEqual(mod.tagged_count(1, 50, 10, 5), 5)
        # tag != 0 and low32 != 1 -> default arm returns 0
        self.assertEqual(mod.tagged_count(2, 99, 99, 99), 0)
        self.assertEqual(mod.tagged_count(0xdeadbeef, 99, 99, 99), 0)
        # low 32 bits select the tag-one arm even with nonzero high bits
        self.assertEqual(mod.tagged_count((1 << 32) | 1, 30, 10, 100), 20)
        # low 32 bits zero but nonzero overall -> default arm, not tag-zero arm
        self.assertEqual(mod.tagged_count(1 << 32, 99, 99, 99), 0)
        # tag-zero arm ignores field_a entirely
        self.assertEqual(mod.tagged_count(0, 12345, 7, 100), 7)

    def test_corruption_body_byte_fails(self):
        with self.assertRaises(ValueError):
            mod.analyze(self.mutated(0x22c3f10, b'\x90'))

    def test_corruption_cap_offset_fails(self):
        # Flip the tag-one cap displacement 0x28 -> 0x30 (at body offset 30).
        with self.assertRaises(ValueError):
            mod.analyze(self.mutated(0x22c3f10 + 30, b'\x30'))

    def test_corruption_tag_immediate_fails(self):
        # Flip cmp $0x1 -> cmp $0x2 (at body offset 10).
        with self.assertRaises(ValueError):
            mod.analyze(self.mutated(0x22c3f10 + 10, b'\x02'))

    def test_corruption_saturate_opcode_fails(self):
        # Flip cmovae (0f 43) -> cmovb (0f 42) at the saturate step.
        with self.assertRaises(ValueError):
            mod.analyze(self.mutated(0x22c3f10 + 25, b'\x42'))

    def test_corruption_padding_byte_fails(self):
        with self.assertRaises(ValueError):
            mod.analyze(self.mutated(0x22c3f55, b'\x90'))

    def test_corruption_retained_evidence_fails(self):
        evidence = json.loads((self.packet / 'evidence.json').read_text())
        evidence['function']['sha256'] = '0' * 64
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as tmp:
            json.dump(evidence, tmp)
            tmp_path = tmp.name
        import subprocess
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1]
                                 / 'tools' / 'tagged_count_min_cap.py'),
             '--check', tmp_path], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_tool_check_passes(self):
        import subprocess
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1]
                                 / 'tools' / 'tagged_count_min_cap.py'),
             '--check', str(self.packet / 'evidence.json')],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Tagged-count-with-cap evidence reproduces exactly.',
                      proc.stdout)


if __name__ == '__main__':
    unittest.main()
