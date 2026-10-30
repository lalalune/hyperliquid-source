from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import fde_gap_classes as g
from test_fde_extents import OFFSET, TEXT, build


def rows(*items):
    """(va, hex bytes, text) tuples as parsed instruction rows."""
    return [{'va': va, 'raw': bytes.fromhex(raw), 'text': text} for va, raw, text in items]


def island(start, end, starts, gap_start=None):
    return {'start': start, 'end': end, 'gap_start': start if gap_start is None else gap_start, 'starts': starts}


class ParseAndFillTests(unittest.TestCase):
    def test_parses_objdump_lines_and_rejects_holes(self):
        text = (' 1030:\tf3 0f 1e fa          \tendbr64\n'
                ' 1034:\tc3                   \tret\n'
                '0000000000001035 <x>:\n'
                ' 1035:\t66 2e 0f 1f 84 00 00 00 00 00 \tcs nopw 0x0(%rax,%rax,1)\n')
        parsed = g.parse_instructions(text)
        self.assertEqual([(r['va'], len(r['raw']), r['text']) for r in parsed],
                         [(0x1030, 4, 'endbr64'), (0x1034, 1, 'ret'), (0x1035, 10, 'cs nopw 0x0(%rax,%rax,1)')])
        with self.assertRaises(ValueError):
            g.parse_instructions(' 1030:\tc3 \tret\n 1032:\tc3 \tret\n')
        with self.assertRaises(ValueError):
            g.parse_instructions(' 1030:\t0f 1f 84 00 \n')

    def test_fill_mnemonics(self):
        for text in ['int3', 'nop', 'xchg %ax,%ax', 'nopl 0x0(%rax)', 'data16 cs nopw 0x0(%rax,%rax,1)']:
            self.assertTrue(g.is_fill(text), text)
        for text in ['add %al,(%rax)', 'endbr64', 'xchg %eax,%ebx', 'ret', 'data16']:
            self.assertFalse(g.is_fill(text), text)

    def test_byte_matcher_accepts_only_canonical_nops(self):
        observed = bytes.fromhex('cccc 90 6666 2e0f1f840000000000 660f1f440000 0f1f00')
        self.assertEqual(g.leading_fill(observed), len(observed))
        self.assertEqual(g.leading_fill(bytes.fromhex('cc 90 f30f1efa')), 2)
        self.assertEqual(g.fill_length(bytes.fromhex('0f1f8400010000 00'), 0), 0)  # non-zero displacement
        self.assertEqual(g.fill_length(bytes.fromhex('0000'), 0), 0)


class ClassifyTests(unittest.TestCase):
    def test_islands_split_at_int3_and_trim_fill(self):
        raw = bytes.fromhex('cc 90 f30f1efa c3 90 cc 0000 cc')
        decoded = rows((0x10, 'cc', 'int3'), (0x11, '90', 'nop'), (0x12, 'f30f1efa', 'endbr64'), (0x16, 'c3', 'ret'),
                       (0x17, '90', 'nop'), (0x18, 'cc', 'int3'), (0x19, '0000', 'add %al,(%rax)'),
                       (0x1b, 'cc', 'int3'))
        result, islands = g.classify(raw, 0x10, decoded)
        self.assertEqual((result['class'], result['islands'], result['leading_fill_bytes']), ('non_fill', 2, 2))
        self.assertTrue(result['byte_matcher_agrees'] and result['decode_ends_at_gap_end'])
        self.assertEqual([(i['start'], i['end'], i['zero_bytes_only']) for i in islands],
                         [(0x12, 0x17, False), (0x19, 0x1b, True)])
        self.assertEqual(islands[0]['endbr64'], [0x12])

    def test_fill_and_zero_byte_classes(self):
        self.assertEqual(g.classify(bytes.fromhex('cc90'), 0, rows((0, 'cc', 'int3'), (1, '90', 'nop')))[0]['class'], 'fill')
        zero, _ = g.classify(bytes.fromhex('90900000'), 0, rows((0, '90', 'nop'), (1, '90', 'nop'), (2, '0000', 'add %al,(%rax)')))
        self.assertEqual(zero['class'], 'zero_bytes')

    def test_disagreement_and_overrun_are_reported(self):
        # The decoder calls the first byte code, but it is a canonical NOP to the byte matcher.
        result, _ = g.classify(bytes.fromhex('90c3'), 0, rows((0, '90c3', 'mystery')))
        self.assertFalse(result['byte_matcher_agrees'])
        overrun, _ = g.classify(bytes.fromhex('e8'), 0, rows((0, 'e800000000', 'call 5')))
        self.assertFalse(overrun['decode_ends_at_gap_end'])


class ReferenceTests(unittest.TestCase):
    ISLANDS = [island(0x2000, 0x2010, {0x2000: 'endbr64', 0x2004: 'ret'}),
               island(0x3000, 0x3010, {0x3000: 'add %al,(%rax)'})]

    def test_stream_finds_branches_and_rip_operands_into_islands(self):
        lines = [' 1000:\tcall   2000 <x+0x10>', ' 1005:\tbnd jmp 2004', ' 100a:\tjne    2010 <y>',
                 ' 100c:\tlea    0x1ff4(%rip),%rdi        # 3000 <z>', ' 1013:\tcall   *0x10(%rip)        # 2008',
                 ' 1019:\tmov    $0x2000,%eax', '0000000000001000 <f>:',
                 ' 101e:\tjmp    0x2004', ' 1020:\tlea    0x0(%rip),%rax        # 0x3008']  # symbol-less forms
        found = g.stream_references(lines, self.ISLANDS)
        self.assertEqual([(r['source'], r['target'], r['kind']) for r in found],
                         [(0x1000, 0x2000, 'call'), (0x1005, 0x2004, 'jump'), (0x100c, 0x3000, 'rip'),
                          (0x1013, 0x2008, 'rip'), (0x101e, 0x2004, 'jump'), (0x1020, 0x3008, 'rip')])

    def test_stream_reads_of_relocation_slots_point_at_the_slot_target(self):
        slots = {0x5000: {'source': 0x5000, 'target': 0x2000, 'kind': 'relative', 'island': 0x2000}}
        lines = [' 1000:\tcall   *0x3ffa(%rip)        # 5000 <x>', ' 1006:\tmov    0x3ff3(%rip),%rax        # 5008']
        found = g.stream_references(lines, self.ISLANDS, slots)
        self.assertEqual([(r['source'], r['target'], r['kind'], r['slot']) for r in found],
                         [(0x1000, 0x2000, 'slot_read', 0x5000)])

    def test_relocations_keep_relative_and_irelative_only(self):
        table = (struct.pack('<QQq', 0x5000, 8, 0x2000) + struct.pack('<QQq', 0x5008, 37, 0x2004)
                 + struct.pack('<QQq', 0x5010, (1 << 32) | 6, 0x2000) + struct.pack('<QQq', 0x5018, 8, 0x4000))
        secs = [{'name': '.rela.dyn', 'type': g.SHT_RELA, 'flags': 2, 'address': 0, 'offset': 0, 'size': len(table)}]
        found = g.relocation_references(table, secs, self.ISLANDS)
        self.assertEqual([(r['source'], r['target'], r['kind']) for r in found],
                         [(0x5000, 0x2000, 'relative'), (0x5008, 0x2004, 'irelative')])
        secs[0]['size'] -= 1
        with self.assertRaises(ValueError):
            g.relocation_references(table, secs, self.ISLANDS)

    def test_container_skips_nobits_tls(self):
        secs = [{'name': '.tbss', 'type': g.SHT_NOBITS, 'flags': 0x403, 'address': 0x5000, 'size': 0x100},
                {'name': '.init_array', 'type': 14, 'flags': 3, 'address': 0x5000, 'size': 0x10}]
        self.assertEqual(g.container(secs, 0x5008)['name'], '.init_array')
        self.assertIsNone(g.container(secs, 0x5010))

    def test_roles(self):
        target = self.ISLANDS[0]

        def ref(kind, container, validated=True, start=True, endbr=True):
            return {'kind': kind, 'container': container, 'validated': validated,
                    'target_is_instruction_start': start, 'target_is_endbr64': endbr}
        cases = [(ref('call', 'fde:0x1000', endbr=False), 'entry'),
                 (ref('jump', 'fde:0x1000'), 'entry'),
                 (ref('relative', 'section:.got'), 'entry'),
                 (ref('rip', 'fde:0x1000', endbr=False), 'pointer_without_landing_pad'),
                 (ref('relative', 'section:.data.rel.ro', endbr=False), 'pointer_without_landing_pad'),
                 (ref('jump', 'island:0x3000'), 'from_other_island'),
                 (ref('call', 'island:0x2000'), 'internal_call'),
                 (ref('jump', 'island:0x2000'), 'internal_jump'),
                 (ref('rip', 'island:0x2000'), 'internal_pointer'),
                 (ref('slot_read', 'fde:0x1000', endbr=False), 'slot_reader'),
                 (ref('slot_read', 'island:0x2000'), 'from_other_island'),
                 (ref('call', 'fde:0x1000', validated=False), 'source_not_confirmed'),
                 (ref('call', 'fde:0x1000', start=False), 'target_not_instruction_start')]
        for item, expected in cases:
            self.assertEqual(g.role(item, target), expected, item)


@unittest.skipUnless(shutil.which('objdump'), 'GNU objdump is required for the decode control')
class SyntheticElfTests(unittest.TestCase):
    """Real objdump over the synthetic FDE ELF: FDEs at 0x1000, 0x1020 and 0x1038; gap 0x1030..0x1038."""

    def analyze(self, text_patches):
        data, _ = build()
        # objdump needs EI_VERSION, ET_DYN, EM_X86_64, EV_CURRENT and e_ehsize.
        data[6] = 1
        struct.pack_into('<HHI', data, 16, 3, 62, 1)
        struct.pack_into('<H', data, 52, 64)
        for va, raw in text_patches:
            data[OFFSET[TEXT] + va - TEXT:OFFSET[TEXT] + va - TEXT + len(raw)] = raw
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'synthetic.elf'
            path.write_bytes(bytes(data))
            return g.analyze(path)

    def test_call_from_fde_enters_island_and_mid_instruction_jump_does_not(self):
        _, _, classes, islands, refs = self.analyze([
            (0x1000, bytes.fromhex('e82b000000 c3')),       # call 0x1030; ret
            (0x1020, bytes.fromhex('eb10 c3')),             # jmp 0x1032 (inside endbr64); ret
            (0x1030, bytes.fromhex('f30f1efa c3 cc 9090')),  # endbr64; ret; int3; nop; nop
        ])
        self.assertEqual([(c['start'], c['class'], c['islands']) for c in classes], [(0x1030, 'non_fill', 1)])
        self.assertEqual([(i['start'], i['end']) for i in islands], [(0x1030, 0x1035)])
        self.assertEqual([(r['source'], r['target'], r['kind'], r['container'], r['role']) for r in refs],
                         [(0x1000, 0x1030, 'call', 'fde:0x1000', 'entry'),
                          (0x1020, 0x1032, 'jump', 'fde:0x1020', 'target_not_instruction_start')])

    def test_desynchronized_sweep_source_is_not_confirmed(self):
        # A stray 0xb8 before the 0x1020 FDE makes the linear sweep see `call 0x1030` at 0x1024, inside
        # the immediate of the `movabs` that a decode from the FDE start finds.
        _, _, classes, _, refs = self.analyze([
            (0x101f, bytes.fromhex('b8')),
            (0x1020, bytes.fromhex('48b8 0000e80700000000 c3')),
            (0x1030, bytes.fromhex('f30f1efa c3 cc 9090')),
        ])
        self.assertEqual([(c['start'], c['decode_ends_at_gap_end']) for c in classes],
                         [(0x1010, False), (0x1030, True)])
        self.assertIn((0x1024, 0x1030, 'call', 'fde:0x1020', 'source_not_confirmed'),
                      [(r['source'], r['target'], r['kind'], r['container'], r['role']) for r in refs])

    def test_unreferenced_island_and_pure_fill_gap(self):
        _, _, classes, islands, refs = self.analyze([(0x1030, bytes.fromhex('31c0 c3 cc cccc cc cc'))])
        self.assertEqual(classes[0]['class'], 'non_fill')
        row = g.island_row(islands[0], refs)
        self.assertEqual((row['class'], row['entrypoints'], row['bytes']), ('unreferenced', [], 3))
        _, _, classes, islands, _ = self.analyze([])
        self.assertEqual(([c['class'] for c in classes], islands), (['fill'], []))


if __name__ == '__main__':
    unittest.main()
