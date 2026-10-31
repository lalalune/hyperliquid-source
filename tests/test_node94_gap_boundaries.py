"""Target-grounded static controls for the two unwindless entry candidates."""
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node94_gap_boundaries as gap


@unittest.skipUnless(shutil.which('objdump'), 'GNU objdump is required for the native static controls')
class Node94GapBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = ROOT / 'artifacts/node/94/hl-node'
        cls.report, cls.rows, cls.raw = gap.inspect_target(cls.binary)
        cls.code = b''.join(bytes.fromhex(row['bytes']) for row in cls.rows)

    def test_authenticated_gap_has_two_closed_candidate_graphs(self):
        report = self.report
        self.assertEqual(report['target_sha256'], gap.DIGEST)
        self.assertEqual(report['window']['sha256'], '6d6fa64d8848a212cedad6ad4092b2477924c53da6dec111f87d3b3c3c81b72a')
        self.assertEqual((report['gap']['start'], report['gap']['end']), (0x5631543, 0x5631f00))
        self.assertEqual((report['gap']['leading_int3_bytes'], report['gap']['trailing_int3_bytes']), (61, 14))
        self.assertEqual((report['fde_records_examined'], report['overlapping_fdes']), (121299, 0))
        self.assertEqual([(c['entry'], c['end'], c['instructions']) for c in report['candidates']],
                         [(0x5631580, 0x56319fd, 285), (0x56319fd, 0x5631ef2, 324)])
        for candidate in report['candidates']:
            self.assertEqual(candidate['instructions'], candidate['statically_reachable_instructions'])
            self.assertEqual(candidate['returns'], [candidate['end'] - 1])
            self.assertEqual(len(candidate['basic_blocks']), 9)
            self.assertEqual(len(candidate['branches']), 6)
        self.assertEqual(report['selected_relocations'], [])
        self.assertEqual(report['decoded_rip_relative_operands'], [])
        self.assertEqual(report['entry_rel32_byte_candidates'], [])

    def test_raw_slice_decode_equals_native_whole_elf_window(self):
        result = subprocess.run(
            ['objdump', '-d', '-w', '-Mintel', '--start-address=' + hex(gap.LOWER),
             '--stop-address=' + hex(gap.UPPER), str(self.binary)],
            capture_output=True, text=True, encoding='utf-8', check=True)
        other = gap.parse_disassembly(result.stdout, self.code, gap.LOWER)
        self.assertEqual([(r['va'], r['bytes'], r['size']) for r in other],
                         [(r['va'], r['bytes'], r['size']) for r in self.rows])
        self.assertEqual(gap.candidate_graphs(other, gap.LOWER, gap.UPPER),
                         self.report['candidates'])

    def test_real_branch_corruption_cannot_target_an_instruction_interior(self):
        changed = bytearray(self.code)
        branch = next(row for row in self.rows if row['va'] == 0x5631648)
        self.assertEqual(bytes.fromhex(branch['bytes'])[:2], b'\x0f\x84')
        offset = branch['va'] - gap.LOWER + 2
        struct.pack_into('<i', changed, offset, struct.unpack_from('<i', changed, offset)[0] + 1)
        rows, _, _ = gap.decode(changed, gap.LOWER)
        with self.assertRaisesRegex(ValueError, 'not a local instruction start'):
            gap.candidate_graphs(rows, gap.LOWER, gap.UPPER)

    def test_marker_bytes_inside_real_movabs_immediate_are_not_an_entry(self):
        changed = bytearray(self.code)
        instruction = next(row for row in self.rows if row['va'] == 0x56315ef)
        self.assertEqual(bytes.fromhex(instruction['bytes'])[:2], b'\x48\xba')
        offset = instruction['va'] - gap.LOWER + 2
        changed[offset:offset + 4] = gap.ENTRY_MARKER
        rows, _, _ = gap.decode(changed, gap.LOWER)
        candidates = gap.candidate_graphs(rows, gap.LOWER, gap.UPPER)
        self.assertEqual([c['entry'] for c in candidates], [0x5631580, 0x56319fd])
        self.assertNotEqual(gap.sha(changed), self.report['window']['sha256'])

    def test_native_output_cannot_be_reused_for_changed_input_bytes(self):
        changed = bytearray(self.code)
        changed[4] ^= 1  # The first actual PUSH instruction after ENDBR64.
        with self.assertRaisesRegex(ValueError, 'bytes differ from input'):
            gap.parse_disassembly(self.raw, changed, gap.LOWER)

    def test_truncated_native_output_is_not_complete_evidence(self):
        lines = self.raw.splitlines()
        final = next(i for i, line in enumerate(lines) if line.lstrip().startswith('5631ef1:'))
        with self.assertRaisesRegex(ValueError, 'complete slice'):
            gap.parse_disassembly('\n'.join(lines[:final]), self.code, gap.LOWER)


if __name__ == '__main__':
    unittest.main()
