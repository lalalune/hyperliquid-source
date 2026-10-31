"""Actual node94 byte controls for one leaf and one selected relocation edge."""
import mmap
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node94_relocated_leaf_54aa940 as leaf


@unittest.skipUnless(shutil.which('objdump'), 'GNU objdump is required for native static controls')
class RelocatedLeafTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = ROOT / 'artifacts/node/94/hl-node'
        cls.report, cls.rows, cls.prefix, cls.raw, cls.prefix_raw = leaf.inspect(cls.binary)
        cls.code = bytes.fromhex(cls.report['candidate']['hex'])
        cls.caller_code = bytes.fromhex(cls.report['caller_decode_prefix']['hex'])

    def test_target_cfg_and_selected_edge_are_counted_separately(self):
        r = self.report
        self.assertEqual(r['target_sha256'], leaf.DIGEST)
        self.assertEqual((r['candidate']['va'], r['candidate']['bytes']), (0x54aa940, 441))
        self.assertEqual(r['candidate_cfg']['native_instructions'], 95)
        self.assertEqual(r['candidate_cfg']['statically_reachable_instructions'], 95)
        self.assertEqual(len(r['candidate_cfg']['blocks']), 4)
        self.assertEqual(len(r['candidate_cfg']['branches']), 2)
        self.assertEqual(r['candidate_cfg']['returns'], [0x54aaaf8])
        self.assertEqual((r['fde_records_examined'], r['overlapping_fdes']), (121299, 0))
        self.assertEqual(r['selected_incoming_edges'], 1)
        self.assertEqual(r['selected_incoming_edge']['instruction_hex'], 'ff159f6d2704')
        self.assertEqual((r['caller_fde']['start'], r['caller_fde']['end']), (0x14f90f0, 0x14f93de))
        self.assertEqual((r['relocation']['place'], r['relocation']['addend']), (0x5770088, 0x54aa940))
        self.assertEqual(sorted(x['va'] for x in r['constant_references']), [0x800580, 0x800590, 0x8005a0])
        self.assertEqual(r['constant_bytes'], 48)

    def test_native_raw_windows_agree_with_the_actual_elf_windows(self):
        for code, base, rows in ((self.code, leaf.START, self.rows),
                                  (self.caller_code, self.report['caller_fde']['start'], self.prefix)):
            with self.subTest(base=hex(base)):
                result = subprocess.run(['objdump', '-d', '-w', '-Mintel',
                                         '--start-address=' + hex(base),
                                         '--stop-address=' + hex(base + len(code)), str(self.binary)],
                                        capture_output=True, text=True, encoding='utf-8', check=True)
                decoded = leaf.parse_native(result.stdout, code, base)
                self.assertEqual([(r['va'], r['size'], r['hex']) for r in decoded],
                                 [(r['va'], r['size'], r['hex']) for r in rows])

    def test_retargeted_real_call_cannot_reuse_the_selected_slot_binding(self):
        changed = bytearray(self.caller_code)
        pos = leaf.CALL - self.report['caller_fde']['start'] + 2
        struct.pack_into('<i', changed, pos, struct.unpack_from('<i', changed, pos)[0] + 8)
        rows, _ = leaf.native(changed, self.report['caller_fde']['start'])
        with self.assertRaisesRegex(ValueError, 'does not name the selected slot'):
            leaf.incoming_call(rows)

    def test_changed_real_rela_addend_or_kind_does_not_bind_this_callee(self):
        original = bytes.fromhex(self.report['relocation']['hex'])
        for field, value in ((16, 0x54aab00), (8, 6)):
            with self.subTest(field=field):
                changed = bytearray(original)
                struct.pack_into('<Q', changed, field, value)
                with self.assertRaisesRegex(ValueError, 'does not bind slot to entry'):
                    leaf.relative_binding(changed)

    def test_actual_branch_displacement_must_land_on_an_instruction_start(self):
        changed = bytearray(self.code)
        pos = 0x54aaa8d - leaf.START + 1
        changed[pos] += 1
        rows, _ = leaf.native(changed, leaf.START)
        with self.assertRaisesRegex(ValueError, 'instruction start'):
            leaf.leaf_graph(rows)

    def test_retargeted_real_load_cannot_count_writable_slot_as_constant(self):
        changed = bytearray(self.code)
        row = next(r for r in self.rows if r['va'] == 0x54aa94b)
        pos = row['va'] - leaf.START + row['size'] - 4
        struct.pack_into('<i', changed, pos, leaf.SLOT - row['va'] - row['size'])
        rows, _ = leaf.native(changed, leaf.START)
        with self.binary.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            with self.assertRaisesRegex(ValueError, 'not readonly non-code'):
                leaf.constants(rows, data, leaf.sections(data))

    def test_stale_native_bytes_are_not_accepted_for_changed_selected_input(self):
        changed = bytearray(self.code)
        changed[4] ^= 1
        with self.assertRaisesRegex(ValueError, 'do not match selected input'):
            leaf.parse_native(self.raw, changed, leaf.START)


if __name__ == '__main__':
    unittest.main()
