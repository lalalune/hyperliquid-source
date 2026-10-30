"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_twin_once_flag as tf
from elf_index import sections


class TwinOnceFlagEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not tf.TARGET.is_file() or tf.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        # Authenticate once; structural mutation controls intentionally bypass
        # the identity gate so each downstream evidence check is exercised.
        cls.result = tf.inspect(tf.TARGET)
        cls.data = tf.TARGET.read_bytes()
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
        record = tf.ROOT / 'research/work-items/foundation-twin-once-flag-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_windows_and_entry_branches_from_retained_bytes(self):
        windows = self.result['windows']
        self.assertEqual(windows[0]['start_va'], '0x15080c0')
        self.assertEqual(windows[0]['fde_end_va_exclusive'], '0x150811b')
        self.assertEqual(windows[0]['fde_bytes'], 91)
        self.assertEqual(windows[0]['fde_section_offset'], '0x13600')
        self.assertEqual(windows[0]['padding_int3_bytes'], 5)
        self.assertEqual(windows[1]['start_va'], '0x15081b0')
        self.assertEqual(windows[1]['fde_end_va_exclusive'], '0x1508202')
        self.assertEqual(windows[1]['fde_bytes'], 82)
        self.assertEqual(windows[1]['fde_section_offset'], '0x13624')
        self.assertEqual(windows[1]['padding_int3_bytes'], 14)
        w1 = self.data[self.offset(0x15080c0):self.offset(0x15080c0) + 91]
        w2 = self.data[self.offset(0x15081b0):self.offset(0x15081b0) + 82]
        # Twin 1: cmp $2, %sil; je return at 0x15080e8; test $1, %sil; jne swap.
        self.assertEqual(w1[1:5], b'\x40\x80\xfe\x02')
        self.assertEqual(w1[5], 0x74)
        self.assertEqual(0x15080c0 + 5 + 2 + w1[6], 0x15080e8)
        self.assertEqual(w1[11], 0x75)
        self.assertEqual(0x15080c0 + 11 + 2 + w1[12], 0x15080df)
        # Twin 2: rbx = [rdi]; cmpb $0, 8(rdi); jne swap at 0x15081cc.
        self.assertEqual(w2[1:4], b'\x48\x8b\x1f')
        self.assertEqual(w2[4:8], b'\x80\x7f\x08\x00')
        self.assertEqual(w2[8], 0x75)
        self.assertEqual(0x15081b0 + 8 + 2 + w2[9], 0x15081cc)
        # Flag sources and swap targets differ; the rest of the shape is shared.
        self.assertEqual(self.result['flag_sources']['twin1'], 'incoming sil byte')
        self.assertEqual(self.result['flag_sources']['twin2'],
                         'byte at 8(rdi) after loading the pointer at [rdi] into rbx')
        self.assertEqual(self.result['swap_targets']['twin1'], '(rdi)')
        self.assertEqual(self.result['swap_targets']['twin2'], '(rbx) where rbx holds [rdi]')

    def test_shared_edges_locked_but_windows_unnamed(self):
        edges = self.result['shared_edges']
        self.assertEqual(edges['global_slot']['slot'], '0x576e720')
        self.assertEqual(edges['global_slot']['relocation'], 'R_X86_64_RELATIVE')
        self.assertEqual(edges['global_slot']['target_cell'], '0x5788598')
        self.assertEqual(edges['global_slot']['cell_section'], '.bss')
        self.assertEqual(edges['call_slot']['slot'], '0x576eb98')
        self.assertEqual(edges['call_slot']['callee'], '0x4eef080')
        self.assertEqual(edges['call_slot']['callee_fde_end_va_exclusive'], '0x4eef08e')
        self.assertEqual(edges['call_slot']['callee_behavior'],
                         'cmpq $0, %fs:-0x428; sete %al; ret')
        self.assertEqual(edges['syscall_slot']['slot'], '0x576ea40')
        self.assertEqual(edges['syscall_slot']['dynamic_symbol'], 'syscall')
        self.assertEqual(edges['syscall_slot']['symbol_index'], 19)
        self.assertEqual(edges['syscall_slot']['immediates'], {'edi': 202, 'edx': 129, 'ecx': 1})
        self.assertEqual(edges['syscall_slot']['control'], 'tail jump, not a call')
        self.assertIsNone(self.result['inferred_label'])
        # Both global-load displacements resolve to the shared slot.
        w1 = self.data[self.offset(0x15080c0):self.offset(0x15080c0) + 91]
        w2 = self.data[self.offset(0x15081b0):self.offset(0x15081b0) + 82]
        self.assertEqual(0x15080c0 + 13 + 7 + struct.unpack_from('<i', w1, 16)[0], 0x576e720)
        self.assertEqual(0x15081b0 + 10 + 7 + struct.unpack_from('<i', w2, 13)[0], 0x576e720)
        # Both syscall tail jumps resolve to the shared slot.
        self.assertEqual(0x15080c0 + 63 + 6 + struct.unpack_from('<i', w1, 65)[0], 0x576ea40)
        self.assertEqual(0x15081b0 + 60 + 6 + struct.unpack_from('<i', w2, 62)[0], 0x576ea40)
        # Both call displacements resolve to the shared call slot; the
        # callee itself comes from that slot's RELATIVE relocation, locked
        # by the tool.
        self.assertEqual(0x15080c0 + 72 + 6 + struct.unpack_from('<i', w1, 74)[0], 0x576eb98)
        self.assertEqual(0x15081b0 + 66 + 6 + struct.unpack_from('<i', w2, 68)[0], 0x576eb98)

    def test_identity_rejects_mutation(self):
        with self.assertRaises(ValueError):
            tf.analyze(self.mutated(0x15080c0, b'\x90'))
        with self.assertRaises(ValueError):
            tf.analyze(self.mutated(0x15081b0, b'\x90'))

    def test_branches_reject_mutation(self):
        # Flip twin 1's flag-2 return branch je to jne: opcode lock must fail.
        with self.assertRaises(ValueError):
            tf.analyze(self.mutated(0x15080c5, b'\x75'))
        # Change twin 1's low-bit branch displacement: target lock must fail.
        with self.assertRaises(ValueError):
            tf.analyze(self.mutated(0x15080cc, b'\x13'))
        # Change twin 2's nonzero branch displacement: target lock must fail.
        with self.assertRaises(ValueError):
            tf.analyze(self.mutated(0x15081b9, b'\x13'))
        # Change twin 1's old-2 branch displacement: target lock must fail.
        with self.assertRaises(ValueError):
            tf.analyze(self.mutated(0x15080e7, b'\x03'))

    def test_calls_and_immediates_reject_mutation(self):
        # Syscall edi immediate 0xca off by one.
        with self.assertRaises(ValueError):
            tf.analyze(self.mutated(0x15080ee, b'\xcb'))
        # Syscall tail-jump displacement off by one.
        with self.assertRaises(ValueError):
            tf.analyze(self.mutated(0x1508101, b'\x3c'))
        # Call displacement off by one.
        with self.assertRaises(ValueError):
            tf.analyze(self.mutated(0x150810a, b'\x8b'))
        # Callee sete opcode changed.
        with self.assertRaises(ValueError):
            tf.analyze(self.mutated(0x4eef08a, b'\x0f\x95'))

    def test_padding_and_fde_reject_mutation(self):
        # First padding byte after twin 1 is not int3.
        with self.assertRaises(ValueError):
            tf.analyze(self.mutated(0x150811b, b'\x90'))
        # First padding byte after twin 2 is not int3.
        with self.assertRaises(ValueError):
            tf.analyze(self.mutated(0x1508202, b'\x90'))
        # FDE range byte for twin 1 changed (91 -> 92).
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        fde_range_va = eh['address'] + 0x13600 + 12
        with self.assertRaises(ValueError):
            tf.analyze(self.mutated(fde_range_va, b'\x5c'))


if __name__ == '__main__':
    unittest.main()
