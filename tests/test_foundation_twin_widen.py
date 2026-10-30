"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import struct
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_twin_widen as twin
from elf_index import sections


class TwinWidenEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not twin.TARGET.is_file() or twin.TARGET.stat().st_size != 91774280:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        # Authenticate once; structural mutation controls intentionally bypass
        # the identity gate so each downstream evidence check is exercised.
        cls.result = twin.inspect(twin.TARGET)
        cls.data = twin.TARGET.read_bytes()
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
        record = twin.ROOT / 'research/work-items/foundation-twin-widen-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_windows_are_twins_except_three_offsets(self):
        windows = self.result['windows']
        self.assertEqual([w['fde_bytes'] for w in windows], [94, 94])
        self.assertEqual([w['element_size'] for w in windows], [4, 8])
        diff = self.result['twin_difference']
        self.assertEqual(diff['differing_byte_offsets'], ['0x28', '0x30', '0x5a'])
        self.assertEqual(diff['shared_call_target'], '0x151f160')
        self.assertEqual(diff['indirect_call_slot'], '0x576dfb8')
        w1 = self.data[self.offset(0x151f0a0):self.offset(0x151f0a0) + 94]
        w2 = self.data[self.offset(0x151f100):self.offset(0x151f100) + 94]
        diffs = [i for i in range(94) if w1[i] != w2[i]]
        self.assertEqual(diffs, [0x28, 0x30, 0x5a])
        self.assertEqual((w1[0x28], w2[0x28]), (4, 8))
        # Both call displacements resolve to the same targets.
        self.assertEqual(0x151f0a0 + 0x2f + 5 + struct.unpack_from('<i', w1, 0x30)[0], 0x151f160)
        self.assertEqual(0x151f100 + 0x2f + 5 + struct.unpack_from('<i', w2, 0x30)[0], 0x151f160)
        self.assertEqual(0x151f0a0 + 0x58 + 6 + struct.unpack_from('<i', w1, 0x5a)[0], 0x576dfb8)
        self.assertEqual(0x151f100 + 0x58 + 6 + struct.unpack_from('<i', w2, 0x5a)[0], 0x576dfb8)

    def test_clamp_boundaries_from_decoded_branch(self):
        behavior = self.result['behavior']
        self.assertEqual(behavior['clamp'], 'count = doubled length if doubled length >= 5 else 4')
        self.assertEqual(behavior['clamp_boundaries'], {'0': 4, '1': 4, '2': 4, '3': 6, '4': 8})
        for length, expected in ((0, 4), (1, 4), (2, 4), (3, 6), (4, 8)):
            doubled = 2 * length
            self.assertEqual(doubled if doubled >= 5 else 4, expected)

    def test_shared_routine_and_error_slot_are_locked_but_not_decoded(self):
        shared = self.result['shared_routine']
        self.assertEqual(shared['start_va'], '0x151f160')
        self.assertEqual(shared['fde_end_va_exclusive'], '0x151f238')
        self.assertFalse(shared['body_decoded'])
        slot = self.result['error_arm_slot']
        self.assertEqual(slot['slot'], '0x576dfb8')
        self.assertEqual(slot['relocation'], 'R_X86_64_RELATIVE')
        self.assertEqual(slot['addend'], '0x1346068')
        self.assertFalse(slot['runtime_target_named'])
        self.assertIsNone(self.result['inferred_label'])

    def test_identity_rejects_mutation(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        fde_range_va = eh['address'] + 0x14f5c + 12
        cases = {
            'element-size byte': (0x151f0a0 + 0x28, b'\x02'),
            'shared call displacement': (0x151f0a0 + 0x30, b'\x75'),
            'indirect call displacement': (0x151f0a0 + 0x5a, b'\x75'),
            'clamp compare byte': (0x151f0a0 + 0x14, b'\x06'),
            'fde range byte': (fde_range_va, b'\x4c'),
            'relocated slot bytes': (0x576dfb8, b'\x01'),
            'window padding byte': (0x151f0fe, b'\x90'),
        }
        for name, (va, raw) in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(ValueError):
                    twin.analyze(self.mutated(va, raw))

    def test_no_gate_claimed(self):
        self.assertFalse(self.result['progress_gate_requested'])
        self.assertFalse(self.result['captured_binary_executed'])


if __name__ == '__main__':
    unittest.main()
