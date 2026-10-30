"""Target-grounded controls for the static foundation packet (no node execution)."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_twin_take as twin
from elf_index import sections


class TwinTakeEvidenceTests(unittest.TestCase):
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
        record = twin.ROOT / 'research/work-items/foundation-twin-take-94/evidence.json'
        self.assertEqual(self.result, json.loads(record.read_text()))

    def test_twin_windows_share_skeleton_differ_only_in_copy(self):
        windows = self.result['windows']
        self.assertEqual([w['label'] for w in windows], ['take-memcpy', 'take-inline'])
        memcpy, inline = windows
        self.assertEqual(memcpy['copy'], {'method': 'memcpy-slot', 'bytes': 0x268})
        self.assertEqual(inline['copy'],
                         {'method': 'inline-movups-plus-tail', 'bytes': 0x38,
                          'movups_bytes': 0x30, 'tail_bytes': 8})
        self.assertEqual(memcpy['stack_bytes'], 0x268)
        self.assertEqual(inline['stack_bytes'], 0x40)
        # The inline copy is strictly smaller than the memcpy copy: the
        # threshold claim rests on this comparison, not on either size alone.
        self.assertLess(inline['copy']['bytes'], memcpy['copy']['bytes'])
        # Inline copy arithmetic: three 16-byte movups (0x30 bytes) plus one
        # 8-byte tail move cover exactly 0x38 bytes, matching the buffer span
        # rsp+8 to rsp+0x40 used by the window.
        self.assertEqual(3 * 16 + 8, inline['copy']['bytes'])

    def test_fde_extent_is_not_the_index_stride(self):
        memcpy, inline = self.result['windows']
        self.assertEqual(memcpy['fde_bytes'], 89)
        self.assertEqual(memcpy['index_stride_bytes'], 96)
        self.assertEqual(memcpy['padding_bytes'], 7)
        self.assertEqual(memcpy['fde_end'], '0x1451a19')
        self.assertEqual(memcpy['index_stride_end'], '0x1451a20')
        # The inline window has no padding: its FDE end is its stride end.
        self.assertEqual(inline['fde_bytes'], 96)
        self.assertEqual(inline['index_stride_bytes'], 96)
        self.assertEqual(inline['padding_bytes'], 0)
        self.assertEqual(inline['fde_end'], '0x1451c50')
        self.assertEqual(inline['index_stride_end'], '0x1451c50')

    def test_shared_panic_and_drop_slots(self):
        slots = self.result['slots']
        self.assertEqual(slots['panic'], {'slot': '0x576e470', 'target': '0x157a9f0'})
        self.assertEqual(slots['drop'], {'slot': '0x576e868', 'target': '0x4eeb4c0'})
        self.assertEqual(slots['window_slots'],
                         {'take-memcpy': '0x566a7f8', 'take-inline': '0x566a7d0'})

    def test_incoming_scan_finds_no_text_calls(self):
        scan = self.result['incoming_scan']
        self.assertEqual(scan['indirect'], [])
        self.assertEqual(scan['direct'], [])

    def test_identity_rejects_mutation(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        fde_range_va = eh['address'] + 0xadd4 + 12
        cases = {
            'memcpy window byte': (0x14519c3, b'\x81'),
            'memcpy length byte': (0x14519ea + 1, b'\x81'),
            'inline window byte': (0x1451bf1, b'\x81'),
            'inline movups byte': (0x1451c1d, b'\x81'),
            'flag comparison byte': (0x14519dc + 3, b'\x82'),
            'fde range byte': (fde_range_va, b'\x4c'),
            'relocated slot bytes': (0x576e470, b'\x01'),
            'memcpy call displacement': (0x14519f7, b'\x75'),
            'panic call displacement': (0x1451a0f, b'\x75'),
            'fde padding byte': (0x1451a19, b'\x90'),
        }
        for name, (va, raw) in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(ValueError):
                    twin.analyze(self.mutated(va, raw))


if __name__ == '__main__':
    unittest.main()
