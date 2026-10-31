"""Target-bound corruption controls bypassing only the top-level digest gate."""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import ren_format_static as tool


class RenFormatStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = tool.ROOT/'artifacts/node/94/hl-node'
        cls.data = cls.binary.read_bytes()
        cls.fdes = list(tool.RANGES)

    def mutate(self, va, byte):
        data = bytearray(self.data)
        off, _ = tool.read_va(data, va, 1)
        data[off] = byte
        with self.assertRaises(ValueError):
            tool.validate(data, self.fdes)

    def test_actual_two_wrappers(self):
        result = tool.validate(self.data, self.fdes)
        self.assertEqual([r['callback_pairs'] for r in result['ranges']], [1, 2])
        self.assertEqual([r['source_line'] for r in result['ranges']], [206, 259])
        self.assertEqual(sum(r['bytes'] for r in result['ranges']), 551)

    def test_missing_fde(self):
        with self.assertRaises(ValueError):
            tool.validate(self.data, self.fdes[:1])

    def test_duplicate_fde(self):
        with self.assertRaises(ValueError):
            tool.validate(self.data, self.fdes + self.fdes[:1])

    def test_wrong_extent(self):
        with self.assertRaises(ValueError):
            tool.validate(self.data, [(self.fdes[0][0], self.fdes[0][1] + 1), self.fdes[1]])

    def test_source_path(self):
        self.mutate(tool.PATH_VA, 0)

    def test_source_line(self):
        self.mutate(tool.SLOTS[0] + 16, 0)

    def test_location_lea(self):
        self.mutate(0x13cea8e, 0)

    def test_descriptor(self):
        self.mutate(0x1f4d9f, 3)

    def test_single_callback(self):
        self.mutate(0x13cea67, 0)

    def test_second_callback(self):
        self.mutate(0x13ceb88, 0)

    def test_format_call_slot(self):
        self.mutate(0x13cebbA, 0)

    def test_nonreturning_trap(self):
        self.mutate(0x13cebbe, 0x90)

    def test_tag_mask(self):
        self.mutate(0x13ceaaa, 2)

    def test_tag_comparison(self):
        self.mutate(0x13cebce, 2)

    def test_payload_layout(self):
        self.mutate(0x13ceabe, 0)

    def test_unwind_target(self):
        self.mutate(0x13ceab4, 0)

    def test_relocation_addend(self):
        original = tool.relocations(self.data)
        original[tool.SLOTS[0]] = (8, tool.PATH_VA + 1)
        with patch.object(tool, 'relocations', return_value=original):
            with self.assertRaises(ValueError):
                tool.validate(self.data, self.fdes)

    def test_first_caller_target(self):
        self.mutate(0x13ce25c, 0)

    def test_second_caller_target(self):
        self.mutate(0x13ce96b, 0)

    def test_argument_pair_layout(self):
        self.mutate(0x13ceb83, 0x20)

    def test_shared_callback_slot_load(self):
        self.mutate(0x13cea7b, 0)

    def test_unbacked_range(self):
        with self.assertRaises(ValueError):
            tool.read_va(self.data, 0xffffffffffffffff, 24)

    def test_truncated_rela(self):
        # Preserve ELF section metadata but cut the final section file extent.
        sections = tool.sections(self.data)
        rela = next(s for s in sections if s['type'] == 4)
        altered = [dict(s) for s in sections]
        next(s for s in altered if s['type'] == 4)['size'] = rela['size'] + 1
        with patch.object(tool, 'sections', return_value=altered):
            with self.assertRaises(ValueError):
                tool.relocations(self.data)

if __name__ == '__main__':
    unittest.main()
