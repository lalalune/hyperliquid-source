"""compare() must fail closed on a malformed relocation record row.

The relocation rows compare() reads come from a hash-pinned evidence
record file (load_coverage passes record(...) output through as-is), so
a row that is missing a field the function reads, or is not a mapping at
all, must meet the module's ValueError diagnostic, not escape as a raw
KeyError or TypeError. A missing kind/type and a missing width already
fail closed in the same expression (both are read via .get); only
offset and addend were dereferenced unguarded.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from byte_progress import compare

SOURCE = b'\x01\x02\x03\x04\x05\x06\x07\x08'
MESSAGE = 'Only recorded four-byte PC32/GOTPCREL fields are supported'


class RelocationRowShapeTests(unittest.TestCase):
    def assert_row_rejected(self, row):
        with self.assertRaisesRegex(ValueError, MESSAGE):
            compare(SOURCE, SOURCE, [row])

    def test_valid_kind_row_compares(self):
        result = compare(SOURCE, SOURCE,
                         [{'offset': 0, 'width': 4, 'kind': 2, 'addend': -4}])
        self.assertTrue(result['raw_equal'])
        self.assertEqual(result['relocation_bytes'], 4)

    def test_valid_type_alias_row_with_defaults_compares(self):
        result = compare(SOURCE, SOURCE,
                         [{'offset': 4, 'type': 9, 'addend': -4}])
        self.assertTrue(result['raw_equal'])
        self.assertEqual(result['relocation_bytes'], 4)

    def test_missing_addend_is_rejected(self):
        self.assert_row_rejected({'offset': 0, 'width': 4, 'kind': 2})

    def test_missing_offset_is_rejected(self):
        self.assert_row_rejected({'width': 4, 'kind': 2, 'addend': -4})

    def test_list_row_is_rejected(self):
        self.assert_row_rejected(['offset', 0])

    def test_string_row_is_rejected(self):
        self.assert_row_rejected('offset')

    def test_int_row_is_rejected(self):
        self.assert_row_rejected(7)

    def test_missing_kind_and_type_stays_rejected(self):
        self.assert_row_rejected({'offset': 0, 'width': 4, 'addend': -4})


if __name__ == '__main__':
    unittest.main()
