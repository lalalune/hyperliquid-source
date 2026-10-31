from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from fde_extents import parse_cie


def cie_bytes(augmentation):
    # version 1, augmentation, NUL terminator, code_align 1, data_align
    # sleb 0x78, return-address register 16, aug_length 1, 'R' encoding 0x1b.
    return b'\x01' + augmentation + b'\x00' + bytes([1, 0x78, 16]) + b'\x01\x1b'


class CieAugmentationEncodingTests(unittest.TestCase):
    def test_non_ascii_augmentation_fails_closed(self):
        data = cie_bytes(b'z\xff')
        with self.assertRaisesRegex(ValueError, 'Unsupported CIE augmentation'):
            parse_cie(data, 0, 0, len(data), 0x3000, 0x3000)

    def test_valid_augmentation_unchanged(self):
        data = cie_bytes(b'zR')
        cie = parse_cie(data, 0, 0, len(data), 0x3000, 0x3000)
        self.assertEqual(cie['augmentation'], 'zR')
        self.assertEqual(cie['fde_encoding'], 0x1b)


if __name__ == '__main__':
    unittest.main()
