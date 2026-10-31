import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import evm_amount_scale as m


class FakeImg:
    """Stub image: cie_r_encoding reads exactly one 64-byte CIE body."""

    def __init__(self, body):
        self.body = body

    def read(self, va, size):
        return self.body[:size]


def cie_body(aug, aug_data):
    body = bytearray(64)
    body[0:4] = (0).to_bytes(4, 'little')
    body[4] = 1  # version 1
    body[5:5 + len(aug)] = aug
    body[5 + len(aug)] = 0
    i = 5 + len(aug) + 1
    body[i] = 1  # code alignment
    i += 1
    body[i] = 1  # data alignment
    i += 1
    body[i] = 0x10  # return-address register (skipped by the version-1 branch)
    i += 1
    body[i] = len(aug_data)  # augmentation length (single-byte ULEB)
    i += 1
    body[i:i + len(aug_data)] = aug_data
    return bytes(body)


def encoding(body):
    fdes = object.__new__(m.Fdes)
    fdes.img = FakeImg(body)
    return fdes.cie_r_encoding(0)


class CieAugEncodingTests(unittest.TestCase):
    def test_non_utf8_aug_fails_closed(self):
        with self.assertRaises(m.EvidenceError):
            encoding(cie_body(b'z\xff', b'\x1b'))

    def test_valid_zr_returns_encoding(self):
        self.assertEqual(encoding(cie_body(b'zR', b'\x1b')), 0x1b)


if __name__ == '__main__':
    unittest.main()
