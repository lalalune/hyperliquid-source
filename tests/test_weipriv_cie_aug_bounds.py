import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import weipriv_sign_guard as w


class FakeImg:
    """Stub image: cie_r_encoding reads exactly one 64-byte CIE body."""

    def __init__(self, body):
        self.body = body

    def read(self, va, size):
        return self.body[:size]


def cie_body(aug, aug_data, tail=b''):
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
    body[i] = 0x10  # return-address register
    i += 1
    body[i] = len(aug_data)  # augmentation length (single-byte ULEB)
    i += 1
    body[i:i + len(aug_data)] = aug_data
    j = i + len(aug_data)
    body[j:j + len(tail)] = tail
    return bytes(body)


def encoding(body):
    fdes = object.__new__(w.Fdes)
    fdes.img = FakeImg(body)
    return fdes.cie_r_encoding(0)


class CieAugBoundsTests(unittest.TestCase):
    def test_valid_zr_returns_encoding(self):
        self.assertEqual(encoding(cie_body(b'zR', b'\x1b')), 0x1b)

    def test_valid_zlr_skips_l_then_returns_encoding(self):
        self.assertEqual(encoding(cie_body(b'zLR', b'\x1b\x1b')), 0x1b)

    def test_valid_zpr_skips_personality_then_returns_encoding(self):
        self.assertEqual(
            encoding(cie_body(b'zPR', b'\x9b\x00\x00\x00\x00\x1b')), 0x1b)

    def test_truncated_r_rejected_not_borrowed(self):
        # aug_length is 0, so no R byte exists; the 0x1b tail belongs to
        # whatever follows the CIE and must not be read as its encoding.
        with self.assertRaises(w.EvidenceError):
            encoding(cie_body(b'zR', b'', tail=b'\x1b'))

    def test_truncated_personality_rejected(self):
        with self.assertRaises(w.EvidenceError):
            encoding(cie_body(b'zPR', b'\x9b\x00\x00'))

    def test_unsupported_personality_nibble_rejected_as_evidence(self):
        with self.assertRaises(w.EvidenceError):
            encoding(cie_body(b'zP', b'\x00'))

    def test_unterminated_augmentation_rejected_as_evidence(self):
        body = bytearray(64)
        body[0:4] = (0).to_bytes(4, 'little')
        body[4] = 1
        body[5:64] = b'zR' + b'A' * 57
        with self.assertRaises(w.EvidenceError):
            encoding(bytes(body))

    def test_non_ascii_augmentation_rejected_as_evidence(self):
        body = bytearray(64)
        body[0:4] = (0).to_bytes(4, 'little')
        body[4] = 1
        body[5] = ord('z')
        body[6] = 0xff
        body[7] = 0
        with self.assertRaises(w.EvidenceError):
            encoding(bytes(body))

    def test_augmentation_length_beyond_window_rejected(self):
        body = bytearray(cie_body(b'zR', b'\x1b'))
        # Rewrite the augmentation-length byte (offset 11 for 'zR') to 60,
        # pushing aug_end past the 64-byte window.
        body[11] = 60
        with self.assertRaises(w.EvidenceError):
            encoding(bytes(body))

    def test_no_r_augmentation_still_rejected(self):
        with self.assertRaises(w.EvidenceError):
            encoding(cie_body(b'zL', b'\x1b'))


if __name__ == '__main__':
    unittest.main()
