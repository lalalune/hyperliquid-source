import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import evm_amount_scale as m

# DW_EH_PE base formats this tool decodes: udata4/sdata4/udata8/sdata8.
UNSUPPORTED_FORMATS = (0x00, 0x01, 0x02, 0x05, 0x09, 0x0a, 0x0d, 0x0f)


class FakeImg:
    """Stub image: read returns bytes 01..08 truncated to the request size."""

    def read(self, va, size):
        return bytes(range(1, 9))[:size]


class ReadEncTests(unittest.TestCase):
    def setUp(self):
        self.img = FakeImg()

    def test_udata4(self):
        self.assertEqual(m.read_enc(self.img, 0x1000, 0x03), (0x04030201, 4))

    def test_sdata4(self):
        self.assertEqual(m.read_enc(self.img, 0x1000, 0x0b), (0x04030201, 4))

    def test_udata8(self):
        self.assertEqual(
            m.read_enc(self.img, 0x1000, 0x04), (0x0807060504030201, 8))

    def test_sdata8(self):
        self.assertEqual(
            m.read_enc(self.img, 0x1000, 0x0c), (0x0807060504030201, 8))

    def test_pcrel_sdata4_adds_va(self):
        self.assertEqual(
            m.read_enc(self.img, 0x1000, 0x1b), (0x1000 + 0x04030201, 4))

    def test_unsupported_formats_rejected_as_evidence(self):
        for enc in UNSUPPORTED_FORMATS:
            with self.subTest(enc=enc):
                with self.assertRaises(m.EvidenceError):
                    m.read_enc(self.img, 0x1000, enc)

    def test_unsupported_format_with_pcrel_bits_rejected_as_evidence(self):
        with self.assertRaises(m.EvidenceError):
            m.read_enc(self.img, 0x1000, 0x10)

    def test_unsupported_application_still_rejected_as_evidence(self):
        with self.assertRaises(m.EvidenceError):
            m.read_enc(self.img, 0x1000, 0x23)


if __name__ == '__main__':
    unittest.main()
