"""read_enc must fail closed on unsupported pointer-encoding formats.

read_enc decodes DWARF pointer encodings from parsed .eh_frame data, but
its format table lookup is a bare dict index: any format outside
{udata4, sdata4, udata8, sdata8} escapes as KeyError instead of the
tool's EvidenceError. The same function already fails closed with
EvidenceError for unsupported application encodings, so an unknown format
must do the same.
"""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import wei_buffered_cap as eas


def synthetic_elf():
    """Minimal ELF64-LE with a .text section of 0x90 bytes."""
    shstr = b'\x00.text\x00.shstrtab\x00'
    text_bytes = b'\x90' * 16
    shoff = 64 + len(text_bytes) + len(shstr)

    def sh(name, typ, flags, addr, off, size):
        return struct.pack('<IIQQQQIIQQ', name, typ, flags, addr, off, size, 0, 0, 1, 0)

    headers = (sh(0, 0, 0, 0, 0, 0)
               + sh(1, 1, 6, 0x400000, 64, len(text_bytes))
               + sh(7, 3, 0, 0, 64 + len(text_bytes), len(shstr)))
    ehdr = bytearray(64)
    ehdr[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', ehdr, 0x28, shoff)
    struct.pack_into('<HHH', ehdr, 0x3a, 64, 3, 2)
    return bytes(ehdr) + text_bytes + shstr + headers


class ReadEncFormatTests(unittest.TestCase):
    def test_unsupported_formats_raise_evidence_error(self):
        img = eas.Image(synthetic_elf())
        # Real DWARF formats the table does not support: uleb128, udata2,
        # sleb128, sdata2, and absptr (size 0 in this table's terms).
        for enc in (0x01, 0x02, 0x09, 0x0a, 0x00):
            with self.subTest(enc=enc):
                with self.assertRaises(eas.EvidenceError):
                    eas.read_enc(img, 0x400000, enc)

    def test_unsupported_format_with_pcrel_bits_also_evidence_error(self):
        img = eas.Image(synthetic_elf())
        with self.assertRaises(eas.EvidenceError):
            eas.read_enc(img, 0x400000, 0x11)  # pcrel + uleb128

    def test_supported_formats_still_decode(self):
        img = eas.Image(synthetic_elf())
        self.assertEqual(eas.read_enc(img, 0x400000, 0x03), (0x90909090, 4))
        self.assertEqual(eas.read_enc(img, 0x400000, 0x0b), (0xFFFFFFFF90909090, 4))
        self.assertEqual(eas.read_enc(img, 0x400000, 0x04), (0x9090909090909090, 8))
        self.assertEqual(eas.read_enc(img, 0x400000, 0x0c), (0x9090909090909090, 8))
        # pcrel application bit still applies on a supported format.
        val, n = eas.read_enc(img, 0x400000, 0x13)
        self.assertEqual((val, n), (0x400000 + 0x90909090, 4))

    def test_unsupported_application_encoding_still_evidence_error(self):
        img = eas.Image(synthetic_elf())
        with self.assertRaises(eas.EvidenceError):
            eas.read_enc(img, 0x400000, 0x33)  # indirect + udata4


if __name__ == '__main__':
    unittest.main()
