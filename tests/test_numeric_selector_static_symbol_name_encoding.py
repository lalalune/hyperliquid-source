"""Dynamic-symbol name decoding in numeric_selector_static must fail closed.

extract() decodes the .dynstr name for each RIP-relative relocation target
through a bare .decode(). A mutated name byte must refuse as the module's
require() ValueError, not escape as a raw UnicodeDecodeError. The two
decoded names on the pinned binary are memcpy and bcmp; mutating a byte
inside memcpy's name exercises the decode, while mutating the leading
.dynstr NUL (never part of a decoded name) is the control that analysis
still succeeds.
"""
import hashlib
import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import numeric_selector_static as n


class SymbolNameEncodingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = n.TARGET.read_bytes()
        if len(cls.data) != n.SIZE or hashlib.sha256(cls.data).hexdigest() != n.SHA:
            raise ValueError("materialized pinned node115 required")
        cls.report, _ = n.analyze(cls.data)
        cls.sections, _ = n.reader(cls.data)
        dynsym = next(s for s in cls.sections if s["name"] == ".dynsym")
        dynstr = next(s for s in cls.sections if s["name"] == ".dynstr")
        cls.dynsym_offset = dynsym["offset"]
        cls.dynstr_offset = dynstr["offset"]
        entry = next(v for v in cls.report["relocations"].values()
                     if v["symbol"] == "memcpy")
        name_offset = struct.unpack_from(
            "<I", cls.data, cls.dynsym_offset + 24 * entry["symbol_index"])[0]
        cls.name_offset = cls.dynstr_offset + name_offset
        cls.name = entry["symbol"].encode()

    def mutated(self, offset, byte):
        result = bytearray(self.data)
        result[offset] = byte
        return bytes(result)

    def test_non_utf8_symbol_name_fails_closed(self):
        mutant = self.mutated(self.name_offset + 1, 0xFF)
        with self.assertRaisesRegex(ValueError,
                                    "dynamic symbol name is not valid UTF-8"):
            n.analyze(mutant)

    def test_latin1_symbol_name_fails_closed(self):
        mutant = self.mutated(self.name_offset + 1, 0xE9)
        with self.assertRaisesRegex(ValueError,
                                    "dynamic symbol name is not valid UTF-8"):
            n.analyze(mutant)

    def test_undecoded_dynstr_byte_leaves_analysis_intact(self):
        mutant = self.mutated(self.dynstr_offset, 0xFF)
        report, _ = n.analyze(mutant)
        self.assertEqual(report["relocations"], self.report["relocations"])


if __name__ == "__main__":
    unittest.main()
