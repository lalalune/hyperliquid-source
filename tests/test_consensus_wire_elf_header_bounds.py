import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "consensus_wire", ROOT / "tools/consensus_wire.py")
cw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cw)


def elf_bytes(phoff=0, phnum=0, shoff=0, shnum=0, shstrndx=0, size=64):
    data = bytearray(size)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 0x20, phoff)
    struct.pack_into('<Q', data, 0x28, shoff)
    struct.pack_into('<HHHHH', data, 0x36, 56, phnum, 64, shnum, shstrndx)
    return bytes(data)


def valid_elf():
    data = bytearray(256)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 0x20, 0)
    struct.pack_into('<Q', data, 0x28, 64)
    struct.pack_into('<HHHHH', data, 0x36, 56, 0, 64, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', data, 64, 0, 3, 0, 0, 128, 8, 0, 0, 1, 0)
    data[128:136] = b'\x00.text\x00'
    return bytes(data)


class ElfHeaderBoundsTests(unittest.TestCase):
    def test_short_header_is_evidence_error(self):
        with self.assertRaises(cw.EvidenceError):
            cw.Elf(b'\x7fELF\x02\x01' + b'\x00' * 4)

    def test_program_header_table_past_eof_is_evidence_error(self):
        with self.assertRaises(cw.EvidenceError):
            cw.Elf(elf_bytes(phoff=1000, phnum=1))

    def test_section_header_table_past_eof_is_evidence_error(self):
        with self.assertRaises(cw.EvidenceError):
            cw.Elf(elf_bytes(shoff=1000, shnum=1))

    def test_second_section_header_past_eof_is_evidence_error(self):
        # First entry fits (64..128), the second would run past the 191-byte file.
        with self.assertRaises(cw.EvidenceError):
            cw.Elf(elf_bytes(shoff=64, shnum=2, size=191))

    def test_valid_minimal_elf_parses(self):
        elf = cw.Elf(valid_elf())
        self.assertEqual(elf.sections, {'': (0, 128, 8)})


if __name__ == "__main__":
    unittest.main()
