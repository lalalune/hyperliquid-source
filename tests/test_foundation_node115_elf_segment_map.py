"""Tests for the node #115 ELF load map and VA-to-file-offset checker.

The module under test is tools/foundation_node115_elf_segment_map.py. The test
exercises the real checker: the derivation runs against the pinned target bytes
and against a constructed synthetic ELF whose expected map is known, and the
packet entry point is called so the committed checker itself is covered.

The synthetic ELF is a test fixture only; it is not derived from the target.
"""

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import foundation_node115_elf_segment_map as checker  # noqa: E402

TARGET = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = ROOT / "research" / "work-items" / "RE-002-node115-elf-segment-map"

PHOFF = 64
PHNUM = 2
SHOFF = PHOFF + PHNUM * 56
SHNUM = 3
STRTAB_OFF = SHOFF + SHNUM * 64
STRTAB = b"\x00.text\x00.shstrtab\x00"
TEXT_OFF = STRTAB_OFF + len(STRTAB)
TEXT = bytes(range(16))
TOTAL = TEXT_OFF + len(TEXT)
LOAD0_VADDR = 0x100000
TEXT_VADDR = 0x200000


def _phdr(ptype, flags, offset, vaddr, filesz, memsz, align):
    return struct.pack("<IIQQQQQQ", ptype, flags, offset, vaddr, vaddr,
                       filesz, memsz, align)


def _shdr(name, stype, flags, addr, offset, size, addralign):
    return struct.pack("<IIQQQQIIQQ", name, stype, flags, addr, offset, size,
                       0, 0, addralign, 0)


def build_elf(text_vaddr=TEXT_VADDR, text_sh_addr=None, filesz=None,
              memsz=None, truncate=0):
    if text_sh_addr is None:
        text_sh_addr = text_vaddr
    ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9
    header = ident + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, text_vaddr, PHOFF,
                                 SHOFF, 0, 64, 56, PHNUM, 64, SHNUM, 2)
    load0 = _phdr(1, 5, 0, LOAD0_VADDR, TOTAL, TOTAL + 0x100, 0x1000)
    load1 = _phdr(1, 5, TEXT_OFF, text_vaddr,
                  len(TEXT) if filesz is None else filesz,
                  len(TEXT) if memsz is None else memsz, 1)
    sections = (_shdr(0, 0, 0, 0, 0, 0, 0)
                + _shdr(1, 1, 6, text_sh_addr, TEXT_OFF, len(TEXT), 16)
                + _shdr(7, 3, 0, 0, STRTAB_OFF, len(STRTAB), 1))
    data = header + load0 + load1 + sections + STRTAB + TEXT
    if truncate:
        data = data[:len(data) - truncate]
    return data


class ElfSegmentMapTest(unittest.TestCase):
    def test_target_digest_matches_authority(self):
        self.assertEqual(checker.sha256_bytes(TARGET.read_bytes()),
                         checker.TARGET_SHA256)

    def test_target_load_map_is_self_consistent(self):
        record = checker.derive_map(TARGET)
        size = TARGET.stat().st_size
        self.assertEqual(record["target"]["size"], size)
        self.assertGreaterEqual(len(record["loads"]), 2)
        for seg in record["loads"]:
            self.assertLessEqual(seg["filesz"], seg["memsz"])
            self.assertLessEqual(seg["offset"] + seg["filesz"], size)

    def test_target_text_translation_round_trips(self):
        record = checker.derive_map(TARGET)
        text = record["text"]
        load = [s for s in record["loads"] if s["index"] == text["load_index"]][0]
        self.assertEqual(text["offset"] - load["offset"], text["addr"] - load["vaddr"])
        self.assertLessEqual(text["offset"] + text["size"], load["offset"] + load["filesz"])
        self.assertEqual(checker.va_to_offset(record["loads"], text["addr"]),
                         text["offset"])

    def test_target_entry_resolves_inside_one_load(self):
        record = checker.derive_map(TARGET)
        entry = record["entry"]
        hits = [s for s in record["loads"]
                if s["vaddr"] <= entry["va"] < s["vaddr"] + s["filesz"]]
        self.assertEqual(len(hits), 1)
        self.assertEqual(checker.va_to_offset(record["loads"], entry["va"]),
                         entry["file_offset"])

    def test_synthetic_elf_derives_known_map(self):
        record = checker.derive_from_bytes(build_elf())
        self.assertEqual(len(record["loads"]), 2)
        self.assertEqual(record["text"]["addr"], TEXT_VADDR)
        self.assertEqual(record["text"]["offset"], TEXT_OFF)
        self.assertEqual(record["entry"]["file_offset"], TEXT_OFF)
        self.assertEqual(record["text"]["size"], len(TEXT))

    def test_synthetic_zero_fill_va_is_refused(self):
        record = checker.derive_from_bytes(build_elf())
        load0 = [s for s in record["loads"] if s["index"] == 0][0]
        with self.assertRaises(checker.ElfFormatError):
            checker.va_to_offset(record["loads"],
                                 load0["vaddr"] + load0["filesz"] + 4)

    def test_rejects_filesz_above_memsz(self):
        with self.assertRaises(checker.ElfFormatError):
            checker.derive_from_bytes(build_elf(filesz=64, memsz=16))

    def test_rejects_load_past_file_extent(self):
        with self.assertRaises(checker.ElfFormatError):
            checker.derive_from_bytes(build_elf(filesz=4096, memsz=4096))

    def test_rejects_text_outside_every_load(self):
        with self.assertRaises(checker.ElfFormatError):
            checker.derive_from_bytes(build_elf(text_sh_addr=0x900000))

    def test_rejects_truncated_section_table(self):
        with self.assertRaises(checker.ElfFormatError):
            checker.derive_from_bytes(build_elf(truncate=8))

    def test_rejects_bad_magic(self):
        raw = bytearray(build_elf())
        raw[0:4] = b"\x7fELG"
        with self.assertRaises(checker.ElfFormatError):
            checker.parse_header(bytes(raw))

    def test_rejects_wrong_class_and_byte_order(self):
        raw = bytearray(build_elf())
        raw[4] = 1
        with self.assertRaises(checker.ElfFormatError):
            checker.parse_header(bytes(raw))
        raw = bytearray(build_elf())
        raw[5] = 2
        with self.assertRaises(checker.ElfFormatError):
            checker.parse_header(bytes(raw))

    def test_rejects_short_header(self):
        with self.assertRaises(checker.ElfFormatError):
            checker.parse_header(b"\x7fELF" + b"\x00" * 8)

    def test_packet_checker_runs_or_reports_missing_evidence(self):
        evidence = PACKET / "evidence.json"
        if evidence.is_file():
            derived = checker.check(PACKET, TARGET)
            self.assertEqual(derived, checker.derive_map(TARGET))
        else:
            with self.assertRaises(AssertionError) as caught:
                checker.check(PACKET, TARGET)
            self.assertIn("evidence.json", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
