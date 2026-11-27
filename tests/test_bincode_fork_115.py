#!/usr/bin/env python3
"""Static node #115 verification for RE-005-node115-bincode-fork-codec."""

import hashlib
import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = ROOT / "research" / "work-items" / "RE-005-node115-bincode-fork-codec"
RECORDS_PATH = PACKET / "records.json"

TEXT_VA = 0x1419300
TEXT_OFF = 0x1418300
RELRO_VA = 0x63F3C20
RELRO_OFF = 0x63F1C20
RELA_OFF = 0x6BE8
RELA_SZ = 0x163CC8


class TestBincodeFork115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        cls.data = ARTIFACT.read_bytes()
        cls.relocs = {}
        for off in range(RELA_OFF, RELA_OFF + RELA_SZ, 24):
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", cls.data, off)
            if (r_info & 0xFFFFFFFF) == 8:
                cls.relocs[r_offset] = r_addend

    def test_artifact_digest_pinned(self):
        digest = hashlib.sha256(self.data).hexdigest()
        self.assertEqual(digest, self.records["sha256"])

    def test_four_bincode_fork_source_paths_and_locations(self):
        self.assertEqual(len(self.records["source_paths"]), 4)
        for sp in self.records["source_paths"]:
            va = int(sp["rodata_va"], 16)
            expected = sp["path"].encode("ascii")
            self.assertEqual(self.data[va : va + len(expected)], expected)
            for loc in sp["locations"]:
                lva = int(loc["va"], 16)
                self.assertEqual(self.relocs.get(lva), va)
                fo = lva - (RELRO_VA - RELRO_OFF)
                _, slen, line, col = struct.unpack_from("<QQII", self.data, fo)
                self.assertEqual(slen, len(expected))
                self.assertEqual(line, loc["line"])
                self.assertEqual(col, loc["col"])

    def test_all_18_decode_error_jump_table_arms(self):
        de = self.records["decode_error_fmt"]
        tbl_va = int(de["jump_table_va"], 16)
        self.assertEqual(len(de["variants"]), 18)
        for v in de["variants"]:
            tag = v["tag"]
            rel = struct.unpack_from("<i", self.data, tbl_va + tag * 4)[0]
            self.assertEqual(tbl_va + rel, int(v["arm_va"], 16))
        # Corruption control: tag 1 must not resolve to tag 2 (LimitExceeded)
        rel1 = struct.unpack_from("<i", self.data, tbl_va + 4)[0]
        rel2 = struct.unpack_from("<i", self.data, tbl_va + 8)[0]
        self.assertNotEqual(tbl_va + rel1, tbl_va + rel2)

    def test_all_13_integer_type_entries(self):
        it = self.records["integer_type_table"]
        ptr_base = int(it["ptr_table_va"], 16)
        len_base = int(it["len_table_va"], 16)
        entries = it["entries"]
        self.assertEqual(len(entries), 13)
        lens = struct.unpack_from("<13Q", self.data, len_base)
        for idx, name in enumerate(entries):
            str_va = self.relocs[ptr_base + idx * 8]
            actual = self.data[str_va : str_va + lens[idx]].decode("ascii")
            self.assertEqual(actual, name)

    def test_invalid_bytes_length_prealloc_guard_bytes(self):
        guard = self.records["invalid_bytes_length_guard"]
        va = int(guard["check_va"], 16)
        fo = va - (TEXT_VA - TEXT_OFF)
        expected = bytes.fromhex(guard["check_bytes_hex"])
        self.assertEqual(self.data[fo : fo + len(expected)], expected)
        # Positive + negative control: final instruction is `movb $0x1, %r12b` (41 b4 01)
        self.assertEqual(expected[-3:], b"\x41\xb4\x01")
        self.assertNotEqual(expected[-3:], b"\x41\xb4\x02")

    def test_packet_manifest_valid(self):
        manifest = PACKET / "MANIFEST.sha256"
        self.assertTrue(manifest.is_file(), "MANIFEST.sha256 missing")
        for line in manifest.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            digest, rel = line.split("  ", 1)
            actual = hashlib.sha256((PACKET / rel).read_bytes()).hexdigest()
            self.assertEqual(actual, digest, f"manifest mismatch for {rel}")


if __name__ == "__main__":
    unittest.main()
