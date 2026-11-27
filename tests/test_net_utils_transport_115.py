#!/usr/bin/env python3
"""Static node #115 verification for RE-012-node115-net-utils-transport."""

import hashlib
import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = ROOT / "research" / "work-items" / "RE-012-node115-net-utils-transport"
RECORDS_PATH = PACKET / "records.json"

TEXT_VA = 0x1419300
TEXT_OFF = 0x1418300
RELRO_VA = 0x63F3C20
RELRO_OFF = 0x63F1C20
RELA_OFF = 0x6BE8
RELA_SZ = 0x163CC8


class TestNetUtilsTransport115(unittest.TestCase):
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
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), self.records["sha256"])

    def test_all_12_net_utils_source_paths_and_locations(self):
        self.assertEqual(len(self.records["source_paths"]), 12)
        for sp in self.records["source_paths"]:
            va = int(sp["rodata_va"], 16)
            expected = sp["path"].encode("ascii")
            self.assertEqual(self.data[va : va + len(expected)], expected)
            loc = sp["sample_location"]
            lva = int(loc["va"], 16)
            self.assertEqual(self.relocs.get(lva), va)
            fo = lva - (RELRO_VA - RELRO_OFF)
            _, slen, line, col = struct.unpack_from("<QQII", self.data, fo)
            self.assertEqual(slen, len(expected))
            self.assertEqual(line, loc["line"])
            self.assertEqual(col, loc["col"])

    def test_diagnostic_strings(self):
        for entry in self.records["diagnostic_strings"]:
            va = int(entry["va"], 16)
            expected = entry["text"].encode("ascii")
            self.assertEqual(self.data[va : va + len(expected)], expected)

    def test_timing_constants_and_negative_controls(self):
        c = self.records["constants"]
        va = int(c["write_timeout_movabs_va"], 16)
        fo = va - (TEXT_VA - TEXT_OFF)
        expected_bytes = bytes.fromhex(c["write_timeout_movabs_hex"])
        self.assertEqual(self.data[fo : fo + len(expected_bytes)], expected_bytes)
        self.assertEqual(struct.unpack("<d", expected_bytes[2:])[0], c["write_timeout_secs"])

        lz4_val = struct.unpack_from("<d", self.data, int(c["lz4_stats_window_va"], 16))[0]
        self.assertEqual(lz4_val, c["lz4_stats_window_secs"])
        self.assertNotEqual(lz4_val, 60.0)

        tr_val = struct.unpack_from("<d", self.data, int(c["traffic_recorder_window_va"], 16))[0]
        self.assertEqual(tr_val, c["traffic_recorder_window_secs"])
        self.assertNotEqual(tr_val, 300.0)

    def test_packet_manifest_valid(self):
        manifest = PACKET / "MANIFEST.sha256"
        self.assertTrue(manifest.is_file())
        for line in manifest.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            digest, rel = line.split("  ", 1)
            actual = hashlib.sha256((PACKET / rel).read_bytes()).hexdigest()
            self.assertEqual(actual, digest)


if __name__ == "__main__":
    unittest.main()
