#!/usr/bin/env python3
"""Static node #115 verification for RE-012-node115-stream-protocols."""

import hashlib
import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = ROOT / "research" / "work-items" / "RE-012-node115-stream-protocols"
RECORDS_PATH = PACKET / "records.json"

TEXT_VA = 0x1419300
TEXT_OFF = 0x1418300


class TestStreamProtocols115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        cls.data = ARTIFACT.read_bytes()

    def test_artifact_digest_pinned(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), self.records["sha256"])

    def test_evm_kvs_msg_dispatch_and_type_name(self):
        ev = self.records["evm_kvs_msg"]
        va = int(ev["type_name_rodata_va"], 16)
        name = ev["type_name"].encode("ascii")
        self.assertEqual(self.data[va : va + len(name)], name)

        dva = int(ev["dispatch_va"], 16)
        fo = dva - (TEXT_VA - TEXT_OFF)
        expected = bytes.fromhex(ev["dispatch_bytes_hex"])
        self.assertEqual(self.data[fo : fo + len(expected)], expected)
        # Negative control: `cmpl $0x1, %r14d` (41 83 fe 01) checks 2 variants, not 3
        self.assertIn(b"\x41\x83\xfe\x01", expected)
        self.assertNotIn(b"\x41\x83\xfe\x02", expected)

    def test_abci_stream_greeting_6_variant_jump_table(self):
        ag = self.records["abci_stream_greeting"]
        va = int(ag["type_name_rodata_va"], 16)
        name = ag["type_name"].encode("ascii")
        self.assertEqual(self.data[va : va + len(name)], name)

        tbl_va = int(ag["jump_table_va"], 16)
        self.assertEqual(len(ag["variants"]), 6)
        for v in ag["variants"]:
            rel = struct.unpack_from("<i", self.data, tbl_va + v["index"] * 4)[0]
            self.assertEqual(tbl_va + rel, int(v["arm_va"], 16))

    def test_greeting_hash_type_name(self):
        gh = self.records["greeting_hash"]
        va = int(gh["type_name_rodata_va"], 16)
        name = gh["type_name"].encode("ascii")
        self.assertEqual(self.data[va : va + len(name)], name)

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
