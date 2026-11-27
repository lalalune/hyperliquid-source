#!/usr/bin/env python3
"""Static node #115 verification for RE-012-node115-node-runtime-crate."""

import hashlib
import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = ROOT / "research" / "work-items" / "RE-012-node115-node-runtime-crate"
RECORDS_PATH = PACKET / "records.json"

TEXT_VA = 0x1419300
TEXT_OFF = 0x1418300


class TestNodeRuntime115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        cls.data = ARTIFACT.read_bytes()

    def test_artifact_digest_pinned(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), self.records["sha256"])

    def test_all_21_node_runtime_source_paths(self):
        self.assertEqual(len(self.records["source_paths"]), 21)
        for sp in self.records["source_paths"]:
            va = int(sp["rodata_va"], 16)
            expected = sp["path"].encode("ascii")
            self.assertEqual(self.data[va : va + len(expected)], expected)

    def test_all_7_node_port_jump_table_arms_and_ports(self):
        tbl = self.records["node_port_table"]
        tbl_va = int(tbl["jump_table_va"], 16)
        self.assertEqual(len(tbl["entries"]), 7)
        ports_seen = set()
        for entry in tbl["entries"]:
            idx = entry["index"]
            rel = struct.unpack_from("<i", self.data, tbl_va + idx * 4)[0]
            arm_va = tbl_va + rel
            self.assertEqual(arm_va, int(entry["arm_va"], 16))
            fo = arm_va - (TEXT_VA - TEXT_OFF)
            insn = self.data[fo : fo + 4]
            self.assertEqual(insn[:2], b"\x66\xb8")
            port = struct.unpack_from("<H", insn, 2)[0]
            self.assertEqual(port, entry["port"])
            ports_seen.add(port)
        self.assertEqual(ports_seen, {3998, 3999, 4001, 4002, 4003, 4004, 4005})
        # Negative control: port 4000 is not in NodePort table
        self.assertNotIn(4000, ports_seen)

    def test_rodata_cli_config_and_build_stamp_anchors(self):
        for anchor in self.records["rodata_anchors"]:
            va = int(anchor["va"], 16)
            expected = anchor["text"].encode("ascii")
            self.assertEqual(
                self.data[va : va + len(expected)],
                expected,
                f"mismatch for anchor {anchor['name']} at {anchor['va']}",
            )

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
