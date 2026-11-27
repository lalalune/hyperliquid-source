"""Binary-backed verification for RE-012 node #115 GossipRpcResponse, connections, and local_abci_state."""

import hashlib
import json
import pathlib
import struct
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent
BIN_PATH = REPO / "artifacts" / "node" / "115" / "hl-node"
PACKET_DIR = REPO / "research" / "work-items" / "RE-012-node115-gossip-rpc-connections-local-state"
RECORDS_PATH = PACKET_DIR / "records.json"
MANIFEST_PATH = PACKET_DIR / "MANIFEST.sha256"

EXPECTED_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TEXT_DELTA = 0x1000


class TestGossipRpcConnectionsLocalState115(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = BIN_PATH.read_bytes()
        cls.records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))

    def test_pinned_binary_sha256(self) -> None:
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), EXPECTED_SHA256)
        self.assertEqual(self.records["target"]["sha256"], EXPECTED_SHA256)

    def test_rodata_anchors(self) -> None:
        for name, entry in self.records["rodata_anchors"].items():
            va = int(entry["va"], 16)
            expected = entry["text"].encode("utf-8")
            self.assertEqual(self.data[va : va + len(expected)], expected, f"mismatch for {name}")

    def test_client_blocks_error_jump_tables(self) -> None:
        for jt_name, jt in self.records["jump_tables"].items():
            base = int(jt["base_va"], 16)
            targets = [int(t, 16) for t in jt["targets"]]
            self.assertEqual(len(targets), 7, f"expected 7 variants in {jt_name}")
            for i, expected_target in enumerate(targets):
                rel = struct.unpack_from("<i", self.data, base + i * 4)[0]
                self.assertEqual(base + rel, expected_target, f"{jt_name}[{i}]")

    def test_timeout_and_threshold_constants(self) -> None:
        c = self.records["constants"]
        for key in ("connection_checks_timeout_secs", "handle_node_connection_timeout_secs"):
            va = int(c[key]["va"], 16)
            val = struct.unpack_from("<d", self.data, va)[0]
            self.assertEqual(val, c[key]["value"])

        # 0x2add493: 48 81 c1 20 4e 00 00 (add rcx, 0x4e20 = 20000)
        lag_off = int(c["max_local_height_lag"]["text_va"], 16) - TEXT_DELTA
        self.assertEqual(self.data[lag_off : lag_off + 3], b"\x48\x81\xc1")
        self.assertEqual(struct.unpack_from("<I", self.data, lag_off + 3)[0], 20_000)

        # 0x2add534: 48 81 c7 90 01 00 00 (add rdi, 0x190 = 400)
        win_off = int(c["upgrade_round_window"]["text_va"], 16) - TEXT_DELTA
        self.assertEqual(self.data[win_off : win_off + 3], b"\x48\x81\xc7")
        self.assertEqual(struct.unpack_from("<I", self.data, win_off + 3)[0], 400)

    def test_negative_control_and_manifest(self) -> None:
        va = int(self.records["rodata_anchors"]["err_peer_only"]["va"], 16)
        self.assertNotEqual(self.data[va + 1 : va + 1 + len(b"PeerOnlyRequest")], b"PeerOnlyRequest")

        lines = [ln.strip() for ln in MANIFEST_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertEqual(len(lines), 2)
        seen = set()
        for line in lines:
            expected_hash, rel_name = line.split("  ", 1)
            seen.add(rel_name)
            actual = hashlib.sha256((PACKET_DIR / rel_name).read_bytes()).hexdigest()
            self.assertEqual(actual, expected_hash)
        self.assertEqual(seen, {"README.md", "records.json"})


if __name__ == "__main__":
    unittest.main()
