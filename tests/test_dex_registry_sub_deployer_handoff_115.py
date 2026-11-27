import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/dex-registry-sub-deployer-handoff-115"
TARGET = ROOT / "artifacts/node/115/hl-node"
SPEC = importlib.util.spec_from_file_location("sub_deployer_handoff_verify", PACKET / "verify.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)
verify_bytes = VERIFY.verify_bytes


class SubDeployerHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = TARGET.read_bytes()
        cls.records = json.loads((PACKET / "records.json").read_text())

    def test_pinned_handoff_path(self):
        result = verify_bytes(self.data, self.records)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["fde_bodies"], 18)
        self.assertEqual(result["instruction_anchors"], 39)

    def test_wrong_target_bytes_are_rejected(self):
        changed = bytearray(self.data)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "target digest mismatch"):
            verify_bytes(bytes(changed), self.records)

    def test_wrong_fde_hash_is_rejected(self):
        records = copy.deepcopy(self.records)
        records["copies"][0]["functions"]["loop"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "FDE byte hash mismatch"):
            verify_bytes(self.data, records)

    def test_wrong_call_target_anchor_is_rejected(self):
        records = copy.deepcopy(self.records)
        records["anchors"][1]["target"] = "0x2ce6f91"
        with self.assertRaisesRegex(ValueError, "direct target mismatch"):
            verify_bytes(self.data, records)


if __name__ == "__main__":
    unittest.main()
