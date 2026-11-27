import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET_DIR = ROOT / "research/work-items/RE-008-node115-block-rules-and-tc-verify"
TARGET = ROOT / "artifacts/node/115/hl-node"


def load_verifier():
    spec = importlib.util.spec_from_file_location("re008_block_rules_tc_verify", PACKET_DIR / "verify.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class TestNode115BlockRulesAndTcVerify(unittest.TestCase):
    def test_manifest_sha256_complete_and_valid(self):
        manifest_path = PACKET_DIR / "MANIFEST.sha256"
        self.assertTrue(manifest_path.is_file(), "MANIFEST.sha256 missing")
        entries = {}
        for line in manifest_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            digest, name = line.split(None, 1)
            entries[name.strip()] = digest
        self.assertIn("README.md", entries)
        self.assertIn("verify.py", entries)
        self.assertIn("records.json", entries)
        for name, expected in entries.items():
            actual = hashlib.sha256((PACKET_DIR / name).read_bytes()).hexdigest()
            self.assertEqual(actual, expected, f"manifest mismatch for {name}")

    def test_verify_packet_and_negative_controls(self):
        mod = load_verifier()
        packet = json.loads((PACKET_DIR / "records.json").read_text())
        report = mod.verify_packet(TARGET, packet)
        self.assertEqual(report["functions_verified"], 3)
        self.assertEqual(report["total_function_bytes"], 2839)
        self.assertEqual(report["windows_verified"], 11)
        self.assertEqual(report["facts_verified"], 16)
        self.assertEqual(report["negative_controls_passed"], 6)

    def test_rejects_wrong_target_digest(self):
        mod = load_verifier()
        packet = json.loads((PACKET_DIR / "records.json").read_text())
        tampered = dict(packet)
        tampered["target_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            mod.verify_packet(TARGET, tampered)

    def test_rejects_corrupted_window_hash(self):
        mod = load_verifier()
        packet = json.loads((PACKET_DIR / "records.json").read_text())
        tampered = json.loads(json.dumps(packet))
        tampered["windows"][0]["sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            mod.verify_packet(TARGET, tampered)


if __name__ == "__main__":
    unittest.main()
