import hashlib
import importlib.util
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET_DIR = ROOT / "research/work-items/RE-008-node115-staking-jailing"
TARGET = ROOT / "artifacts/node/115/hl-node"


def load_verifier():
    spec = importlib.util.spec_from_file_location("re008_staking_jailing_verify", PACKET_DIR / "verify.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class TestNode115StakingJailing(unittest.TestCase):
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
        self.assertEqual(report["functions_verified"], 5)
        self.assertEqual(report["total_function_bytes"], 10178)
        self.assertEqual(report["windows_verified"], 10)
        self.assertEqual(report["facts_verified"], 15)
        self.assertEqual(report["negative_controls_passed"], 6)

    def test_rust_admission_constants_match_node115_rodata(self):
        mod = load_verifier()
        helper = mod.load_elf_support()
        image = helper.Image(TARGET.read_bytes())

        rust_src = (ROOT / "src/node115-staking/src/admission.rs").read_text()
        m_tbl = re.search(r"pub const ACTION_CLASS_TABLE: \[u8; 92\] = \[(.*?)\];", rust_src, re.S)
        self.assertIsNotNone(m_tbl)
        tbl_vals = [int(x) for x in re.findall(r"\b[0-4]\b", re.sub(r"//.*", "", m_tbl.group(1)))]
        self.assertEqual(len(tbl_vals), 92)
        self.assertEqual(bytes(tbl_vals), image.get(0x79dd60, 92))

        m_addrs = re.search(
            r"pub const OTHER_CHAIN_LISTED_ADDRESSES: \[Address; 3\] = \[(.*?)\];",
            rust_src,
            re.S,
        )
        self.assertIsNotNone(m_addrs)
        addr_bytes = [int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m_addrs.group(1))]
        self.assertEqual(len(addr_bytes), 60)
        self.assertEqual(bytes(addr_bytes), image.get(0x464946, 60))

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
