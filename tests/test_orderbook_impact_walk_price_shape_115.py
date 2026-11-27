import hashlib
import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKET_DIR = ROOT / "research" / "work-items" / "RE-006-node115-impact-walk-and-price-shape"
EVIDENCE_PATH = PACKET_DIR / "evidence.json"
MANIFEST_PATH = PACKET_DIR / "MANIFEST.sha256"
BINARY_PATH = ROOT / "artifacts" / "node" / "115" / "hl-node"


class TestOrderbookImpactWalkPriceShape115(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        cls.binary = BINARY_PATH.read_bytes()

    def test_manifest_and_target_sha256(self) -> None:
        self.assertEqual(
            hashlib.sha256(self.binary).hexdigest(),
            self.evidence["target_sha256"],
        )
        entries = {}
        for line in MANIFEST_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            digest, rel = line.split(None, 1)
            entries[rel] = digest
        self.assertEqual(set(entries), {"README.md", "evidence.json"})
        for rel, expected in entries.items():
            actual = hashlib.sha256((PACKET_DIR / rel).read_bytes()).hexdigest()
            self.assertEqual(actual, expected, f"manifest mismatch for {rel}")

    def test_fdes_constants_and_system_users_match_node115(self) -> None:
        sec = self.evidence["sections"]
        text_va = int(sec["text_va"], 16)
        text_off = int(sec["text_file_offset"], 16)
        ro_va = int(sec["rodata_va"], 16)
        ro_off = int(sec["rodata_file_offset"], 16)

        total_bytes = 0
        for fde in self.evidence["fdes"]:
            s, e = int(fde["start"], 16), int(fde["end"], 16)
            self.assertEqual(e - s, fde["size"], fde["name"])
            total_bytes += e - s
            raw = self.binary[text_off + (s - text_va) : text_off + (e - text_va)]
            self.assertEqual(hashlib.sha256(raw).hexdigest(), fde["sha256"], fde["name"])
        self.assertEqual(len(self.evidence["fdes"]), 6)
        self.assertEqual(total_bytes, 9544)

        for item in self.evidence["rodata_f64_constants"]:
            va = int(item["va"], 16)
            bits = struct.unpack_from("<Q", self.binary, ro_off + (va - ro_va))[0]
            val = struct.unpack_from("<d", self.binary, ro_off + (va - ro_va))[0]
            self.assertEqual(bits, int(item["bits"], 16), item["label"])
            self.assertEqual(val, item["value"], item["label"])

        for su in self.evidence["system_users"]:
            va = int(su["va"], 16)
            raw = self.binary[ro_off + (va - ro_va) : ro_off + (va - ro_va) + 20]
            self.assertEqual(raw.hex(), su["hex"])

        # Negative control
        f0 = self.evidence["fdes"][0]
        s0, e0 = int(f0["start"], 16), int(f0["end"], 16)
        mut = bytearray(self.binary[text_off + (s0 - text_va) : text_off + (e0 - text_va)])
        mut[0] ^= 0xFF
        self.assertNotEqual(hashlib.sha256(bytes(mut)).hexdigest(), f0["sha256"])


if __name__ == "__main__":
    unittest.main()
