import hashlib
import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKET_DIR = ROOT / "research" / "work-items" / "RE-004-node115-fee-solvency-and-vlm-gates"
EVIDENCE_PATH = PACKET_DIR / "evidence.json"
MANIFEST_PATH = PACKET_DIR / "MANIFEST.sha256"
BINARY_PATH = ROOT / "artifacts" / "node" / "115" / "hl-node"


class TestFeeSolvencyAndVlmGates115(unittest.TestCase):
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

    def test_fdes_solvency_scales_and_constants_match_node115(self) -> None:
        sec = self.evidence["sections"]
        text_va = int(sec["text_va"], 16)
        text_off = int(sec["text_file_offset"], 16)
        ro_va = int(sec["rodata_va"], 16)
        ro_off = int(sec["rodata_file_offset"], 16)

        total_bytes = 0
        for fde in self.evidence["fdes"]:
            start = int(fde["start"], 16)
            end = int(fde["end"], 16)
            size = end - start
            self.assertEqual(size, fde["size"], fde["name"])
            total_bytes += size
            raw = self.binary[text_off + (start - text_va) : text_off + (end - text_va)]
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                fde["sha256"],
                f"FDE digest mismatch for {fde['name']}",
            )
        self.assertEqual(len(self.evidence["fdes"]), 8)
        self.assertEqual(total_bytes, 9568)

        # Verify all 11 .rodata IEEE-754 f64 constants
        for item in self.evidence["rodata_f64_constants"]:
            va = int(item["va"], 16)
            bits = struct.unpack_from("<Q", self.binary, ro_off + (va - ro_va))[0]
            self.assertEqual(bits, int(item["bits"], 16), item["label"])
            val = struct.unpack_from("<d", self.binary, ro_off + (va - ro_va))[0]
            self.assertEqual(val, item["value"], item["label"])

        # Verify contiguous 6-scale table at .rodata 0x79d4d0
        tbl = self.evidence["protocol_fee_scales_table"]
        tbl_off = ro_off + (int(tbl["va"], 16) - ro_va)
        for i, (exp_val, exp_bits) in enumerate(zip(tbl["values"], tbl["bits"])):
            bits = struct.unpack_from("<Q", self.binary, tbl_off + i * 8)[0]
            val = struct.unpack_from("<d", self.binary, tbl_off + i * 8)[0]
            self.assertEqual(bits, int(exp_bits, 16))
            self.assertEqual(val, exp_val)

        # Negative control: flipping a byte in 0x36a58d0 must fail SHA-256 verification
        solv = next(f for f in self.evidence["fdes"] if f["name"] == "fee_schedule_solvency_0x36a58d0")
        s = int(solv["start"], 16)
        e = int(solv["end"], 16)
        mutated = bytearray(self.binary[text_off + (s - text_va) : text_off + (e - text_va)])
        mutated[0] ^= 0xFF
        self.assertNotEqual(hashlib.sha256(bytes(mutated)).hexdigest(), solv["sha256"])


if __name__ == "__main__":
    unittest.main()
