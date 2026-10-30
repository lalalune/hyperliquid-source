import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import vault_distribution_static as vds

PACKET = ROOT / "research" / "work-items" / "vault-distribution-94"
BINARY = ROOT / vds.BINARY_REL


class VaultDistributionStaticTests(unittest.TestCase):
    def test_binary_digest(self):
        self.assertTrue(BINARY.exists())
        data = BINARY.read_bytes()
        vds.check_digest(data)
        with self.assertRaises(vds.EvidenceError):
            vds.check_digest(b"corrupt")

    def test_analysis_fdes(self):
        data = BINARY.read_bytes()
        analysis = vds.analyse(data)
        self.assertEqual(len(analysis["fdes"]), 3)
        total_bytes = sum(f["bytes"] for f in analysis["fdes"])
        self.assertEqual(total_bytes, 12528)

        fde_ids = {f["id"] for f in analysis["fdes"]}
        self.assertEqual(
            fde_ids,
            {"fde1_apply_distribution", "fde2_verify_equity", "fde3_ledger_transition"},
        )

    def test_panic_records(self):
        data = BINARY.read_bytes()
        analysis = vds.analyse(data)
        records = analysis["source_records"]
        self.assertEqual(len(records), 7)

        # 6 records in vault/mod.rs
        vault_records = [r for r in records.values() if "vault/mod.rs" in r["path"]]
        self.assertEqual(len(vault_records), 6)

        # 1 record in qtys/mod.rs
        qtys_records = [r for r in records.values() if "qtys/mod.rs" in r["path"]]
        self.assertEqual(len(qtys_records), 1)
        self.assertEqual(qtys_records[0]["line"], 843)
        self.assertEqual(qtys_records[0]["col"], 1)

    def test_control_opcodes(self):
        data = BINARY.read_bytes()
        analysis = vds.analyse(data)
        controls = analysis["controls"]
        self.assertEqual(len(controls), len(vds.CONTROLS))

        for va, op in vds.CONTROLS.items():
            self.assertIn(hex(va), controls)
            self.assertEqual(controls[hex(va)], op)

    def test_mathematical_profit_and_fee_model(self):
        # Case 1: Profitable vault distribution
        # share = 0.1, total_f = 1,000,000.0, deposited_ntl = 50,000, fee = 20%
        # gross = 100,000
        # principal = min(50,000, 100,000) = 50,000
        # profit = 100,000 - 50,000 = 50,000
        # fee = 50,000 * 0.2 = 10,000
        # participant_amount = 100,000 - 10,000 = 90,000
        res = vds.calculate_vault_distribution(0.1, 1000000.0, 50000, 0.2)
        self.assertEqual(res["gross"], 100000)
        self.assertEqual(res["principal"], 50000)
        self.assertEqual(res["profit"], 50000)
        self.assertEqual(res["fee"], 10000)
        self.assertEqual(res["participant_amount"], 90000)

        # Case 2: Break-even (no profit -> no fee)
        res_even = vds.calculate_vault_distribution(0.1, 1000000.0, 100000, 0.2)
        self.assertEqual(res_even["gross"], 100000)
        self.assertEqual(res_even["principal"], 100000)
        self.assertEqual(res_even["profit"], 0)
        self.assertEqual(res_even["fee"], 0)
        self.assertEqual(res_even["participant_amount"], 100000)

        # Case 3: Loss (gross < deposited -> no profit -> no fee)
        res_loss = vds.calculate_vault_distribution(0.1, 1000000.0, 150000, 0.2)
        self.assertEqual(res_loss["gross"], 100000)
        self.assertEqual(res_loss["principal"], 100000)
        self.assertEqual(res_loss["profit"], 0)
        self.assertEqual(res_loss["fee"], 0)
        self.assertEqual(res_loss["participant_amount"], 100000)

        # Case 4: Zero fee fraction
        res_zero_fee = vds.calculate_vault_distribution(0.25, 2000000.0, 100000, 0.0)
        self.assertEqual(res_zero_fee["profit"], 400000)
        self.assertEqual(res_zero_fee["fee"], 0)
        self.assertEqual(res_zero_fee["participant_amount"], 500000)

    def test_mathematical_model_input_validation(self):
        with self.assertRaises(vds.EvidenceError):
            vds.calculate_vault_distribution(-0.1, 1000.0, 100, 0.1)
        with self.assertRaises(vds.EvidenceError):
            vds.calculate_vault_distribution(0.1, -1000.0, 100, 0.1)
        with self.assertRaises(vds.EvidenceError):
            vds.calculate_vault_distribution(0.1, 1000.0, -100, 0.1)
        with self.assertRaises(vds.EvidenceError):
            vds.calculate_vault_distribution(0.1, 1000.0, 100, 1.5)

    def test_negative_controls_opcode_mutation(self):
        data = BINARY.read_bytes()
        original_op = vds.CONTROLS[0x3957a86]
        try:
            vds.CONTROLS[0x3957a86] = "90909090909090"
            with self.assertRaises(vds.EvidenceError):
                vds.analyse(data)
        finally:
            vds.CONTROLS[0x3957a86] = original_op

    def test_negative_panic_record_mutation(self):
        data = BINARY.read_bytes()
        original_line = vds.SOURCE_RECORDS["0x570d9a0"]["line"]
        try:
            vds.SOURCE_RECORDS["0x570d9a0"]["line"] = 9999
            with self.assertRaises(AssertionError):
                vds.analyse(data)
        finally:
            vds.SOURCE_RECORDS["0x570d9a0"]["line"] = original_line

    def test_manifest_verification(self):
        manifest_path = PACKET / "MANIFEST.sha256"
        self.assertTrue(manifest_path.exists())
        lines = manifest_path.read_text(encoding="utf-8").splitlines()
        self.assertGreaterEqual(len(lines), 4)
        for line in lines:
            digest, rel_path = line.split("  ")
            target = PACKET / rel_path
            self.assertTrue(target.is_file(), f"Target missing: {target}")
            data = target.read_bytes()
            self.assertFalse(b"\r" in data, f"CRLF in {target}")
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)

    def test_packet_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            vds.generate_packet(tmp_path, BINARY)
            manifest_orig = (PACKET / "MANIFEST.sha256").read_bytes()
            manifest_new = (tmp_path / "MANIFEST.sha256").read_bytes()
            self.assertEqual(manifest_orig, manifest_new)


if __name__ == "__main__":
    unittest.main()
