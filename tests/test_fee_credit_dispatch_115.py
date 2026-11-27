import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "research/work-items/RE-004-node115-fee-credit-dispatch-115"))
import fee_credit_dispatch_verify as verify  # noqa: E402


class FeeCreditDispatch115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / "artifacts/node/115/hl-node").read_bytes()

    def test_dispatch_route_and_scope_limits(self):
        result = verify.verify_facts(self.data)
        self.assertEqual(result["indirect_call_sites"], [
            {
                "site": "0x241abca",
                "caller_fde_unwind_range": ["0x241a3c0", "0x241b097"],
                "raw_call_bytes": "ff1590af0c04",
                "argument_setup": {
                    "0x241abb5": "488b7c2428",
                    "0x241abba": "488db42460020000",
                    "0x241abc2": "4489fa",
                    "0x241abc5": "488b4c2468",
                },
            },
            {
                "site": "0x593c633",
                "caller_fde_unwind_range": ["0x593be40", "0x593cac6"],
                "raw_call_bytes": "ff152795ba00",
                "argument_setup": {
                    "0x593c61f": "488b7c2428",
                    "0x593c624": "488db42460020000",
                    "0x593c62c": "89da",
                    "0x593c62e": "488b4c2468",
                },
            },
            {
                "site": "0x593d2c3",
                "caller_fde_unwind_range": ["0x593cad0", "0x593d756"],
                "raw_call_bytes": "ff159788ba00",
                "argument_setup": {
                    "0x593d2af": "488b7c2428",
                    "0x593d2b4": "488db42460020000",
                    "0x593d2bc": "89da",
                    "0x593d2be": "488b4c2468",
                },
            },
        ])
        self.assertEqual(result["relative_relocation_target"], "0x3c10000")
        self.assertEqual(result["raw_text_slot_call_candidates"], 3)
        self.assertFalse(result["source_level_caller_roles_identified"])
        self.assertFalse(result["fee_tier_to_ledger_composition_proven"])

    def test_indirect_call_displacement_mutation_is_rejected(self):
        mutated = bytearray(self.data)
        at = self._file_offset(0x593C633 + 2, 1)
        mutated[at] ^= 1
        with self.assertRaisesRegex(verify.Reject, "indirect-call bytes changed"):
            verify.verify_facts(bytes(mutated), check_digest=False)

    def test_relative_relocation_mutation_is_rejected(self):
        mutated = bytearray(self.data)
        rela = next(s for s in verify.sections(self.data) if s["name"] == ".rela.dyn")
        changed = False
        for offset in range(rela["offset"], rela["offset"] + rela["size"], 24):
            where, info, addend = struct.unpack_from("<QQq", self.data, offset)
            if where == verify.SLOT and info & 0xFFFFFFFF == 8:
                struct.pack_into("<q", mutated, offset + 16, addend + 1)
                changed = True
                break
        self.assertTrue(changed, "expected relative relocation was not found")
        with self.assertRaisesRegex(verify.Reject, "relative relocation"):
            verify.verify_facts(bytes(mutated), check_digest=False)

    def test_argument_register_setup_mutation_is_rejected(self):
        mutated = bytearray(self.data)
        at = self._file_offset(0x593D2BC, 1)
        mutated[at] ^= 1
        with self.assertRaisesRegex(verify.Reject, "argument setup changed"):
            verify.verify_facts(bytes(mutated), check_digest=False)

    def test_wrong_target_digest_is_rejected(self):
        with self.assertRaisesRegex(verify.Reject, "target SHA-256 mismatch"):
            verify.verify_facts(self.data + b"x")

    def _file_offset(self, address, size):
        return next(section["offset"] + address - section["address"]
                    for section in verify.sections(self.data)
                    if section["type"] != 8 and section["address"] <= address
                    and address + size <= section["address"] + section["size"])


if __name__ == "__main__":
    unittest.main()
