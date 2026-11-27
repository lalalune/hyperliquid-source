import sys
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "research/work-items/RE-004-node115-fee-validator-route-115"))
import verify  # noqa: E402


class FeeValidatorRoute115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / "artifacts/node/115/hl-node").read_bytes()

    def test_validator_route_and_scope_limits(self):
        result = verify.verify_facts(self.data)
        self.assertEqual(result["direct_validator_call"]["callsite"], "0x3c190fb")
        self.assertEqual(result["direct_validator_call"]["raw_direct_call_xrefs"], 1)
        self.assertEqual(len(result["validator_caller_registration"]["indirect_calls"]), 3)
        self.assertFalse(result["maker_taker_labels_recovered"])
        self.assertFalse(result["trade_fee_to_ledger_composition_proven"])

    def test_call_displacement_mutation_is_rejected(self):
        mutated = bytearray(self.data)
        at = self._file_offset(verify.DIRECT_CALL + 1, 1)
        mutated[at] ^= 1
        with self.assertRaisesRegex(verify.Reject, "direct validator call bytes"):
            verify.verify_facts(bytes(mutated), check_digest=False)

    def test_slot_relocation_mutation_is_rejected(self):
        mutated = bytearray(self.data)
        sections = verify.sections(self.data)
        rela = next(section for section in sections if section["name"] == ".rela.dyn")
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

    def test_result_status_mutation_is_rejected(self):
        mutated = bytearray(self.data)
        at = self._file_offset(0x3C1912E + 3, 1)
        mutated[at] ^= 1
        with self.assertRaisesRegex(verify.Reject, "status/result anchor"):
            verify.verify_facts(bytes(mutated), check_digest=False)

    def test_validator_input_size_mutation_is_rejected(self):
        mutated = bytearray(self.data)
        at = self._file_offset(0x3C190EB, 1)
        mutated[at] ^= 1
        with self.assertRaisesRegex(verify.Reject, "validator input setup"):
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
