import sys
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "research/work-items/RE-004-node115-fee-handler-dispatch-115"))

import verify  # noqa: E402


class FeeHandlerDispatch115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / "artifacts/node/115/hl-node").read_bytes()

    def test_pinned_two_handler_edges(self):
        result = verify.verify_facts(self.data)
        self.assertEqual(result["callers"]["fee_handler"]["relocated_callee"], "0x44896f0")
        self.assertEqual(result["callers"]["spot_fee_handler"]["relocated_callee"], "0x3c10000")
        self.assertFalse(result["semantic_labels_recovered"])

    def test_call_argument_mutation_is_rejected(self):
        item = verify.CALLERS["fee_handler"]["arguments"][2]
        offset = self._file_offset(item[0], len(item[1]))
        mutated = bytearray(self.data)
        mutated[offset] ^= 1
        with self.assertRaisesRegex(verify.Reject, "argument setup changed"):
            verify.verify_facts(bytes(mutated), check_digest=False)

    def test_indirect_slot_relocation_mutation_is_rejected(self):
        slot = verify.CALLERS["spot_fee_handler"]["slot"]
        reloc_section = next(s for s in verify.sections(self.data) if s["name"] == ".rela.dyn")
        mutated = bytearray(self.data)
        start, end = reloc_section["offset"], reloc_section["offset"] + reloc_section["size"]
        for at in range(start, end, 24):
            where, info, addend = struct.unpack_from("<QQq", self.data, at)
            if where == slot and info & 0xFFFFFFFF == 8:
                struct.pack_into("<q", mutated, at + 16, addend + 1)
                break
        else:
            self.fail("expected RELATIVE relocation not found")
        with self.assertRaisesRegex(verify.Reject, "slot relocation"):
            verify.verify_facts(bytes(mutated), check_digest=False)

    def test_wrong_target_digest_is_rejected(self):
        with self.assertRaisesRegex(verify.Reject, "SHA-256 mismatch"):
            verify.verify_facts(self.data + b"x")

    def _file_offset(self, address, size):
        return next(s["offset"] + address - s["address"] for s in verify.sections(self.data)
                    if s["type"] != 8 and s["address"] <= address
                    and address + size <= s["address"] + s["size"])


if __name__ == "__main__":
    unittest.main()
