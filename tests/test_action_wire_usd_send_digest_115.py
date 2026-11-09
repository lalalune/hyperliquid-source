import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import action_wire_usd_send_digest_115 as evidence
from elf_index import sections


class UsdSendDigestEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = ROOT / "artifacts/node/115/hl-node"
        cls.data = cls.target.read_bytes()

    def test_keccak_known_vectors(self):
        self.assertEqual(
            evidence.keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        self.assertEqual(
            evidence.keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )

    def test_synthetic_vector_is_stable_and_mutation_sensitive(self):
        result = evidence.make_vector()
        self.assertEqual(result["action"]["typehash"], "0x" + evidence.EXPECTED_USD_SEND_TYPEHASH)
        self.assertEqual(result["final"]["digest"], "0x5f4ad47ff6a6f14e393ab0605191f836f96905dc62bdeaec47cd7c0f99d4e10b")
        self.assertEqual(len(bytes.fromhex(result["final"]["preimage"][2:])), 66)
        self.assertNotEqual(
            result["final"]["digest"],
            evidence.make_vector({**result["values"], "amount": "1.26"})["final"]["digest"],
        )

    def test_target_static_chain(self):
        result = evidence.verify_target(self.data)
        self.assertEqual(result["target_sha256"], evidence.DIGEST)
        self.assertEqual(result["fde_count"], 135313)
        self.assertEqual(result["relative_relocations"]["0x64ea890"], "0x43d2b20")
        self.assertEqual(result["relative_relocations"]["0x64ea898"], "0x43d3130")

    def test_wrong_target_digest_is_rejected(self):
        changed = bytearray(self.data)
        changed[0] ^= 1
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            evidence.verify_target(bytes(changed))

    def test_wrong_indirect_call_slot_is_rejected(self):
        changed = bytearray(self.data)
        secs = sections(changed)
        _, off = evidence._section_for_va(changed, secs, 0x44339EE, 6)
        changed[off + 2] ^= 1
        with self.assertRaisesRegex(ValueError, "call 0x44339ee targets"):
            evidence.verify_target(bytes(changed), check_digest=False)

    def test_wrong_relocation_target_is_rejected(self):
        changed = bytearray(self.data)
        secs = sections(changed)
        rela = next(s for s in secs if s["name"] == ".rela.dyn")
        for pos in range(rela["offset"], rela["offset"] + rela["size"], 24):
            offset = int.from_bytes(changed[pos:pos + 8], "little")
            if offset == 0x64EA890:
                changed[pos + 16] ^= 1
                break
        else:
            self.fail("expected message-hash relocation was not found")
        with self.assertRaisesRegex(ValueError, "relocation 0x64ea890"):
            evidence.verify_target(bytes(changed), check_digest=False)

    def test_wrong_prefix_is_rejected(self):
        changed = bytearray(self.data)
        secs = sections(changed)
        _, off = evidence._section_for_va(changed, secs, evidence.PREFIX_VA, 2)
        changed[off] ^= 1
        with self.assertRaisesRegex(ValueError, "final EIP-712 prefix differs"):
            evidence.verify_target(bytes(changed), check_digest=False)


if __name__ == "__main__":
    unittest.main()
