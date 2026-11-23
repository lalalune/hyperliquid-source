import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import action_wire_variant_dispatch_crosswalk_115 as packet  # noqa: E402


class ActionWireVariantDispatchCrosswalkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = packet.load_image()
        cls.variants = packet.read_variants()

    def test_all_variants_join_to_unique_dispatch_arms(self):
        table_base, rows = packet.check_image(self.image, self.variants)
        self.assertEqual(table_base, 0x79B120)
        self.assertEqual(len(rows), 92)
        self.assertEqual(len({row["target_va"] for row in rows}), 92)
        self.assertEqual(rows[75]["rust_variant"], "SendToEvmWithData")
        self.assertEqual(rows[75]["tag_rule"], "0xd1")
        self.assertEqual(rows[75]["target_va"], 0x36C3696)

    def test_below_base_vote_global_rule_uses_default_index(self):
        _, rows = packet.check_image(self.image, self.variants)
        vote = rows[20]
        self.assertEqual(vote["rust_variant"], "VoteGlobal")
        self.assertEqual(vote["tag_rule"], "<0x86")
        self.assertEqual(vote["dispatch_rule"], "tag < 0x86 -> default 20")

    def test_tag_index_mutation_is_rejected(self):
        mutated = [dict(row) for row in self.variants]
        mutated[75]["tag_word"] = "0xd0"
        with self.assertRaisesRegex(packet.EvidenceError, "tag/index mismatch"):
            packet.check_image(self.image, mutated)

    def test_special_tag_rule_moved_to_other_variant_is_rejected(self):
        mutated = [dict(row) for row in self.variants]
        mutated[20]["rust_variant"] = "OtherVariant"
        with self.assertRaisesRegex(packet.EvidenceError, "VoteGlobal default row"):
            packet.check_image(self.image, mutated)

    def test_changed_table_entry_is_rejected(self):
        data = bytearray(self.image.data)
        offset = self.image.offset(packet.TABLE_BASE + 20 * 4, 4)
        first_entry = self.image.offset(packet.TABLE_BASE, 4)
        data[offset:offset + 4] = data[first_entry:first_entry + 4]
        with self.assertRaisesRegex(packet.EvidenceError, "targets are not unique"):
            packet.check_image(packet.Image(bytes(data)), self.variants)

    def test_wrong_binary_digest_is_rejected(self):
        data = bytearray(self.image.data)
        offset = self.image.offset(packet.DISPATCH_FDE[0], 1)
        data[offset] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "hl-node"
            candidate.write_bytes(data)
            with self.assertRaisesRegex(packet.EvidenceError, "target SHA-256 mismatch"):
                packet.load_image(candidate)

    def test_manifest_reproducible(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            packet.write_packet(out)
            first = {path.name: path.read_bytes() for path in out.iterdir()}
            packet.write_packet(out)
            second = {path.name: path.read_bytes() for path in out.iterdir()}
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
