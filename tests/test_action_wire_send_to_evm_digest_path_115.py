import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import action_wire_send_to_evm_digest_path_115 as packet  # noqa: E402


class SendToEvmDigestPathTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = packet.load_image()

    def test_dispatch_to_builder_call_chain(self):
        entry, target = packet.check_image(self.image)
        self.assertEqual(entry, 0x79B24C)
        self.assertEqual(target, 0x36C3696)

    def test_changed_dispatch_table_entry_is_rejected(self):
        data = bytearray(self.image.data)
        offset = self.image.offset(0x79B24C, 4)
        data[offset] ^= 1
        with self.assertRaisesRegex(packet.EvidenceError, "table target mismatch"):
            packet.check_image(packet.Image(bytes(data)))

    def test_changed_dynamic_callback_site_is_rejected(self):
        data = bytearray(self.image.data)
        offset = self.image.offset(0x442D192, 1)
        data[offset] ^= 1
        with self.assertRaisesRegex(packet.EvidenceError, "instruction bytes changed"):
            packet.check_image(packet.Image(bytes(data)))

    def test_changed_signing_wrapper_call_is_rejected(self):
        data = bytearray(self.image.data)
        offset = self.image.offset(0x46E6D4C, 1)
        data[offset] ^= 1
        with self.assertRaisesRegex(packet.EvidenceError, "instruction bytes changed"):
            packet.check_image(packet.Image(bytes(data)))

    def test_changed_relocated_builder_target_is_rejected(self):
        data = bytearray(self.image.data)
        rela = self.image.named[".rela.dyn"]
        found = False
        for at in range(rela["offset"], rela["offset"] + rela["size"], 24):
            slot = int.from_bytes(data[at:at + 8], "little")
            if slot == 0x64EA980:
                data[at + 16] ^= 1
                found = True
                break
        self.assertTrue(found)
        with self.assertRaisesRegex(packet.EvidenceError, "relocated call mismatch"):
            packet.check_image(packet.Image(bytes(data)))


if __name__ == "__main__":
    unittest.main()
