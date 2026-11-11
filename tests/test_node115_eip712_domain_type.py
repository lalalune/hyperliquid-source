import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "research/work-items/RE-005-node115-eip712-domain-type/collect.py"
SPEC = importlib.util.spec_from_file_location("node115_domain_type_collect", MODULE_PATH)
COLLECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COLLECTOR)


class DomainTypeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.binary = ROOT / "artifacts/node/115/hl-node"
        self.data = self.binary.read_bytes()

    def test_target_bound_packet_reproduces(self):
        result = COLLECTOR.collect(self.binary)
        self.assertEqual(result["fde_extent"]["size"], 3523)
        self.assertEqual(result["rodata_literal"]["bytes"], "address verifyingContract")
        self.assertFalse(result["fde_extent"]["validated_function_boundary"])

    def test_wrong_target_digest_is_refused(self):
        data = bytearray(self.data)
        data[0] ^= 1
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "changed-elf"
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "unexpected target SHA-256"):
                COLLECTOR.collect(path)

    def test_code_anchor_corruption_is_refused(self):
        data = bytearray(self.data)
        offset = COLLECTOR.file_offset(data, 0x169EA54, 1, required_flags=4)
        data[offset] ^= 1
        with self.assertRaisesRegex(ValueError, "code-byte mismatch at 0x169ea54"):
            COLLECTOR.observed_bytes(data)

    def test_verifying_contract_literal_corruption_is_refused(self):
        data = bytearray(self.data)
        offset = COLLECTOR.file_offset(data, 0x47B7F9, 1)
        data[offset] ^= 1
        with self.assertRaisesRegex(ValueError, "verifyingContract data literal mismatch"):
            COLLECTOR.observed_bytes(data)


if __name__ == "__main__":
    unittest.main()
