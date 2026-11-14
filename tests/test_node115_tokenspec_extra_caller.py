"""Target-bound static proof and corruption controls; no captured execution."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT/"research/work-items/RE-001-node115-tokenspec-extra-caller"
spec = importlib.util.spec_from_file_location("tokenspec_caller", PACKET/"verify_target.py")
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

class CallerProof(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pins = json.loads((PACKET/"discovery.json").read_text())
        cls.window = bytes.fromhex(cls.pins["excerpt"]["raw_hex"])
        cls.base = int(cls.pins["excerpt"]["start"], 16)

    def test_real_target_replay(self):
        result = helper.verify((ROOT/"artifacts/node/115/hl-node").read_bytes(), self.pins)
        self.assertEqual(result["input"], "incoming RSI + 0x30 via R14")
        self.assertEqual(result["writer"], "0x3c453f0")

    def test_digest_rejects_before_native_tools(self):
        with self.assertRaisesRegex(ValueError, "target digest"):
            helper.verify(b"not the target", self.pins, True, Path("never-executed"))

    def test_fde_pin_corruption(self):
        pins = json.loads(json.dumps(self.pins))
        pins["caller_fde"]["fde_record_hex"] = "00" + pins["caller_fde"]["fde_record_hex"][2:]
        with self.assertRaisesRegex(ValueError, "FDE record"):
            helper.verify((ROOT/"artifacts/node/115/hl-node").read_bytes(), pins)

    def test_each_semantic_instruction_byte_flip(self):
        # These controls call the small fragment decoder, not the digest-first CLI.
        ranges = [(0x3c4429e, 6), (0x3c443ed, 10), (0x3c443f7, 5),
                  (0x3c443fc, 10), (0x3c443cf, 12), (0x3c443c8, 7)]
        checked = 0
        for va, size in ranges:
            for i in range(va-self.base, va-self.base+size):
                for bit in range(8):
                    corrupt = bytearray(self.window)
                    corrupt[i] ^= 1 << bit
                    with self.subTest(offset=i, bit=bit):
                        with self.assertRaises(ValueError):
                            helper.facts(corrupt, self.base, b"spec")
                    checked += 1
        self.assertGreater(checked, 0)

    def test_literal_corruption(self):
        with self.assertRaisesRegex(ValueError, "field name data"):
            helper.facts(self.window, self.base, b"spEc")

if __name__ == "__main__":
    unittest.main()
