"""Target-bound static proof and corruption controls; no captured execution."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT/"research/work-items/RE-001-node115-tokenspec-second-caller"
spec = importlib.util.spec_from_file_location("tokenspec_second_caller", PACKET/"verify_target.py")
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
        self.assertEqual(result["input"], "incoming RSI + 0x28 via R14")
        self.assertEqual(result["writer"], "0x3c453f0")
        self.assertEqual(result["writer_call"], "0x41b3083")

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
        ranges = [(0x41b3000, 9), (0x41b3009, 4), (0x41b300d, 3), (0x41b3010, 3),
                  (0x41b3013, 3), (0x41b3016, 10), (0x41b3020, 2), (0x41b3022, 3),
                  (0x41b3025, 2), (0x41b3027, 4), (0x41b302b, 3), (0x41b302e, 3),
                  (0x41b3031, 5), (0x41b3036, 4), (0x41b303a, 2), (0x41b303c, 4),
                  (0x41b3040, 3), (0x41b3043, 2), (0x41b3045, 3), (0x41b3048, 3),
                  (0x41b304b, 3), (0x41b304e, 5), (0x41b3053, 4), (0x41b3057, 2),
                  (0x41b3059, 4), (0x41b305d, 3), (0x41b3060, 6), (0x41b3066, 2),
                  (0x41b3068, 4), (0x41b306c, 5), (0x41b3071, 3), (0x41b3074, 3),
                  (0x41b3077, 2), (0x41b3079, 4), (0x41b307d, 3), (0x41b3080, 3),
                  (0x41b3083, 5), (0x41b3088, 2), (0x41b308a, 4), (0x41b308e, 4),
                  (0x41b3092, 3), (0x41b3095, 2), (0x41b3097, 3), (0x41b309a, 4),
                  (0x41b309e, 4), (0x41b30a2, 3), (0x41b30a5, 4), (0x41b30a9, 10),
                  (0x41b30b3, 5), (0x41b30b8, 3), (0x41b30bb, 3), (0x41b30be, 5),
                  (0x41b30c3, 5), (0x41b30c8, 2), (0x41b30ca, 4), (0x41b30ce, 3),
                  (0x41b30d1, 2), (0x41b30d3, 2), (0x41b30d5, 4), (0x41b30d9, 3),
                  (0x41b30dc, 2), (0x41b30de, 5), (0x41b30e3, 4), (0x41b30e7, 5),
                  (0x41b30ec, 3), (0x41b30ef, 2), (0x41b30f1, 7), (0x41b30f8, 6)]
        checked = 0
        for va, size in ranges:
            for i in range(va-self.base, va-self.base+size):
                for bit in range(8):
                    corrupt = bytearray(self.window)
                    corrupt[i] ^= 1 << bit
                    with self.subTest(offset=i, bit=bit):
                        with self.assertRaises(ValueError):
                            helper.facts(corrupt, self.base)
                    checked += 1
        self.assertGreater(checked, 0)

if __name__ == "__main__":
    unittest.main()
