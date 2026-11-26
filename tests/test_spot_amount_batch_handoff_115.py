import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "spot_amount_batch_handoff_115", ROOT / "research" / "work-items" / "RE-004-node115-spot-amount-batch-handoff" / "verify.py"
)
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


class SpotAmountBatchHandoffTests(unittest.TestCase):
    def test_pinned_static_handoff_and_mutation_controls(self):
        result = tool.run()
        self.assertEqual(result["fdes"], 7)
        self.assertEqual(result["instruction_witnesses"], 25)
        self.assertEqual(result["direct_call_edges"], 5)
        self.assertEqual(result["witness_mutations_rejected"], 25)
        self.assertFalse(result["captured_binary_executed"])

    def test_wrong_target_digest_is_refused(self):
        data = bytearray(tool.TARGET.read_bytes())
        data[0] ^= 1
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            tool._verify_evidence(data)


if __name__ == "__main__":
    unittest.main()
