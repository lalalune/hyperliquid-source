"""Target-bound regeneration and corruption controls for the Ctx packet."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-009-ctx-encoder-115"

def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, PACKET / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

extract = module("ctx_encoder_extract", "extract.py")
qualifier = module("ctx_encoder_qualify", "qualify.py")

class ContextEncoderEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contexts = json.loads((PACKET / "contexts.json").read_text(encoding="utf-8"))
        cls.witness = json.loads((PACKET / "format-descriptor-witness.json").read_text(encoding="utf-8"))

    def test_entire_selected_contexts_regenerate_from_node115(self):
        target = ROOT / "artifacts/node/115/hl-node"
        if not target.is_file() or target.stat().st_size != 105896032:
            self.skipTest("materialized Node115 required")
        actual = extract.analyze(target)
        expected = copy.deepcopy(self.contexts)
        # Record the actual provider version, not an instruction coverage metric.
        actual.pop("capstone")
        expected.pop("capstone")
        self.assertEqual(actual, expected)

    def test_calendar_and_integer_proofs_regenerate(self):
        expected = json.loads((PACKET / "qualification.json").read_text(encoding="utf-8"))
        self.assertEqual(qualifier.qualify(self.contexts, self.witness), expected)

    def test_changed_year_shift_rejected_even_with_updated_body_hash(self):
        data = copy.deepcopy(self.contexts)
        frame = next(f for f in data["records"] if f["start"] == "0x1628bc0")
        row = next(r for r in frame["instructions"] if r["va"] == "0x1628bd3")
        row["bytes"] = "41c1fd0c"
        import hashlib
        frame["sha256"] = hashlib.sha256(bytes.fromhex(
            "".join(r["bytes"] for r in frame["instructions"]))).hexdigest()
        with self.assertRaises(AssertionError):
            qualifier.qualify(data, self.witness)

    def test_changed_calendar_cell_rejected(self):
        data = copy.deepcopy(self.contexts)
        table = next(d for d in data["data"] if d["label"] == "ordinal-month-delta")
        raw = bytearray.fromhex(table["rawHex"])
        raw[120] ^= 1
        table["rawHex"] = raw.hex()
        with self.assertRaises(AssertionError):
            qualifier.qualify(data, self.witness)

    def test_changed_decimal_pair_rejected(self):
        data = copy.deepcopy(self.contexts)
        table = next(d for d in data["data"] if d["label"] == "decimal-digit-pairs")
        raw = bytearray.fromhex(table["rawHex"])
        raw[17] ^= 1
        table["rawHex"] = raw.hex()
        with self.assertRaises(AssertionError):
            qualifier.qualify(data, self.witness)

    def test_changed_nested_key_reference_rejected(self):
        data = copy.deepcopy(self.contexts)
        frame = next(f for f in data["records"] if f["start"] == "0x4e0bdb0")
        row = next(r for r in frame["instructions"] if r["va"] == "0x4e0be4e")
        row["ripReferences"][0]["raw32"] = "00" * 32
        with self.assertRaises(AssertionError):
            qualifier.qualify(data, self.witness)

if __name__ == "__main__":
    unittest.main()
