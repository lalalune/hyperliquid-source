import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "research/work-items/RE-015-node115-hl-node-xrefs/verify.py"
SPEC = importlib.util.spec_from_file_location("hl_node_xrefs_verify", SCRIPT)
VERIFY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VERIFY)


class HlNodeLiteralReferences(unittest.TestCase):
    def test_target_occurrences_and_direct_references(self):
        self.assertEqual(VERIFY.analyze(), json.loads(VERIFY.OUT.read_text()))


if __name__ == "__main__":
    unittest.main()
