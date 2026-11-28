import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import replay_timer_tree_pointer_115 as evidence


class ReplayTimerTreePointer115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = (ROOT / 'artifacts/node/115/hl-node').read_bytes()

    def test_target_identity_and_tree_context_flow(self):
        self.assertEqual(hashlib.sha256(self.target).hexdigest(), evidence.SHA)
        result = evidence.verify(self.target)
        self.assertEqual(len(result['context_flow']), 12)
        self.assertEqual(result['windows']['tree_callback']['start_va'], 0x51520f0)
        self.assertFalse(result['component_gate_changed'])

    def test_every_anchor_mutation_is_rejected(self):
        for va, encoded in evidence.ANCHORS.items():
            with self.subTest(va=hex(va)):
                changed = bytearray(self.target)
                spans = [s for s in evidence.sections(self.target) if s['type'] != 8
                         and s['address'] <= va
                         and va + len(bytes.fromhex(encoded)) <= s['address'] + s['size']]
                self.assertEqual(len(spans), 1)
                offset = spans[0]['offset'] + va - spans[0]['address']
                changed[offset] ^= 1
                with self.assertRaises(ValueError):
                    evidence.verify(changed, authenticate=False)


if __name__ == '__main__':
    unittest.main()
