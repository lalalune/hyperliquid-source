"""Check the production cycle against actual captured bytes; no future mock."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-production-wait-cycle-94'
spec = importlib.util.spec_from_file_location('production_wait_packet', PACKET / 'verify.py')
packet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packet)


class ProductionWaitEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = packet.TARGET.read_bytes()

    def test_regenerate_from_authenticated_capture(self):
        result = packet.build(self.data)
        self.assertEqual(packet.encoded(result), (PACKET / 'records.json').read_text())
        self.assertEqual(result['primary_bytes'], 1497)
        self.assertEqual(result['support_bytes'], 123)

    def test_wrong_target_is_rejected_before_observation(self):
        changed = bytearray(self.data)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'wrong node94 SHA-256'):
            packet.build(changed)

    def test_instruction_state_table_fde_and_symbol_corruptions_below_digest_gate(self):
        result = packet.controls(self.data)
        self.assertEqual(packet.encoded(result), (PACKET / 'controls.json').read_text())
        self.assertEqual(len(result['rejected']), 58)
        self.assertFalse(result['survived'])

    def test_retained_exports_reject_change_outside_semantic_obligations(self):
        # The entry push lies outside the semantic obligations. Export equality
        # must reject it even when whole-file and body hashes are bypassed.
        image = packet.Image(self.data)
        changed = bytearray(self.data)
        changed[image.off(0x1487370)] ^= 1
        with self.assertRaisesRegex(ValueError, 'export bytes'):
            packet.observe(changed, body_hashes=False)


if __name__ == '__main__':
    unittest.main()
