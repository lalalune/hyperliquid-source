"""Bind the gossip cache findings to the captured node, not to a behavioral mock."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-gossip-cache-retention-94'
spec = importlib.util.spec_from_file_location('gossip_cache_packet', PACKET / 'verify.py')
packet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packet)


class GossipCacheEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = packet.TARGET.read_bytes()

    def test_regenerate_from_authenticated_capture(self):
        actual = packet.build(self.data)
        self.assertEqual(packet.encoded(actual), (PACKET / 'records.json').read_text())
        self.assertEqual(actual['primary_bytes'], 1730)
        self.assertEqual(sum(r['instructions'] for r in actual['primary_bodies']), 400)

    def test_wrong_target_is_rejected_before_observation(self):
        changed = bytearray(self.data)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'wrong node94 SHA-256'):
            packet.build(changed)

    def test_instruction_fde_and_relocation_corruptions_below_digest_gate(self):
        result = packet.controls(self.data)
        self.assertEqual(packet.encoded(result), (PACKET / 'controls.json').read_text())
        self.assertEqual(len(result['rejected']), 33)
        self.assertFalse(result['survived'])

    def test_retained_exports_reject_unpinned_instruction_change(self):
        # A NOP lies outside the semantic obligations. This check exercises the
        # full export byte comparison independently of the whole/body hashes.
        image = packet.Image(self.data)
        changed = bytearray(self.data)
        changed[image.off(0x473ce98)] ^= 1
        with self.assertRaisesRegex(ValueError, 'export bytes'):
            packet.observe(changed, body_hashes=False)


if __name__ == '__main__':
    unittest.main()
