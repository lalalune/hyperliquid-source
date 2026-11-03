import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

import sibling_search_static as packet

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
PACKET_DIR = ROOT / 'research' / 'work-items' / 'RE-006-node115-sibling-search'
VA_TO_OFF = 0x1000


def flip(data, va):
    mutated = bytearray(data)
    mutated[va - VA_TO_OFF] ^= 0xFF
    return bytes(mutated)


class SiblingSearchPacketTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = ARTIFACT.read_bytes()

    def test_retained_packet_regenerates_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet.generate(self.data, tmp)
            for name in ('records.json', 'frames.txt',
                         'sibling_search_full_body_35bf460_35bf4f2_objdump.txt'):
                self.assertEqual((Path(tmp) / name).read_bytes(),
                                 (PACKET_DIR / name).read_bytes(), name)

    def test_generate_authenticates_the_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(packet.PacketError, 'artifact SHA-256 mismatch'):
                packet.generate(flip(self.data, 0x35bf460), tmp)

    def test_counters(self):
        records = packet.analyze(self.data)
        counters = records['counters']
        self.assertEqual(counters, packet.EXPECTED)
        self.assertEqual(counters['call_sites'], 99)
        self.assertEqual(counters['node_position_sites'], 60)
        self.assertEqual(counters['height_consumed_reads'], 0)
        self.assertEqual(counters['height_vector_copy_reads'], 38)
        self.assertEqual(counters['height_other_phase_reads'], 99)

    def test_sibling_body_counterfactual(self):
        with self.assertRaisesRegex(packet.PacketError,
                                    'sibling body differs from its pinned digest'):
            packet.analyze(flip(self.data, 0x35bf480))

    def test_caller_digest_counterfactual(self):
        with self.assertRaisesRegex(packet.PacketError,
                                    'caller 0x421b430 differs from its pinned digest'):
            packet.analyze(flip(self.data, 0x421b460))

    def test_call_site_byte_counterfactual(self):
        # Flipping the E8 opcode at the 0x2a89910 join site breaks the
        # digest of its caller, which is checked before the branch census.
        with self.assertRaisesRegex(packet.PacketError,
                                    'caller 0x2a89500 differs from its pinned digest'):
            packet.analyze(flip(self.data, 0x2a89910))

    def test_height_read_counterfactual(self):
        # 0x2a40f69 reads the height slot of unit 0x2a40cc0|0x20 in an FP phase;
        # flipping a byte in that caller breaks its pinned boundary digest.
        with self.assertRaisesRegex(packet.PacketError,
                                    'caller 0x2a40cc0 differs from its pinned digest'):
            packet.analyze(flip(self.data, 0x2a40f69))

    def test_join_sites_are_the_retained_three(self):
        joins = sorted(site for site, info in packet.SITES.items() if info['join'])
        self.assertEqual(joins, [0x2a89910, 0x55a0bf0, 0x55a16f0])


if __name__ == '__main__':
    unittest.main()
