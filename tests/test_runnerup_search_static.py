import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

import runnerup_search_static as packet

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
PACKET_DIR = ROOT / 'research' / 'work-items' / 'RE-006-node115-runnerup-search'
VA_TO_OFF = 0x1000


def flip(data, va):
    mutated = bytearray(data)
    mutated[va - VA_TO_OFF] ^= 0xFF
    return bytes(mutated)


class RunnerupSearchPacketTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = ARTIFACT.read_bytes()

    def test_retained_packet_regenerates_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet.generate(self.data, tmp)
            for name in ('records.json', 'frames.txt',
                         'runnerup_search_full_body_35be560_35be5f2_objdump.txt'):
                self.assertEqual((Path(tmp) / name).read_bytes(),
                                 (PACKET_DIR / name).read_bytes(), name)

    def test_generate_authenticates_the_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(packet.PacketError, 'artifact SHA-256 mismatch'):
                packet.generate(flip(self.data, 0x35be560), tmp)

    def test_counters(self):
        records = packet.analyze(self.data)
        counters = records['counters']
        self.assertEqual(counters, packet.EXPECTED)
        self.assertEqual(counters['call_sites'], 50)
        self.assertEqual(counters['node_position_sites'], 49)
        self.assertEqual(counters['height_consumed_reads'], 0)
        self.assertEqual(counters['height_vector_copy_reads'], 28)
        self.assertEqual(counters['height_other_phase_reads'], 53)

    def test_runnerup_body_counterfactual(self):
        with self.assertRaisesRegex(packet.PacketError,
                                    'runnerup body differs from its pinned digest'):
            packet.analyze(flip(self.data, 0x35be580))

    def test_caller_digest_counterfactual(self):
        with self.assertRaisesRegex(packet.PacketError,
                                    'caller 0x446bcd0 differs from its pinned digest'):
            packet.analyze(flip(self.data, 0x446bd00))

    def test_call_site_byte_counterfactual(self):
        # Flipping the E8 opcode at the 0x23fe63e site breaks the digest
        # of its caller, which is checked before the branch census.
        with self.assertRaisesRegex(packet.PacketError,
                                    'caller 0x23fdb60 differs from its pinned digest'):
            packet.analyze(flip(self.data, 0x23fe63e))

    def test_height_read_counterfactual(self):
        # 0x4472574 reads the height slot of unit 0x4472010|0x30 in an
        # abs-value phase; flipping a byte in that caller breaks its
        # pinned boundary digest.
        with self.assertRaisesRegex(packet.PacketError,
                                    'caller 0x4472010 differs from its pinned digest'):
            packet.analyze(flip(self.data, 0x4472574))

    def test_presentations_and_the_one_flag_only_site(self):
        presentations = Counter(i['presentation'] for i in packet.SITES.values())
        self.assertEqual(presentations, {'handle_register': 43, 'handle_stack': 4,
                                         'register_pair': 2, 'split_handle': 1})
        record_forms = Counter(i['record_form'] for i in packet.SITES.values())
        self.assertEqual(record_forms, {'lea': 48, 'register': 2})
        flag_only = sorted(s for s, i in packet.SITES.items() if i['class'] == 'flag_only')
        self.assertEqual(flag_only, [0x44781ad])


if __name__ == '__main__':
    unittest.main()
