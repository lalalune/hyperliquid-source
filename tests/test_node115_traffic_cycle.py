"""Static target-bound evidence controls; never run or emulate captured code."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-012-node115-traffic-cycle'
spec = importlib.util.spec_from_file_location('node115_traffic_cycle', PACKET / 'collect.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class StaticPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()

    def test_original_operand_and_branch_anchors(self):
        expected = json.loads((PACKET / 'records.json').read_text())['facts']
        self.assertEqual(collector.anchors(self.data), expected)

    def test_every_claim_anchor_rejects_private_byte_corruption(self):
        # Mutation is confined to a Python bytearray. Neither the original nor
        # modified instruction streams are evaluated, emulated or executed.
        mutated = bytearray(self.data)
        for address, raw in collector.CONFIG['anchors'].items():
            with self.subTest(anchor=address):
                offset, _ = collector.read(self.data, int(address, 16), len(bytes.fromhex(raw)))
                mutated[offset] ^= 1
                with self.assertRaisesRegex(ValueError, 'changed traffic-cycle anchor'):
                    collector.anchors(mutated)
                mutated[offset] ^= 1

    def test_wrong_identity_fails_before_native_tools_and_output(self):
        mutated = bytearray(self.data)
        mutated[-1] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'not-created'
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                collector.collect(mutated, output)
            self.assertFalse(output.exists())

    def test_complete_native_exports_regenerate_exactly(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            actual = collector.collect(self.data, output)
            self.assertEqual(actual, json.loads((PACKET / 'records.json').read_text()))
            for name in ['frames.txt', 'relocations.txt', 'records.json',
                         *[p.name for p in PACKET.glob('*.objdump.txt')]]:
                with self.subTest(file=name):
                    self.assertEqual((output / name).read_bytes(), (PACKET / name).read_bytes())


if __name__ == '__main__':
    unittest.main()

