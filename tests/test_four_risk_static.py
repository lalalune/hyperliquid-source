"""Static target-bound evidence controls; never run or emulate captured code."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-007-node115-position-margin-paths'
spec = importlib.util.spec_from_file_location('four_risk', PACKET / 'collect.py')
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
                with self.assertRaisesRegex(ValueError, 'changed native anchor'):
                    collector.anchors(mutated)
                mutated[offset] ^= 1

    def test_actual_semantic_sites_reject_counterfactuals(self):
        for address, value in [(71874577, 137), (71874594, 129), (71874676, 67), (71874774, 78), (71874656, 2), (59463062, 41), (59462642, 77), (59462652, 129), (59462689, 9), (62830851, 208)]:
            offset, old = collector.read(self.data, address, 1)
            changed = bytearray(self.data)
            changed[offset] = value
            with self.subTest(address=hex(address)):
                with self.assertRaisesRegex(ValueError, 'changed native anchor'):
                    collector.anchors(changed)

    def test_actual_dispatch_table_corruption_rejected(self):
        table = collector.CONFIG['tables'][0]
        offset, _ = collector.read(self.data, int(table['va'], 16), 1)
        changed = bytearray(self.data)
        changed[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'changed dispatch data'):
            collector.anchors(changed)

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
