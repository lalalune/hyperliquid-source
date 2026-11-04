"""Static target-bound evidence controls; never run or emulate captured code."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-004-node115-quantity-bookkeeping'
spec = importlib.util.spec_from_file_location('node115_quantity_bookkeeping', PACKET / 'collect.py')
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
                with self.assertRaisesRegex(ValueError, 'changed arithmetic anchor'):
                    collector.anchors(mutated)
                mutated[offset] ^= 1

    def test_actual_counter_saturation_store_and_clear_controls(self):
        # Change the actual unsigned saturation condition, intermediate store,
        # optional gate, signed overflow branch, notification predicate and
        # caller zeroing. These are structural controls, not target execution.
        for address, replacement in [(0x4206f98, 0x74), (0x4206fb7, 0x75),
                                     (0x4206fcd, 0x44), (0x4206fd5, 0x75),
                                     (0x420700e, 0x71), (0x4207010, 0x90),
                                     (0x420702c, 0x71), (0x420703f, 0x94),
                                     (0x4205ef6, 0x85), (0x4205f28, 0x01)]:
            offset, old = collector.read(self.data, address, 1)
            self.assertNotEqual(old[0], replacement)
            changed = bytearray(self.data)
            changed[offset] = replacement
            with self.subTest(address=hex(address)):
                with self.assertRaisesRegex(ValueError, 'changed arithmetic anchor'):
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
