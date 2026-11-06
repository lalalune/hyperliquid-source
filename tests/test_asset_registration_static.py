"""Static target-bound evidence controls; never run or emulate captured code."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-007-node115-asset-registration-path'
spec = importlib.util.spec_from_file_location('asset_registration', PACKET / 'collect.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)

# (virtual address, original byte): immediates, displacements and tag constants
# that carry a claim in README.md. Each is flipped privately and must be refused.
CLAIM_BYTES = [
    (63185242, 101),   # 0x3c4215a: first string length limit, cmp rbp,0x65
    (63185288, 15),    # 0x3c42188: index count limit low byte, cmp rcx,0x270f
    (63185289, 39),    # 0x3c42189: index count limit high byte
    (63185486, 6),     # 0x3c4224e: byte parameter limit
    (63185518, 50),    # 0x3c4226e: u32 parameter threshold 0x32
    (63185542, 101),   # 0x3c42286: second string length limit
    (71745427, 162),   # 0x446bf93: Ok tag compare 0x1a2
    (71745752, 16),    # 0x446c0d8: modulus 10000 low byte
    (71745753, 39),    # 0x446c0d9: modulus 10000 high byte
    (63185453, 62),    # 0x3c4222d: duplicate-name tag 0x3e
    (63185498, 65),    # 0x3c4225a: byte-parameter tag 0x41
    (63186388, 82),    # 0x3c425d4: rollback tag 0x152
    (71745989, 162),   # 0x446c1c5: Ok tag store 0x1a2
    (71745922, 1),     # 0x446c182: flag compare value 1
    (71745823, 5),     # 0x446c11f: 96-byte stride, shl 5 after lea r12*3
    (64056135, 5),     # 0x3d16b47: 32-byte stride, shl 5
    (71745456, 120),   # 0x446bfb0: state field +0x378 niche test displacement
    (71745773, 88),    # 0x446c0ed: state field +0x158 displacement
]


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
            size = len(bytes.fromhex(raw))
            for position in (0, size // 2, size - 1):
                with self.subTest(anchor=address, position=position):
                    offset, _ = collector.read(self.data, int(address, 16) + position, 1)
                    mutated[offset] ^= 1
                    with self.assertRaisesRegex(ValueError, 'changed native anchor'):
                        collector.anchors(mutated)
                    mutated[offset] ^= 1

    def test_claim_bytes_are_the_documented_originals_and_reject_counterfactuals(self):
        for address, original in CLAIM_BYTES:
            offset, old = collector.read(self.data, address, 1)
            self.assertEqual(old[0], original, hex(address))
            changed = bytearray(self.data)
            changed[offset] = (original + 1) & 0xff
            with self.subTest(address=hex(address)):
                with self.assertRaisesRegex(ValueError, 'changed native anchor'):
                    collector.anchors(changed)

    def test_claim_bytes_lie_inside_an_anchor(self):
        spans = [(int(a, 16), int(a, 16) + len(bytes.fromhex(r)))
                 for a, r in collector.CONFIG['anchors'].items()]
        for address, _ in CLAIM_BYTES:
            with self.subTest(address=hex(address)):
                self.assertTrue(any(lo <= address < hi for lo, hi in spans))

    def test_every_window_is_a_complete_unwind_extent_and_unexecuted(self):
        record = json.loads((PACKET / 'records.json').read_text())
        self.assertEqual([(w['start'], w['end']) for w in record['windows']],
                         [tuple(r) for r in collector.CONFIG['ranges']])
        self.assertEqual(record['implementation_bytes'], 0)
        self.assertEqual(record['requested_gates'], [])

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
