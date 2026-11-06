"""Static target-bound evidence controls; never run or emulate captured code."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-007-node115-asset-registration-caller-name-rules'
spec = importlib.util.spec_from_file_location('asset_registration_caller', PACKET / 'collect.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)

# (virtual address, original byte): immediates, displacements and tag constants
# that carry a claim in README.md. Each is flipped privately and must be refused.
CLAIM_BYTES = [
    (0x38b4036, 0x10),  # imul rax,[rsp],0x510: front-vector element stride low byte
    (0x38b404b, 0x2),  # lea rbx,[rax+0x200]: state object offset in the boxed object
    (0x38b4342, 0x10),  # mov esi,0x710: boxed object size low byte
    (0x38b4343, 0x7),  # mov esi,0x710: boxed object size high byte
    (0x38b406a, 0xa2),  # cmp eax,0x1a2: Ok tag after the rule check
    (0x38b4003, 0x1),  # cmp rdx,1: indexed selector tag
    (0x38b428d, 0xa0),  # add rbp,0x1a0: map field offset
    (0x38b3fe7, 0x56),  # 0x156 word written before the unwrap-on-Err sites
    (0x447d785, 0xf),  # cmp rax,0x270f low byte
    (0x447d786, 0x27),  # cmp rax,0x270f high byte
    (0x447d78e, 0x55),  # tag 0x155 low byte
    (0x447d7ba, 0x1a),  # cross-margin message length 26
    (0x447d816, 0x1b),  # too-many-assets message length 27
    (0x447d8a4, 0x64),  # name length limit 100
    (0x447d8aa, 0x58),  # name-too-long tag 0x158
    (0x447d8db, 0x56),  # prefix-mismatch tag 0x156
    (0x447d919, 0x9),  # range value 9 in the length message
    (0x447d923, 0xa),  # suffix length upper bound 10 (exclusive)
    (0x447d9b0, 0x38),  # alphabet message length 56
    (0x447d7e5, 0xf0),  # message-error tag 0xf0
    (0x3f1097b, 0x20),  # mov edx,0x120 low byte
    (0x3f1097c, 0x1),  # mov edx,0x120 high byte
    (0x44e59f2, 0xa5),  # upper-case range base
    (0x44e59f5, 0xe6),  # upper-case range width
    (0x44e59fc, 0xc6),  # digit range base
    (0x44e59ff, 0xf6),  # digit range width
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
