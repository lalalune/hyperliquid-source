import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "research/work-items/RE-017-node115-vote-to-replay-root-provenance"))
import verify  # noqa: E402


class VoteToReplayRootProvenanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = verify.base.load_image()

    def test_selected_cross_path_anchors(self):
        verify.check_image(self.image)

    def test_tracker_field_is_joined_at_ingress_and_finalization(self):
        self.assertEqual(
            self.image.data[self.image.file_offset(0x294FEE1):
                            self.image.file_offset(0x294FEE1) + 7].hex(),
            "488db2503e0000",
        )
        self.assertEqual(
            self.image.data[self.image.file_offset(0x548BF2D):
                            self.image.file_offset(0x548BF2D) + 8].hex(),
            "498db424503e0000",
        )

    def test_rejects_mutated_tracker_handoff(self):
        data = bytearray(self.image.data)
        offset = self.image.file_offset(0x294FEE1)
        data[offset + 3] ^= 1
        mutant = verify.base.cpu.Image(bytes(data))
        with self.assertRaisesRegex(ValueError, "instruction bytes changed"):
            verify.check_image(mutant)

    def test_rejects_mutated_finalizer_call(self):
        data = bytearray(self.image.data)
        offset = self.image.file_offset(0x548BF4B)
        data[offset + 1] ^= 1
        mutant = verify.base.cpu.Image(bytes(data))
        with self.assertRaisesRegex(ValueError, "instruction bytes changed"):
            verify.check_image(mutant)


if __name__ == "__main__":
    unittest.main()
