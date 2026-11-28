"""Selected begin-store width and stage controls on synthetic fixture images."""

from hashlib import sha256
from pathlib import Path
from struct import pack_into, unpack_from
import subprocess
import sys
import tempfile
import unittest

from apply_begin import U64_MAX, apply

H = 1196590000
LAYOUT_CASES = (("compact", 0x42C8, 0xE08, 0xF28),
                ("expanded", 0x4E38, 0x1978, 0x1A98))


def state(size, height):
    image = bytearray(b"\xa5" * size)
    pack_into("<Q", image, 0x28, height)
    pack_into("<Q", image, 0x30, 4800)
    return image


def run(image, layout, height, stage, new_round=None):
    return apply(image, sha256(image).hexdigest(), layout, height, stage, new_round)


class ReplayBeginStoreTests(unittest.TestCase):
    def test_round_mirror_and_height_writes_in_both_layouts(self):
        for layout, size, offset_one, offset_two in LAYOUT_CASES:
            image = state(size, H)
            wanted = image.copy()
            for offset, value in ((0x28, H + 1), (0, 0), (0x30, 4813),
                                  (offset_one, 4813), (offset_two, 4813)):
                wanted[offset:offset + 8] = value.to_bytes(8, "little")
            self.assertEqual(run(image, layout, H, "after-clock", 4813), wanted)
            self.assertEqual(image[8:16], b"\xa5" * 8)

    def test_native_height_saturates(self):
        image = state(0x42C8, U64_MAX)
        output = run(image, "compact", U64_MAX, "after-clock", 4813)
        self.assertEqual(unpack_from("<Q", output, 0x28)[0], U64_MAX)

    def test_later_stage_initializes_index_and_preserves_other_state(self):
        for layout, size, _, _ in LAYOUT_CASES:
            late = state(size, H + 1)
            late[0x50] = 3
            expected = late.copy()
            expected[:16] = (1).to_bytes(8, "little") + bytes(8)
            self.assertEqual(run(late, layout, H + 1, "before-action-initializer"), expected)

    def test_fixture_identity_height_layout_and_arguments(self):
        image = state(0x4E38, H)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            apply(image, "0" * 64, "expanded", H, "after-clock", 4813)
        with self.assertRaisesRegex(ValueError, "height"):
            run(image, "expanded", H + 1, "after-clock", 4813)
        with self.assertRaisesRegex(ValueError, "exactly"):
            run(image, "compact", H, "after-clock", 4813)
        for invalid in (None, -1, U64_MAX + 1):
            with self.assertRaisesRegex(ValueError, "u64"):
                run(image, "expanded", H, "after-clock", invalid)
        with self.assertRaisesRegex(ValueError, "does not"):
            run(image, "expanded", H, "before-action-initializer", 4813)

    def test_cli_reads_a_local_fixture_and_writes_projected_bytes(self):
        image = state(0x42C8, H)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "before.bin"
            path.write_bytes(image)
            result = subprocess.run([
                sys.executable, "-B", str(Path(__file__).with_name("apply_begin.py")), str(path),
                "--sha256", sha256(image).hexdigest(), "--layout", "compact", "--height", str(H),
                "--stage", "after-clock", "--new-round", "4813",
            ], check=True, capture_output=True)
            self.assertEqual(result.stdout, run(image, "compact", H, "after-clock", 4813))
            self.assertEqual(path.read_bytes(), image)


if __name__ == "__main__":
    unittest.main(verbosity=2)
