from hashlib import sha256
import json
from pathlib import Path
from struct import pack_into, unpack_from
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from rewrite import COMPACT_SIZE, U64_MAX, rewrite_local

HEIGHT = 41


def digest(data):
    return sha256(data).hexdigest()


def compact(tag, target, version):
    state = bytearray(b"\xa5" * COMPACT_SIZE)
    pack_into("<4Q", state, 0x18, version, 99, HEIGHT, 105)
    pack_into("<IIQ", state, 0x10e8, tag, 0xa5a5a5a5, target)
    return state


class LocalStartupRewriteTests(unittest.TestCase):
    def test_equality_changes_only_replay_pair_and_retains_original_copy(self):
        for version, expected in [(7, 8), (U64_MAX - 1, U64_MAX), (U64_MAX, U64_MAX)]:
            with self.subTest(version=version):
                image = compact(1, HEIGHT, version)
                before = bytes(image)
                result = rewrite_local(image, digest(image), HEIGHT)
                self.assertTrue(result.rewritten)
                self.assertEqual(result.original_pair, (version, 99))
                self.assertEqual(result.replay_pair, (expected, 105))
                self.assertEqual(unpack_from("<QQ", result.image, 0x18), (expected, 105))
                self.assertEqual(result.image[:0x18], before[:0x18])
                self.assertEqual(result.image[0x28:], before[0x28:])
                self.assertEqual(image, before)

    def test_absent_and_future_freezes_preserve_input_image(self):
        for tag, target in [(0, 0), (0, U64_MAX), (1, HEIGHT + 1), (1, U64_MAX)]:
            with self.subTest(tag=tag, target=target):
                image = compact(tag, target, 7)
                result = rewrite_local(image, digest(image), HEIGHT)
                self.assertFalse(result.rewritten)
                self.assertEqual(result.image, image)
                self.assertEqual(result.original_pair, result.replay_pair)

    def test_past_and_invalid_fixture_coordinates(self):
        image = compact(1, HEIGHT - 1, 7)
        with self.assertRaisesRegex(ValueError, "below checkpoint"):
            rewrite_local(image, digest(image), HEIGHT)
        with self.assertRaisesRegex(ValueError, "height"):
            rewrite_local(image, digest(image), HEIGHT + 1)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            rewrite_local(image, "0" * 64, HEIGHT)
        with self.assertRaisesRegex(ValueError, "exactly"):
            rewrite_local(image[:-1], digest(image[:-1]), HEIGHT)
        image = compact(2, HEIGHT, 7)
        with self.assertRaisesRegex(ValueError, "option tag"):
            rewrite_local(image, digest(image), HEIGHT)

    def test_cli_binary_and_report(self):
        image = compact(1, HEIGHT, 7)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "compact.bin"
            path.write_bytes(image)
            args = [
                sys.executable, "-B", str(Path(__file__).with_name("rewrite.py")), str(path),
                "--sha256", digest(image), "--height", str(HEIGHT),
            ]
            result = subprocess.run(args + ["--image"], check=True, capture_output=True)
            report = subprocess.run(args, check=True, capture_output=True)
            self.assertEqual(result.stdout, rewrite_local(image, digest(image), HEIGHT).image)
            self.assertEqual(json.loads(report.stdout), {
                "original_pair": [7, 99], "replay_pair": [8, 105], "rewritten": True,
                "output_sha256": digest(result.stdout),
            })


if __name__ == "__main__":
    unittest.main(verbosity=2)
