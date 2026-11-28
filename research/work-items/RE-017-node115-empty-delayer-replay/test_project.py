from hashlib import sha256
import json
from pathlib import Path
from struct import pack_into, unpack_from
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from project import COMPACT_SIZE, project_empty_replay

HEIGHT = 418


def synthetic():
    image = bytearray(b"\xA5" * COMPACT_SIZE)
    pack_into("<Q", image, 0x28, HEIGHT)
    pack_into("<4Q", image, 0x40C0, 0, 0x1000, 0, 0)
    return image


def projection(image):
    return project_empty_replay(image, sha256(image).hexdigest(), HEIGHT)


class EmptyExtractorTests(unittest.TestCase):
    def test_exact_image_delta_preserves_counter_and_every_other_byte(self):
        image = synthetic()
        before = bytes(image)
        updated, words, consumer = projection(image)
        self.assertEqual(updated[:0x40C8], before[:0x40C8])
        self.assertEqual(updated[0x40D0:], before[0x40D0:])
        self.assertEqual(unpack_from("<4Q", updated, 0x40C0), (0, 8, 0, 0))
        self.assertEqual(unpack_from("<Q", updated, 0x4120), (0xA5A5A5A5A5A5A5A5,))
        self.assertEqual(image, before)
        self.assertEqual(words, (0, 8, 0))
        self.assertEqual(consumer, (8, 8, 0, 8))
        self.assertEqual(projection(updated), (updated, words, consumer))

    def test_fixture_coordinates_and_nearby_unsupported_shapes(self):
        image = synthetic()
        with self.assertRaisesRegex(ValueError, "exactly"):
            projection(image[:-1])
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            project_empty_replay(image, "0" * 64, HEIGHT)
        with self.assertRaisesRegex(ValueError, "height"):
            project_empty_replay(image, sha256(image).hexdigest(), HEIGHT + 1)
        for offset, value, message in (
            (0x40C0, 1 << 63, "zero-capacity"),
            (0x40C0, 4, "zero-capacity"),
            (0x40D0, 1, "zero-head"),
            (0x40D8, 1, "empty"),
            (0x40C8, 0, "pointer word"),
            (0x40C8, 7, "pointer word"),
        ):
            with self.subTest(offset=hex(offset), value=value):
                image = synthetic()
                pack_into("<Q", image, offset, value)
                with self.assertRaisesRegex(ValueError, message):
                    projection(image)

    def test_cli_reports_normalized_fixture_and_empty_descriptor(self):
        image = synthetic()
        with TemporaryDirectory() as directory:
            source = Path(directory) / "state.bin"
            source.write_bytes(image)
            arguments = [
                sys.executable, "-B", str(Path(__file__).with_name("project.py")),
                str(source), "--height", str(HEIGHT), "--sha256", sha256(image).hexdigest(),
            ]
            result = subprocess.run(arguments, check=True, capture_output=True, text=True)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout), {
            "height": HEIGHT,
            "output_sha256": sha256(projection(image)[0]).hexdigest(),
            "extractor_words": [0, 8, 0],
            "consumer_range_words": [8, 8, 0, 8],
        })


if __name__ == "__main__":
    unittest.main(verbosity=2)
