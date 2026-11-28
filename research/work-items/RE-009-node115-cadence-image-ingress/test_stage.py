from hashlib import sha256
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

import msgpack

from stage import DECODED_SIZE, read_checkpoint, stage

HEIGHT = 41


def digest(image):
    return sha256(image).hexdigest()


def fixture(height, misc):
    return msgpack.packb({"exchange": {"msc": misc, "locus": {"ctx": {"height": height}}}})


class CadenceIngressTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "state.rmp"

    def resolve(self, raw, height=HEIGHT, pin=None):
        self.path.write_bytes(raw)
        return read_checkpoint(self.path, pin or digest(raw), height)

    def test_default_custom_and_full_u64_words(self):
        for misc, expected in [({}, 1000), ({"aci": 0}, 1000), ({"aci": 21}, 21),
                               ({"aci": (1 << 64) - 1}, (1 << 64) - 1)]:
            with self.subTest(misc=misc):
                self.assertEqual(self.resolve(fixture(HEIGHT, misc)), expected)

    def test_missing_msc_invalid_cadence_and_related_duplicate(self):
        missing = msgpack.packb({"exchange": {"locus": {"ctx": {"height": HEIGHT}}}})
        with self.assertRaisesRegex(ValueError, "missing field msc"):
            self.resolve(missing)
        for word in (False, None, -1, "1000"):
            with self.subTest(word=word), self.assertRaisesRegex(ValueError, "must be a u64"):
                self.resolve(fixture(HEIGHT, {"aci": word}))
        pack = msgpack.packb
        duplicate = (b"\x81" + pack("exchange") + b"\x82" + pack("msc") + b"\x82"
                     + pack("aci") + pack(0) + pack("aci") + pack(1)
                     + pack("locus") + pack({"ctx": {"height": HEIGHT}}))
        with self.assertRaisesRegex(ValueError, "duplicate field aci"):
            self.resolve(duplicate)

    def test_independently_pinned_source_and_image_coordinates(self):
        raw = fixture(HEIGHT, {"aci": 21})
        with self.assertRaisesRegex(ValueError, "checkpoint SHA-256"):
            self.resolve(raw, pin="0" * 64)
        with self.assertRaisesRegex(ValueError, "trailing"):
            self.resolve(raw + b"\xc0")
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.resolve(raw[:-1])
        with self.assertRaisesRegex(ValueError, "height"):
            self.resolve(raw, height=HEIGHT + 1)

        image = bytearray(b"\xa5" * DECODED_SIZE)
        struct.pack_into("<Q", image, 0x28, HEIGHT)
        with self.assertRaisesRegex(ValueError, "fixture SHA-256"):
            stage(image, "0" * 64, HEIGHT, 21)
        with self.assertRaisesRegex(ValueError, "fixture height"):
            stage(image, digest(image), HEIGHT + 1, 21)

    def test_cli_writes_only_the_resolved_word_into_a_local_fixture(self):
        raw = fixture(HEIGHT, {"aci": 21})
        interval = self.resolve(raw)
        image = bytearray(b"\xa5" * DECODED_SIZE)
        struct.pack_into("<Q", image, 0x28, HEIGHT)
        decoded = self.path.with_name("decoded.bin")
        decoded.write_bytes(image)
        output = subprocess.run(
            [sys.executable, "-B", str(Path(__file__).with_name("stage.py")), str(self.path),
             str(decoded), "--checkpoint-sha256", digest(raw), "--decoded-sha256", digest(image),
             "--height", str(HEIGHT)],
            check=True, capture_output=True,
        ).stdout
        self.assertEqual(output[:0x1ea8], image[:0x1ea8])
        self.assertEqual(output[0x1eb0:], image[0x1eb0:])
        self.assertEqual(struct.unpack_from("<Q", output, 0x1ea8), (interval,))


if __name__ == "__main__":
    unittest.main(verbosity=2)
