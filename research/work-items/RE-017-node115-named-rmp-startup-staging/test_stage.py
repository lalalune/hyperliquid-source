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
MISSING = object()


def digest(value):
    return sha256(value).hexdigest()


def checkpoint(hardfork=MISSING, freeze=MISSING, outside=None):
    fields = {"height": HEIGHT, "round": 105}
    if hardfork is not MISSING:
        fields["hardfork"] = hardfork
    exchange = {"locus": {"ctx": fields}}
    if freeze is not MISSING:
        exchange["scheduled_freeze_height"] = freeze
    return msgpack.packb({"outside": outside, "exchange": exchange}, use_bin_type=True)


def decoded():
    image = bytearray(b"\xa5" * DECODED_SIZE)
    struct.pack_into("<4Q", image, 0x18, 17, 19, HEIGHT, 105)
    return image


class NamedStartupTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "checkpoint.rmp"

    def project(self, raw, expected=HEIGHT, pin=None):
        self.path.write_bytes(raw)
        return read_checkpoint(self.path, pin or digest(raw), expected)

    def test_pins_independent_words_and_streams_unrelated_bytes(self):
        raw = checkpoint({"round": 99, "version": (1 << 64) - 1},
                         0, outside=b"\x7e" * (2 * 1024 * 1024))
        self.assertEqual(self.project(raw), {
            "height": HEIGHT, "hardfork_version": (1 << 64) - 1,
            "hardfork_round": 99, "scheduled_freeze": 0,
        })

    def test_options_and_required_child_fields(self):
        for absent in [MISSING, None]:
            result = self.project(checkpoint(freeze=absent))
            self.assertIsNone(result["scheduled_freeze"])
            self.assertEqual((result["hardfork_version"], result["hardfork_round"]), (0, 0))
        with self.assertRaisesRegex(ValueError, "missing field round"):
            self.project(checkpoint({"version": 2}))
        with self.assertRaisesRegex(ValueError, "scheduled_freeze_height must be a u64"):
            self.project(checkpoint(freeze=True))

        pack = msgpack.packb
        locus = pack("locus") + pack({"ctx": {"height": HEIGHT}})
        option = pack("scheduled_freeze_height") + pack(None)
        duplicate = b"\x81" + pack("exchange") + b"\x83" + locus + option * 2
        with self.assertRaisesRegex(ValueError, "duplicate field scheduled"):
            self.project(duplicate)

    def test_exact_byte_updates_and_cli(self):
        data = checkpoint({"version": 8, "round": 99}, 0)
        result = self.project(data)
        image = decoded()
        actual = stage(image, digest(image), result)
        self.assertEqual(struct.unpack_from("<4Q", actual, 0x18), (8, 99, HEIGHT, 105))
        self.assertEqual(struct.unpack_from("<2Q", actual, 0x10e8), (1, 0))
        self.assertEqual(actual[0x38:0x10e8], image[0x38:0x10e8])
        self.assertEqual(actual[0x10f8:], image[0x10f8:])

        image_path = self.path.with_name("decoded.bin")
        image_path.write_bytes(image)
        command = [
            sys.executable, "-B", str(Path(__file__).with_name("stage.py")), str(self.path),
            "--sha256", digest(data), "--height", str(HEIGHT), "--decoded-state", str(image_path),
            "--decoded-sha256", digest(image),
        ]
        output = subprocess.run(command, check=True, capture_output=True)
        self.assertEqual(output.stdout, actual)
        self.assertEqual(output.stderr, b"")
        absent = stage(image, digest(image), self.project(checkpoint(freeze=None)))
        self.assertEqual(absent[0x10e8:0x10f0], bytes(8))
        self.assertEqual(absent[0x10f0:0x10f8], image[0x10f0:0x10f8])

    def test_input_identity_size_height_and_eof(self):
        data = checkpoint()
        with self.assertRaisesRegex(ValueError, "height"):
            self.project(data, HEIGHT + 1)
        with self.assertRaisesRegex(ValueError, "checkpoint SHA-256"):
            self.project(data, pin="0" * 64)
        with self.assertRaisesRegex(ValueError, "trailing"):
            self.project(data + b"\xc0")
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.project(data[:-1])
        fields = self.project(data)
        image = decoded()
        with self.assertRaisesRegex(ValueError, "exactly"):
            stage(image[:-1], digest(image[:-1]), fields)
        with self.assertRaisesRegex(ValueError, "fixture SHA-256"):
            stage(image, "0" * 64, fields)


if __name__ == "__main__":
    unittest.main(verbosity=2)
