from hashlib import sha256
import math
from pathlib import Path
from random import Random
from struct import pack_into, unpack
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from project import DECODED_SIZE, delay_bytes, project_delay


def token(bits):
    return b"\xcb" + bits.to_bytes(8, "big")


class TrackerDelayTests(unittest.TestCase):
    def test_default_and_binary64_boundaries_preserve_unsigned_words(self):
        self.assertEqual(delay_bytes(None), bytes(8))
        for bits in (0, 1, 0xFFFFFFFFFFFFF, 0x10000000000000, 0x3FF0000000000000,
                     0x7FEFFFFFFFFFFFFF, 0x8000000000000000):
            with self.subTest(bits=hex(bits)):
                self.assertEqual(delay_bytes(token(bits)), bits.to_bytes(8, "little"))
        for bits in (0x8000000000000001, 0xBFF0000000000000, 0x7FF0000000000000,
                     0xFFF0000000000000, 0x7FF8000000000000):
            with self.subTest(bits=hex(bits)), self.assertRaisesRegex(ValueError, "finite"):
                delay_bytes(token(bits))

    def test_independent_acceptance_oracle_over_deterministic_bit_patterns(self):
        generator = Random(115)
        for _ in range(4096):
            bits = generator.getrandbits(64)
            packed = bits.to_bytes(8, "big")
            value, = unpack(">d", packed)
            if math.isfinite(value) and value >= 0:
                self.assertEqual(delay_bytes(token(bits)), packed[::-1])
            else:
                with self.assertRaises(ValueError):
                    delay_bytes(token(bits))

    def test_empty_malformed_or_unsupported_tokens_are_not_whole_tracker_absence(self):
        for raw in (b"", b"\xc0", b"\xcb\x00", token(0) + b"\x00",
                    b"\xca" + bytes(4), b"\x01"):
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, "complete"):
                delay_bytes(raw)

    def test_projection_modifies_only_the_decoded_word_and_checks_coordinates(self):
        image = bytearray(b"\xa5" * DECODED_SIZE)
        pack_into("<Q", image, 0x28, 42)
        image = bytes(image)
        digest = sha256(image).hexdigest()
        result = project_delay(image, digest, 42, token(0x4000000000000000))
        self.assertEqual(result[:0x23B8], image[:0x23B8])
        self.assertEqual(result[0x23B8:0x23C0], bytes.fromhex("0000000000000040"))
        self.assertEqual(result[0x23C0:], image[0x23C0:])
        self.assertEqual(project_delay(image, digest, 42, None)[0x23B8:0x23C0], bytes(8))
        with self.assertRaisesRegex(ValueError, "exactly"):
            project_delay(image[:-1], digest, 42, None)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            project_delay(image, "0" * 64, 42, None)
        with self.assertRaisesRegex(ValueError, "height"):
            project_delay(image, digest, 41, None)

    def test_cli_stages_the_same_bytes_as_the_library(self):
        with TemporaryDirectory() as directory:
            image = bytes(DECODED_SIZE)
            digest = sha256(image).hexdigest()
            path = Path(directory) / "historical.bin"
            path.write_bytes(image)
            args = [sys.executable, "-B", str(Path(__file__).with_name("project.py")),
                    str(path), "--sha256", digest, "--height", "0"]
            result = subprocess.run(args + ["--adu-f64-hex", token(1).hex()],
                                    check=True, capture_output=True)
            self.assertEqual(result.stdout, project_delay(image, digest, 0, token(1)))
            missing = subprocess.run(args, check=False, capture_output=True)
            self.assertNotEqual(missing.returncode, 0)
            self.assertEqual(missing.stdout, b"")


if __name__ == "__main__":
    unittest.main(verbosity=2)
