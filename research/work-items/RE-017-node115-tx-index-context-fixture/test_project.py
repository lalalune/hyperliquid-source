from hashlib import sha256
from pathlib import Path
from struct import pack_into, unpack_from
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from project import DECODED_SIZE, decode_tx_index, stage


def digest(value):
    return sha256(value).hexdigest()


class TransactionIndexFixtureTests(unittest.TestCase):
    def test_native_unsigned_widths_and_nonnegative_signed_widths(self):
        for token_hex, value in [
            ("00", 0), ("7f", 127), ("cc80", 128), ("cdffff", 65535),
            ("ceffffffff", (1 << 32) - 1), ("cfffffffffffffffff", (1 << 64) - 1),
            ("d07f", 127), ("d17fff", 32767), ("d27fffffff", (1 << 31) - 1),
            ("d37fffffffffffffff", (1 << 63) - 1),
        ]:
            with self.subTest(token_hex=token_hex):
                self.assertEqual(decode_tx_index(bytes.fromhex(token_hex)), (1, value))

    def test_distinct_omission_nil_and_explicit_zero(self):
        self.assertEqual(decode_tx_index(None), (1, 0))
        self.assertEqual(decode_tx_index(b"\xc0"), (0, None))
        self.assertEqual(decode_tx_index(b"\x00"), (1, 0))
        image = bytearray(b"\xa5" * DECODED_SIZE)
        pack_into("<Q", image, 0x28, 41)
        for token, expected in [(None, (1, 0)), (b"\x00", (1, 0)),
                                (b"\xc0", (0, 0xa5a5a5a5a5a5a5a5))]:
            with self.subTest(token=token):
                result = stage(image, digest(image), 41, token)
                self.assertEqual(unpack_from("<QQ", result), expected)
                self.assertEqual(result[0x10:], image[0x10:])

    def test_bad_scalar_and_image_coordinates(self):
        for token in (b"", b"\xff", b"\xc2", b"\xcf\x00", b"\x00\x00", b"\xd0\xff"):
            with self.subTest(token=token), self.assertRaises(ValueError):
                decode_tx_index(token)
        original = bytes(DECODED_SIZE)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            stage(original, "0" * 64, 0, b"\x00")
        with self.assertRaisesRegex(ValueError, "height"):
            stage(original, digest(original), 1, b"\x00")
        with self.assertRaisesRegex(ValueError, "exactly"):
            stage(original[:-1], digest(original[:-1]), 0, b"\x00")

    def test_cli_emits_one_local_staged_image(self):
        original = bytes(DECODED_SIZE)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "decoded.bin"
            path.write_bytes(original)
            result = subprocess.run(
                [sys.executable, "-B", str(Path(__file__).with_name("project.py")), str(path),
                 "--sha256", digest(original), "--height", "0", "--token-hex", "cc80"],
                check=True, capture_output=True,
            )
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.stdout, stage(original, digest(original), 0, b"\xcc\x80"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
