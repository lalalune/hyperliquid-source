from hashlib import sha256
from pathlib import Path
from struct import pack_into, unpack_from
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from project import COMPACT_SIZE, project_empty_delayer

HEIGHT = 1234


def fixture():
    image = bytearray(b"\xA5" * COMPACT_SIZE)
    pack_into("<Q", image, 0x28, HEIGHT)
    pack_into("<5Q", image, 0x40C0, 3, 0xDEADBEEF, 6, 0, 0)
    return image


def project(image):
    return project_empty_delayer(image, sha256(image).hexdigest(), HEIGHT)


class EmptyDelayerFixtureTests(unittest.TestCase):
    def test_exact_delta_and_untouched_pointer_word(self):
        image = fixture()
        before = bytes(image)
        out = project(image)
        self.assertEqual(out[:0x40E0], before[:0x40E0])
        self.assertEqual(unpack_from("<4Q", out, 0x40E0), (0, 8, 0, 0))
        self.assertEqual(out[0x4100:0x4120], before[0x4100:0x4120])
        self.assertEqual(out[0x4120:0x4128], bytes(8))
        self.assertEqual(out[0x4128:], before[0x4128:])
        self.assertEqual(image, before)

    def test_second_application_has_no_further_delta(self):
        first = project(fixture())
        self.assertEqual(project(first), first)

    def test_layout_digest_and_height_are_checked(self):
        image = fixture()
        with self.assertRaisesRegex(ValueError, "exactly"):
            project(image[:-1])
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            project_empty_delayer(image, "0" * 64, HEIGHT)
        with self.assertRaisesRegex(ValueError, "height"):
            project_empty_delayer(image, sha256(image).hexdigest(), HEIGHT + 1)

    def test_unsupported_loader_branches(self):
        for offset, value, message in (
            (0x40C0, 1 << 63, "sentinel"),
            (0x40D8, 1, "nonempty ring"),
            (0x40E0, 1, "nonzero destination"),
        ):
            with self.subTest(offset=hex(offset)):
                image = fixture()
                pack_into("<Q", image, offset, value)
                with self.assertRaisesRegex(ValueError, message):
                    project(image)

    def test_cli_emits_binary_only_and_no_partial_output_on_error(self):
        image = fixture()
        with TemporaryDirectory() as directory:
            source = Path(directory) / "state.bin"
            source.write_bytes(image)
            invoke = [sys.executable, "-B", str(Path(__file__).with_name("project.py")),
                      str(source), "--height", str(HEIGHT), "--sha256"]
            result = subprocess.run(
                invoke + [sha256(image).hexdigest()], capture_output=True, check=True,
            )
            self.assertEqual(result.stdout, project(image))
            self.assertEqual(result.stderr, b"")
            failure = subprocess.run(invoke + ["0" * 64], capture_output=True, check=False)
            self.assertEqual(failure.returncode, 1)
            self.assertEqual(failure.stdout, b"")
            self.assertIn(b"SHA-256", failure.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
