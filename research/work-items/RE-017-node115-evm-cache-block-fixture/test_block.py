from hashlib import sha256
from pathlib import Path
from struct import unpack_from
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from build_block import build_block


def digest(value):
    return sha256(value).hexdigest()


def inputs():
    records = b"".join(bytes([lane]) * 0x800 + lane.to_bytes(8, "little")
                       + (lane + 32).to_bytes(8, "little") for lane in range(1, 4))
    descriptors = b"a" * 0xF8 + b"c" * 0xF8 + b"s" * 0xF8 + bytes.fromhex("1020304050607080")
    return records, descriptors


def build(records, descriptors):
    return build_block(records, digest(records), descriptors, digest(descriptors))


class CacheBlockFixtureTests(unittest.TestCase):
    def test_all_lane_boundaries_counters_and_tail(self):
        records, descriptors = inputs()
        block = build(records, descriptors)
        self.assertEqual(len(block), 0x1B20)
        for lane, descriptor in enumerate(b"acs"):
            start = (0, 0x908, 0x1210)[lane]
            self.assertEqual(block[start:start + 0xF8], bytes([descriptor]) * 0xF8)
            self.assertEqual(block[start + 0xF8:start + 0x8F8], bytes([lane + 1]) * 0x800)
            self.assertEqual(unpack_from("<QQ", block, start + 0x8F8), (lane + 1, lane + 33))
        self.assertEqual(block[0x1B18:], descriptors[-8:])

    def test_files_are_independently_pinned_and_require_exact_lengths(self):
        records, descriptors = inputs()
        with self.assertRaisesRegex(ValueError, "cache records SHA-256"):
            build_block(records, "0" * 64, descriptors, digest(descriptors))
        with self.assertRaisesRegex(ValueError, "descriptors and tail SHA-256"):
            build_block(records, digest(records), descriptors, "0" * 64)
        with self.assertRaisesRegex(ValueError, "exactly 0x1830"):
            build(records[1:], descriptors)
        with self.assertRaisesRegex(ValueError, "exactly 0x2f0"):
            build(records, descriptors + b"\x00")

    def test_cli_emits_only_the_payload_and_rejects_extra_bytes(self):
        records, descriptors = inputs()
        with TemporaryDirectory() as directory:
            records_file = Path(directory) / "records.bin"
            metadata_file = Path(directory) / "metadata.bin"
            records_file.write_bytes(records)
            metadata_file.write_bytes(descriptors)
            command = [
                sys.executable, "-B", str(Path(__file__).with_name("build_block.py")),
                str(records_file), str(metadata_file), "--records-sha256", digest(records),
                "--descriptors-sha256", digest(descriptors),
            ]
            result = subprocess.run(command, check=True, capture_output=True)
            self.assertEqual(result.stderr, b"")
            self.assertEqual(result.stdout, build(records, descriptors))

            metadata_file.write_bytes(descriptors + b"\x00")
            result = subprocess.run(command, check=False, capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"exactly 0x2f0", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
