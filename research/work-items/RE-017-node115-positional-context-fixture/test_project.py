from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

import msgpack

from project import DECODED_SIZE, project, stage_round

HEIGHT = 41
ROUND = 102
CLOCK = "2026-11-28T13:47:08.123456789"
PREV = "2026-11-28T13:47:07.999999999"


def digest(data):
    return sha256(data).hexdigest()


def context():
    return [17, [0, 9], HEIGHT, None, ROUND, CLOCK, PREV, 8, 9, 10, None, None, False]


def checkpoint(value):
    return msgpack.packb({"exchange": {"locus": {"ctx": value}}}, use_bin_type=True)


class PositionalContextTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "checkpoint.rmp"

    def project_raw(self, raw, height=HEIGHT, pin=None):
        self.path.write_bytes(raw)
        return project(self.path, pin if pin is not None else digest(raw), height)

    def test_selects_arrays_under_named_parent_with_large_unrelated_branch(self):
        raw = msgpack.packb(
            {"unused": b"\xa5" * (2 * 1024 * 1024),
             "exchange": {"locus": {"ctx": context()}, "later": [1, "s"]}},
            use_bin_type=True,
        )
        self.assertEqual(self.project_raw(raw), {
            "height": HEIGHT, "round": ROUND, "time": CLOCK, "prev_time": PREV,
        })

    def test_mutations_do_not_fall_back_to_named_context_defaults(self):
        value = context()
        with self.assertRaisesRegex(ValueError, "fewer than nine"):
            self.project_raw(checkpoint(value[:8]))
        with self.assertRaises(ValueError):
            self.project_raw(checkpoint({"height": HEIGHT, "round": ROUND}))
        value[4] = True
        with self.assertRaisesRegex(ValueError, "unsigned"):
            self.project_raw(checkpoint(value))
        value = context()
        value[6] = "2026-02-29T13:00:00"
        with self.assertRaisesRegex(ValueError, "calendar"):
            self.project_raw(checkpoint(value))
        value[6] = "2026-11-28T13:00:00Z"
        with self.assertRaisesRegex(ValueError, "clock text"):
            self.project_raw(checkpoint(value))

    def test_identity_height_duplicate_and_outer_eof(self):
        raw = checkpoint(context())
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.project_raw(raw, pin="0" * 64)
        with self.assertRaisesRegex(ValueError, "height"):
            self.project_raw(raw, height=HEIGHT + 1)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.project_raw(raw[:-1])
        with self.assertRaisesRegex(ValueError, "trailing"):
            self.project_raw(raw + b"\xc0")
        token = msgpack.packb("ctx") + msgpack.packb(context())
        duplicate = b"\x81" + msgpack.packb("exchange") + b"\x81" + msgpack.packb("locus") + b"\x82" + token * 2
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.project_raw(duplicate)

    def test_stages_round_at_verified_boundary_and_cli_reports_both_clocks(self):
        raw = checkpoint(context())
        projection = self.project_raw(raw)
        image = bytearray(b"\xa5" * DECODED_SIZE)
        struct.pack_into("<Q", image, 0x28, HEIGHT)
        expected = stage_round(image, digest(image), projection)
        self.assertEqual(expected[:0x30], image[:0x30])
        self.assertEqual(struct.unpack_from("<Q", expected, 0x30), (ROUND,))
        self.assertEqual(expected[0x38:], image[0x38:])
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            stage_round(image, "0" * 64, projection)
        with self.assertRaisesRegex(ValueError, "height"):
            stage_round(image, digest(image), {**projection, "height": 1})

        decoded = self.path.with_name("decoded.bin")
        decoded.write_bytes(image)
        command = [
            sys.executable, "-B", str(Path(__file__).with_name("project.py")), str(self.path),
            "--sha256", digest(raw), "--height", str(HEIGHT),
        ]
        report = subprocess.run(command, check=True, capture_output=True)
        self.assertEqual(json.loads(report.stdout), projection)
        result = subprocess.run(
            command + ["--decoded-state", str(decoded), "--decoded-sha256", digest(image)],
            check=True, capture_output=True,
        )
        self.assertEqual(result.stdout, expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
