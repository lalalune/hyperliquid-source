import hashlib
from pathlib import Path
import tempfile
import unittest

import msgpack

from read_coordinates import Coordinates, read_coordinates


class CoordinateReader(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "checkpoint.rmp"

    def decode(self, data):
        self.path.write_bytes(data)
        return read_coordinates(self.path, hashlib.sha256(data).hexdigest())

    def named(self, fields):
        return msgpack.packb({
            "exchange": {
                "other": list(range(100_000)),
                "locus": {"ctx": fields},
            },
            "unrelated": {"another": b"value"},
        }, use_bin_type=True)

    def test_distinct_coordinate_values_and_aliases(self):
        for alias in ("round", "consensus_round"):
            data = self.named({"height": 42, alias: 817})
            self.assertEqual(self.decode(data), Coordinates(42, 817, alias))

    def test_missing_round_and_present_zero_are_distinct_observations(self):
        self.assertEqual(self.decode(self.named({"height": 42})), Coordinates(42, 0, None))
        self.assertEqual(self.decode(self.named({"height": 42, "round": 0})),
                         Coordinates(42, 0, "round"))

    def test_coordinate_conflicts_and_identity(self):
        for invalid in (
            self.named({"round": 7}),
            self.named({"height": True}),
            self.named({"height": 42, "round": 7, "consensus_round": 7}),
            self.named({"height": 42}) + b"\x81",
        ):
            with self.assertRaises(ValueError):
                self.decode(invalid)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            read_coordinates(self.path, "0" * 64)
