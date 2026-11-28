"""Synthetic writer-shape controls for the offline LtHash cache projector."""

import json
from hashlib import sha256
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from read_sidecar import HASH_BYTES, LANES, U64_MAX, project


def sample():
    return {name: {"hash": [(i + index) % 256 for i in range(HASH_BYTES)],
                   "n_elements": U64_MAX - index,
                   "n_bytes": index + 17}
            for index, name in enumerate(reversed(LANES))}


def parse(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return project(raw, sha256(raw).hexdigest())


class SidecarProjectionTests(unittest.TestCase):
    def test_native_layout_for_each_named_record(self):
        source = sample()
        records = parse(source)
        self.assertEqual(tuple(records), LANES)
        for lane, record in records.items():
            row = source[lane]
            self.assertEqual(len(record), 0x810)
            self.assertEqual(record[:0x800], bytes(row["hash"]))
            self.assertEqual(int.from_bytes(record[0x800:0x808], "little"), row["n_elements"])
            self.assertEqual(int.from_bytes(record[0x808:0x810], "little"), row["n_bytes"])

    def test_identity_duplicate_and_utf8_controls(self):
        raw = json.dumps(sample()).encode()
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            project(raw, "0" * 64)
        duplicate = b'{"accounts_hash":null,' + raw[1:]
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            project(duplicate, sha256(duplicate).hexdigest())
        embedded = raw.replace(b'"n_bytes":', b'"n_bytes":0,"n_bytes":', 1)
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            project(embedded, sha256(embedded).hexdigest())
        invalid_utf8 = b"\xff" + raw
        with self.assertRaises(UnicodeDecodeError):
            project(invalid_utf8, sha256(invalid_utf8).hexdigest())

    def test_wrong_record_counts_and_values(self):
        for field, bad in (
            ("n_elements", -1), ("n_elements", U64_MAX + 1), ("n_bytes", True),
            ("hash", []), ("hash", [0] * (HASH_BYTES + 1)),
            ("hash", [False] * HASH_BYTES), ("hash", [256] * HASH_BYTES),
            ("hash", "00" * HASH_BYTES),
        ):
            obj = sample()
            obj[LANES[0]][field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                parse(obj)
        obj = sample()
        del obj[LANES[0]]
        with self.assertRaisesRegex(ValueError, "three named"):
            parse(obj)

    def test_cli_reads_a_pinned_local_sidecar_and_reports_absence(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "lt_hashes.json"
            raw = json.dumps(sample()).encode()
            path.write_bytes(raw)
            command = [sys.executable, "-B", str(Path(__file__).with_name("read_sidecar.py")),
                       str(path), "--sha256", sha256(raw).hexdigest()]
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            summary = json.loads(result.stdout)
            self.assertEqual(summary["sidecar_sha256"], sha256(raw).hexdigest())
            self.assertEqual(summary["records"][LANES[0]]["layout_bytes"], 0x810)
            path.unlink()
            missing = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(missing.returncode, 1)
            self.assertIn("offline check", missing.stderr)
            self.assertEqual(missing.stdout, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
