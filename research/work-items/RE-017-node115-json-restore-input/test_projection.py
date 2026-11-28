"""Offline tests for the named JSON local restore fixture input."""

from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from project import project


def payload(ctx, exchange_tail=b""):
    return b'{"exchange":{"locus":{"ctx":{' + ctx + b'}}' + exchange_tail + b'}}'


def run(raw, height=10_000):
    return project(raw, sha256(raw).hexdigest(), height)


class LocalJsonRestoreProjectionTests(unittest.TestCase):
    def test_independent_words_and_freeze_target(self):
        raw = payload(
            b'"height":10000,"consensus_round":20101,"hardfork":{"round":303,"version":109}',
            b',"scheduled_freeze_height":10001',
        )
        self.assertEqual(run(raw), {
            "checkpoint_sha256": sha256(raw).hexdigest(),
            "persisted_height": 10000,
            "persisted_round": 20101,
            "hardfork": {"version": 109, "round": 303},
            "scheduled_freeze": 10001,
        })

    def test_omissions_and_explicit_null(self):
        for tail in (b"", b',"scheduled_freeze_height":null'):
            report = run(payload(b'"height":10000', tail))
            self.assertEqual(report["persisted_round"], 0)
            self.assertEqual(report["hardfork"], {"version": 0, "round": 0})
            self.assertIsNone(report["scheduled_freeze"])
        self.assertEqual(run(payload(b'"height":10000', b',"scheduled_freeze_height":0'))[
            "scheduled_freeze"], 0)

    def test_duplicates_include_alias_and_null_option(self):
        for raw in (
            payload(b'"height":10000,"height":10000'),
            payload(b'"height":10000,"round":1,"consensus_round":1'),
            payload(b'"height":10000,"hardfork":{"version":109,"round":5,"round":6}'),
            payload(b'"height":10000', b',"scheduled_freeze_height":null,"scheduled_freeze_height":10000'),
        ):
            with self.assertRaisesRegex(ValueError, "duplicate field"):
                run(raw)

    def test_u64_coordinates_and_identity(self):
        maximum = 1 << 64
        raw = payload(b'"height":10000,"round":18446744073709551615')
        self.assertEqual(run(raw)["persisted_round"], maximum - 1)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            project(raw, "0" * 64, 10000)
        with self.assertRaisesRegex(ValueError, "differs"):
            run(raw, 10001)
        with self.assertRaisesRegex(ValueError, "missing field"):
            run(payload(b'"round":0'))
        for invalid in (b"true", b"-1", b"1.0", b'"1"', str(maximum).encode()):
            with self.assertRaisesRegex(ValueError, "u64"):
                run(payload(b'"height":10000,"round":' + invalid))

    def test_cli_reads_a_real_local_fixture(self):
        raw = payload(b'"height":10000,"round":10001')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.json"
            path.write_bytes(raw)
            command = [sys.executable, "-B", str(Path(__file__).with_name("project.py")),
                       str(path), "--sha256", sha256(raw).hexdigest(), "--height", "10000"]
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            self.assertEqual(json.loads(result.stdout), run(raw))


if __name__ == "__main__":
    unittest.main(verbosity=2)
