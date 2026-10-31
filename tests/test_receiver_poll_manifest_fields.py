"""Manifest-entry field guard in receiver_poll generate(); synthetic manifest, no target execution."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import receiver_poll_static as receiver_poll


class ReceiverPollManifestFieldsTests(unittest.TestCase):
    def run_generate(self, entry):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / 'provenance').mkdir()
        (root / 'provenance' / 'artifacts.json').write_text(
            json.dumps({'files': [entry]}))
        binary = root / 'hl-node'
        binary.write_bytes(b'\x00' * 64)
        orig = receiver_poll.ROOT
        receiver_poll.ROOT = root
        self.addCleanup(setattr, receiver_poll, 'ROOT', orig)
        return binary, root / 'out'

    def test_missing_sha256_fails_closed(self):
        binary, out = self.run_generate(
            {'path': 'artifacts/node/94/hl-node', 'size': 64})
        with self.assertRaisesRegex(ValueError, 'missing sha256'):
            receiver_poll.generate(binary, out)

    def test_missing_size_fails_closed(self):
        binary, out = self.run_generate(
            {'path': 'artifacts/node/94/hl-node', 'sha256': 'x' * 64})
        with self.assertRaisesRegex(ValueError, 'missing size'):
            receiver_poll.generate(binary, out)

    def test_missing_both_fields_names_both(self):
        binary, out = self.run_generate({'path': 'artifacts/node/94/hl-node'})
        with self.assertRaisesRegex(ValueError, 'missing size/sha256'):
            receiver_poll.generate(binary, out)

    def test_valid_entry_passes_validation(self):
        data = b'\x00' * 64
        binary, out = self.run_generate({
            'path': 'artifacts/node/94/hl-node', 'size': len(data),
            'sha256': hashlib.sha256(data).hexdigest()})
        # check() passes, so the failure moves downstream to a ValueError
        # contract error (ELF parsing of the dummy binary) instead of a
        # KeyError from the field guard.
        with self.assertRaises(ValueError):
            receiver_poll.generate(binary, out)


if __name__ == '__main__':
    unittest.main()
