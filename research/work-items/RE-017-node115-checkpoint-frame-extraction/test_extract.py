import hashlib
from pathlib import Path
import tempfile
import unittest

import lz4.frame

from extract import extract

PAYLOAD = b"\x81\xa8exchange\x80" * 150_000


def sha(data):
    return hashlib.sha256(data).hexdigest()


class ArchiveExtraction(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.source = root / "checkpoint.rmp.lz4"
        self.destination = root / "checkpoint.rmp"
        self.compressed = lz4.frame.compress(PAYLOAD, content_checksum=True)
        self.source.write_bytes(self.compressed)

    def test_archive_and_output_match_across_multiple_chunks(self):
        size = extract(self.source, self.destination, sha(self.compressed), sha(PAYLOAD), len(PAYLOAD))
        self.assertEqual(size, len(PAYLOAD))
        self.assertEqual(self.destination.read_bytes(), PAYLOAD)
        self.assertEqual(self.source.read_bytes(), self.compressed)

    def test_digest_checks_and_output_bound_leave_no_partial_file(self):
        for archive, decoded, limit, message in [
            ("0" * 64, sha(PAYLOAD), len(PAYLOAD), "compressed archive"),
            (sha(self.compressed), "0" * 64, len(PAYLOAD), "decoded checkpoint SHA"),
            (sha(self.compressed), sha(PAYLOAD), 1000, "maximum output size"),
        ]:
            with self.assertRaisesRegex(ValueError, message):
                extract(self.source, self.destination, archive, decoded, limit)
            self.assertFalse(self.destination.exists())

    def test_rejects_nonframe_and_preserves_existing_output(self):
        raw = (len(PAYLOAD)).to_bytes(4, "little") + PAYLOAD[:16]
        self.source.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "LZ4 frame"):
            extract(self.source, self.destination, sha(raw), sha(PAYLOAD), len(PAYLOAD))
        self.destination.write_bytes(b"already present")
        with self.assertRaises(FileExistsError):
            extract(self.source, self.destination, sha(raw), sha(PAYLOAD), len(PAYLOAD))
        self.assertEqual(self.destination.read_bytes(), b"already present")
