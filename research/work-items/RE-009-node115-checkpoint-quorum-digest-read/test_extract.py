import hashlib
from pathlib import Path
import tempfile
import unittest

import msgpack

from extract_qrs import extract


DIGEST = "0x" + bytes(range(32)).hex()
OTHER = "0x" + bytes(reversed(range(32))).hex()


def checkpoint(rows):
    return msgpack.packb({"ignore": [1, 2], "exchange": {"advt": {"qrs": rows}}, "other": 1})


class ExtractTests(unittest.TestCase):
    def read(self, content, height=42, sha256=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.rmp"
            path.write_bytes(content)
            return extract(path, sha256 or hashlib.sha256(content).hexdigest(), height)

    def test_named_and_array_payload_without_neighbor_height_confusion(self):
        result = self.read(checkpoint([
            [41, [OTHER, [], []]], [42, {"h": DIGEST, "a": [], "b": []}], [42, [DIGEST, [], []]],
        ]))
        self.assertEqual(result["digest"], DIGEST)
        self.assertEqual(result["agreeing_rows"], 2)
        self.assertEqual(result["row_height"], 42)
        self.assertEqual(result["kind"], "checkpoint_abci_quorum_candidate")

    def test_wrong_checksum(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.read(checkpoint([]), sha256="0" * 64)

    def test_no_row_at_exact_height(self):
        with self.assertRaisesRegex(ValueError, "no quorum digest row"):
            self.read(checkpoint([[41, [DIGEST, [], []]]]))

    def test_conflicting_rows(self):
        with self.assertRaisesRegex(ValueError, "conflicting quorum"):
            self.read(checkpoint([[42, [DIGEST, [], []]], [42, [OTHER, [], []]]]))

    def test_extra_document_rejected(self):
        with self.assertRaisesRegex(ValueError, "single complete checkpoint"):
            self.read(checkpoint([[42, [DIGEST, [], []]]]) + b"\xc0")

    def test_duplicate_digest_key_rejected(self):
        packer = msgpack.Packer()
        packed_row = packer.pack_array_header(2) + packer.pack(42)
        packed_row += packer.pack_map_header(3)
        packed_row += packer.pack("h") + packer.pack(DIGEST)
        packed_row += packer.pack("h") + packer.pack(OTHER)
        packed_row += packer.pack("a") + packer.pack([])
        prefix = b"".join(
            packer.pack_map_header(1) + packer.pack(name) for name in ("exchange", "advt", "qrs")
        )
        with self.assertRaisesRegex(ValueError, "exactly one quorum payload"):
            self.read(prefix + packer.pack_array_header(1) + packed_row)

    def test_truncation_rejected(self):
        with self.assertRaises(msgpack.OutOfData):
            self.read(checkpoint([[42, [DIGEST, [], []]]])[:-1])

    def test_digest_is_hex_string(self):
        with self.assertRaisesRegex(ValueError, "lowercase hex digest"):
            self.read(checkpoint([[42, [b"\x11" * 32, [], []]]]))


if __name__ == "__main__":
    unittest.main()
