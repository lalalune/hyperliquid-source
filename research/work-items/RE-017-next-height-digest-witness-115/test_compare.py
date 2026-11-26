import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from compare import U64_MAX, compare

FIXTURES = Path(__file__).resolve().parent / "fixtures"
WITNESS = FIXTURES / "witness.jsonl"
LOCAL = FIXTURES / "local.jsonl"
WITNESS_SHA = "c3644ff7f6d208cdf646696c60446243ef8282a03b099af6d9676b8b4b49a6c1"
LOCAL_SHA = "639b08de6ad69213f1148035227d6abd02991c4031d41ec11b5b567158eebef4"


class CompareTest(unittest.TestCase):
    def test_frozen_successor(self):
        result = compare(40, WITNESS, WITNESS_SHA, LOCAL, LOCAL_SHA)
        self.assertEqual((result["height"], result["comparison"]), (41, "equal"))
        self.assertEqual(result["expected"], "0x" + "11" * 32)

    def test_mismatches_use_every_byte_and_ignore_exchange_hash(self):
        original = json.loads(LOCAL.read_bytes().splitlines()[1])
        with TemporaryDirectory() as tmp:
            other = Path(tmp) / "local"
            for position in range(32):
                different = bytearray.fromhex(original["abci_digest"][2:])
                different[position] ^= 1
                row = dict(original, abci_digest="0x" + different.hex(),
                           exchange_abci_hash=original["abci_digest"])
                raw = (json.dumps(row) + "\n").encode()
                other.write_bytes(raw)
                result = compare(40, WITNESS, WITNESS_SHA, other, hashlib.sha256(raw).hexdigest())
                self.assertEqual(result["comparison"], "mismatch")

    def test_selection_and_provenance_boundaries(self):
        for height, message in [(41, "missing"), (U64_MAX, "successor"), (-1, "successor")]:
            with self.subTest(height=height), self.assertRaisesRegex(ValueError, message):
                compare(height, WITNESS, WITNESS_SHA, LOCAL, LOCAL_SHA)
        with self.assertRaisesRegex(ValueError, "same file"):
            compare(40, WITNESS, WITNESS_SHA, WITNESS, WITNESS_SHA)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            compare(40, WITNESS, LOCAL_SHA, LOCAL, LOCAL_SHA)

    def test_repeated_conflicting_and_malformed_witnesses(self):
        original = WITNESS.read_bytes()
        with TemporaryDirectory() as tmp:
            other = Path(tmp) / "witness"

            def compare_bytes(raw):
                other.write_bytes(raw)
                return compare(40, other, hashlib.sha256(raw).hexdigest(), LOCAL, LOCAL_SHA)

            self.assertEqual(compare_bytes(original * 2)["comparison"], "equal")
            for raw, error in [
                (original + original.replace(b"11", b"33"), "conflicting"),
                (original.replace(b'"height":', b'"height":40,"height":'), "duplicate JSON key"),
                (original.replace(b"41", b"true"), "invalid u64"),
                (original.replace(b"0x", b"0X"), "invalid d digest"),
                (original.rstrip(), "incomplete"),
                (LOCAL.read_bytes(), "unexpected fields"),
            ]:
                with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                    compare_bytes(raw)


if __name__ == "__main__":
    unittest.main()
