"""Integrity controls for the explicit public prior-comparison snapshot."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import node115_prior_corpus as corpus


class PriorCorpusTests(unittest.TestCase):
    def test_real_snapshot_is_complete_and_filters_the_reference_packet(self):
        with patch.dict(os.environ, {"NODE115_PRIOR_ROOT": str(ROOT)}):
            all_paths = corpus.paths(ROOT)
            self.assertGreaterEqual(len(all_paths), corpus.RECORD_COUNT)
            self.assertEqual(len(corpus._reference(ROOT)[1]), corpus.RECORD_COUNT)
            self.assertTrue(corpus.is_verified(ROOT))
            narrowed = corpus.paths(ROOT, "*lu-nextnode*/records.json")
            self.assertTrue(narrowed)
            self.assertTrue(all("lu-nextnode" in p for p in narrowed))
            self.assertEqual(corpus.paths(ROOT, "not-a-real-packet"), [])

    def test_committed_packet_identity_is_checked(self):
        with patch.dict(os.environ, {"NODE115_PRIOR_ROOT": str(ROOT)}):
            path = Path(corpus.paths(ROOT, "*lu-nextnode*/records.json")[0])
            record = json.loads(path.read_text())
            self.assertTrue(corpus.is_reference_packet(ROOT, path.parent.name, record))
            self.assertFalse(corpus.is_reference_packet(ROOT, path.parent.name, {}))

    def test_missing_or_changed_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "research/work-items/test/records.json"
            path.parent.mkdir(parents=True)
            original = b'{"exhibits": [{"range": "0x10..0x20"}]}\n'
            path.write_bytes(original)
            entry = {"path": path.relative_to(root).as_posix(),
                     "sha256": hashlib.sha256(original).hexdigest()}
            self.assertEqual(corpus.verify_files(root, [entry]), (path.resolve(),))
            path.write_bytes(original.replace(b"0x20", b"0x21"))
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                corpus.verify_files(root, [entry])
            path.unlink()
            with self.assertRaisesRegex(ValueError, "missing prior"):
                corpus.verify_files(root, [entry])

    def test_updated_packet_uses_only_hash_authenticated_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live = root / "research/work-items/test/records.json"
            saved = root / corpus.ARCHIVE / "test/records.json"
            live.parent.mkdir(parents=True)
            saved.parent.mkdir(parents=True)
            original = b'{"exhibits": [{"range": "0x10..0x20"}]}\n'
            live.write_bytes(b'{"corrected": true}')
            saved.write_bytes(original)
            entry = {"path": live.relative_to(root).as_posix(),
                     "sha256": hashlib.sha256(original).hexdigest()}
            self.assertEqual(corpus.verify_files(root, [entry]), (saved.resolve(),))
            saved.write_bytes(b'{"forged": true}')
            with self.assertRaisesRegex(ValueError, "archived prior record digest mismatch"):
                corpus.verify_files(root, [entry])
            saved.unlink()
            with self.assertRaisesRegex(ValueError, "prior record digest mismatch"):
                corpus.verify_files(root, [entry])

    def test_duplicate_and_escaping_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "research/work-items/test/records.json"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"{}")
            entry = {"path": path.relative_to(root).as_posix(),
                     "sha256": hashlib.sha256(b"{}").hexdigest()}
            for entries in [[entry, entry], [dict(entry, path="../records.json")]]:
                with self.assertRaisesRegex(ValueError, "invalid or duplicate"):
                    corpus.verify_files(root, entries)

    def test_manifest_omission_cannot_create_a_smaller_valid_corpus(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / corpus.MANIFEST
            path.parent.mkdir(parents=True)
            manifest = json.loads((ROOT / corpus.MANIFEST).read_text())
            manifest["records"].pop()
            path.write_text(json.dumps(manifest))
            with patch.dict(os.environ, {"NODE115_PRIOR_ROOT": str(root)}):
                with self.assertRaisesRegex(ValueError, "manifest digest"):
                    corpus.paths(root)

    def test_range_annotation_and_context_controls(self):
        self.assertEqual(corpus.parse_range("0x100..0x125 (37 bytes)"), (0x100, 0x125))
        with self.assertRaisesRegex(ValueError, "annotation mismatch"):
            corpus.parse_range("0x100..0x125 (36 bytes)")
        record = {"next_question": {"windows": [{"range": ["0x100", "0x125"]}]},
                  "exhibits": [{"range": "0x200..0x210"}]}
        self.assertEqual(list(corpus._explicit_ranges(record)), [(0x200, 0x210)])

    def test_next_work_requires_an_existing_full_exhibit(self):
        with patch.dict(os.environ, {"NODE115_PRIOR_ROOT": str(ROOT)}):
            self.assertTrue(corpus.is_documented(ROOT, 0x63577f0, 0x635a786))
            self.assertFalse(corpus.is_documented(ROOT, 0, 1 << 64))

    def test_candidate_overlay_adds_conflicts_but_not_positive_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            added = root / "research/work-items/injected/records.json"
            added.parent.mkdir(parents=True)
            added.write_text('{"exhibits":[{"range":["0xf0000000000","0xf0000000010"]}]}')
            with patch.dict(os.environ, {"NODE115_PRIOR_ROOT": str(ROOT)}):
                self.assertIn(str(added), corpus.paths(root))
                self.assertFalse(corpus.is_documented(root, 0xf0000000000, 0xf0000000010))


if __name__ == "__main__":
    unittest.main()
