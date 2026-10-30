"""Controls for the info_request_path side-effect tag lookup.

build() previously located each fixed SIDE_EFFECT_TAGS entry through a bare
next(), so a request file missing one of them escaped as StopIteration
instead of the EvidenceError this module raises for every other missing
evidence (including its own hub->deser edge, which uses next(..., None)).
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'info_request_path.py'

spec = importlib.util.spec_from_file_location('info_request_path', TOOL)
irp = importlib.util.module_from_spec(spec)
sys.modules['info_request_path'] = irp
spec.loader.exec_module(irp)


def tag_entry(text):
    return {"text": text, "kind": "tag", "occurrence": 1, "anchor": 0x100,
            "functions": [0x200], "lea_sites": [0x300]}


def full_tags():
    return [tag_entry(t) for t in irp.SIDE_EFFECT_TAGS] + [tag_entry("other")]


class SideEffectMarkersTests(unittest.TestCase):
    def test_returns_one_marker_per_side_effect_tag(self):
        markers = irp.side_effect_markers(full_tags())
        self.assertEqual([m["marker"] for m in markers], list(irp.SIDE_EFFECT_TAGS))
        self.assertTrue(all(m["kind"] == "tag" for m in markers))
        self.assertEqual(markers[0]["functions"], [0x200])

    def test_missing_tag_raises_evidence_error(self):
        tags = [t for t in full_tags() if t["text"] != "outPath"]
        with self.assertRaises(irp.EvidenceError):
            irp.side_effect_markers(tags)

    def test_empty_tags_raises_evidence_error(self):
        with self.assertRaises(irp.EvidenceError):
            irp.side_effect_markers([])

    def test_unrelated_tags_are_ignored(self):
        markers = irp.side_effect_markers(full_tags() + [tag_entry("unrelated")])
        self.assertEqual(len(markers), len(irp.SIDE_EFFECT_TAGS))


if __name__ == '__main__':
    unittest.main()
