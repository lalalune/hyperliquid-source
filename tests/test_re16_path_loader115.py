import hashlib
import itertools
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re16_path_loader115 as tool  # noqa: E402

CACHE = {}
PACKET = ROOT / "research" / "work-items" / "RE-016-path-loader-115"


class PathLoader115(unittest.TestCase):
    def setUp(self):
        if not CACHE:
            image = tool.mat.Image(tool.BINARY.read_bytes())
            CACHE.update(image=image, static=tool.static_evidence(image), cases=list(itertools.islice(tool.all_cases(), 240)))
        self.image, self.cases = CACHE["image"], CACHE["cases"]
        self.ev, self.calls, self.decoded = CACHE["static"]

    def test_regenerated_evidence_matches_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = tool.generate(pathlib.Path(tmp))
            self.assertEqual(summary["mismatches"], 0)
            self.assertEqual(summary["cases"], tool.CASES)
            self.assertEqual(summary["negative_controls"]["detected"], summary["negative_controls"]["total"])
            self.assertGreaterEqual(summary["negative_controls"]["total"], 30)
            names = sorted(p.name for p in PACKET.iterdir() if p.suffix in (".tsv", ".json"))
            self.assertEqual(names, sorted(p.name for p in pathlib.Path(tmp).iterdir()))
            for name in names:
                self.assertEqual((pathlib.Path(tmp) / name).read_bytes(), (PACKET / name).read_bytes(), name)

    def test_manifest(self):
        listed = {}
        for row in (PACKET / "MANIFEST.sha256").read_text().splitlines():
            digest, name = row.split("  ", 1)
            listed[name] = digest
        self.assertEqual(sorted(listed), sorted(p.name for p in PACKET.iterdir() if p.name != "MANIFEST.sha256"))
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)

    def test_measure_matches_summary(self):
        measure = json.loads((PACKET / "measure.json").read_text())
        summary = json.loads((PACKET / "summary.json").read_text())
        self.assertEqual(measure["cases"], summary["cases"])
        self.assertEqual(measure["negative_controls"], summary["negative_controls"]["total"])
        self.assertEqual(measure["negative_detected"], summary["negative_controls"]["detected"])

    def test_static_constants(self):
        self.assertEqual(self.ev["function"]["fde_bytes"], 796)
        self.assertEqual(self.ev["extension_constant"], {"va": "0x7c95c0", "bytes": b"rmp".hex(), "text": "rmp"})
        self.assertEqual(self.ev["direct_callers"], ["0x2ae4f0b", "0x2cdf007", "0x3c13536", "0x564a68c"])
        self.assertEqual(len(self.calls), 19)
        roles = {r["role"] for r in self.calls}
        self.assertIn("eq_ignore_ascii_case", roles)
        self.assertEqual(self.ev["frame"]["body_rsp_from_entry"], -0xf0)

    def test_model_agrees_with_machine_code(self):
        n, bad, classes, machine = tool.evaluate(self.image, self.cases)
        self.assertEqual((n, bad), (240, 0))
        for outcome in ("rmp/ok", "rmp/err", "other/ok", "other/err", "early/err"):
            self.assertIn(outcome, classes)

    def test_every_model_mutant_is_caught(self):
        for name in tool.MODEL_MUTANTS:
            _, bad, _, _ = tool.evaluate(self.image, self.cases, mut=frozenset([name]), stop_on_first=True)
            self.assertTrue(bad, name)

    def test_code_byte_mutants_are_caught(self):
        for va, old, new, what in tool.BYTE_MUTANTS:
            self.assertEqual(self.image.code(va, 1)[0], old, what)
            _, bad, _, _ = tool.evaluate(self.image, self.cases, override={va: new}, stop_on_first=True)
            self.assertTrue(bad, what)

    def test_extension_rule(self):
        e = tool.ext_of
        self.assertIsNone(e(b".."))
        self.assertIsNone(e(b".rmp"))          # dot at index 0 is a hidden file
        self.assertIsNone(e(b"noext"))
        self.assertIsNone(e(b""))
        self.assertEqual(e(b"a.rmp"), b"rmp")
        self.assertEqual(e(b"a.tar.RMP"), b"RMP")
        self.assertEqual(e(b"a/b.c/d"), b"c/d")   # no separator awareness: the last dot wins
        self.assertEqual(e(b"a."), b"")
        self.assertTrue(tool.eq_nocase(b"rMP", b"rmp"))
        self.assertFalse(tool.eq_nocase(b"rm", b"rmp"))
        self.assertFalse(tool.eq_nocase(b"rm\\", b"rmp"))

    def test_error_arms_return_one(self):
        by_shape = {}
        for c in self.cases:
            calls, rax, rdx = tool.model(c)
            by_shape.setdefault((tuple(r[0] for r in calls), rax), (c, rdx))
        err = [k for k in by_shape if k[1] == 1]
        self.assertTrue(any("format" in k[0] for k in err))
        self.assertTrue(any("rmp_err" in k[0] for k in err))
        self.assertTrue(any("other_err" in k[0] for k in err))
        self.assertTrue(any("other_decode_error" in k[0] for k in err))
        self.assertTrue(any("rmp_decode_error" in k[0] for k in err))

    def test_wrong_inputs_are_rejected(self):
        corrupt = bytearray(self.image.data)
        corrupt[self.image.text["offset"] + 7] ^= 1
        with self.assertRaises(tool.ToolError):
            tool.mat.Image(bytes(corrupt))
        with self.assertRaises(tool.ToolError):
            self.image.code(self.image.text["address"] + self.image.text["size"] + 0x100, 4)
        with self.assertRaises(tool.ToolError):
            self.image.read(0x7fff_ffff_f000, 3)

    def test_case_stream_is_deterministic(self):
        again = list(itertools.islice(tool.all_cases(), 24))
        for a, b in zip(self.cases, again):
            self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
