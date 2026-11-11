import hashlib
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_warm_table115 as T  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-011-warm-table-growth-115"


class WarmTableTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = T.Image(T.BINARY.read_bytes())
        T.init_globals(cls.image)
        cls.cases = T.all_cases()
        cls.sample = cls.cases[::9]

    def test_rejects_wrong_binary(self):
        data = bytearray(self.image.data)
        data[0x1000] ^= 1
        with self.assertRaises(T.ToolError):
            T.Image(bytes(data))

    def test_static_evidence(self):
        st = T.static_evidence(self.image)
        self.assertEqual(st["special_const"]["hex"], "80" * 16)
        self.assertEqual([f["start"] for f in st["functions"]], ["0x3eda870", "0x3ed8040", "0x143d5f0", "0x2a03a10"])
        self.assertEqual(st["got"]["memmove"]["import"], "memmove")
        with self.assertRaises(T.ToolError):
            T.fde_rows(self.image, {T.MAP_RESERVE + 1})

    def test_sample_matches_model(self):
        res = T.evaluate(self.image, self.sample)
        self.assertEqual([r[0]["kind"] for r in res if not r[3]], [])
        kinds = {T.outcome(c, g) for c, _, g, _ in res}
        for k in ("rehash_in_place", "resize_free_old", "resize_from_static", "alloc_err", "alloc_error",
                  "capacity_overflow", "capacity_overflow_err", "drop_inner_and_outer"):
            self.assertIn(k, kinds)

    def test_model_mutants_detected(self):
        m = T.Machine(self.image)
        for mut in T.MODEL_MUTANTS:
            # first case (full list) where the wrong reconstruction predicts something else; the real code must disagree with it
            c = next((c for c in self.cases if T.model_case(c, frozenset([mut])) != T.model_case(c)), None)
            self.assertIsNotNone(c, mut)
            self.assertNotEqual(T.model_case(c, frozenset([mut])), T.run_case(m, c), mut)

    def test_code_byte_mutants_detected(self):
        for at, imm_at, old, new, what in T.byte_mutants(self.image):
            kind = "drop" if 0x2000000 < at < 0x3000000 else ("set" if at < 0x2000000 else "map")
            rel = [c for c in self.cases if c["kind"] == kind]
            res = T.evaluate(self.image, rel, override={imm_at: new}, stop_on_first=True)
            self.assertTrue(any(not r[3] for r in res), what)

    def test_out_of_range_code_rejected(self):
        with self.assertRaises(T.ToolError):
            self.image.code(self.image.text["address"] + self.image.text["size"] - 2, 16)

    def test_regeneration_matches_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            T.generate(tmp)
            for name in ("cases.tsv", "constants.json", "decoded-instructions.tsv", "negative-controls.tsv",
                         "outcome-classes.tsv", "summary.json"):
                a = (pathlib.Path(tmp) / name).read_bytes()
                b = (FOLDER / name).read_bytes()
                self.assertEqual(hashlib.sha256(a).hexdigest(), hashlib.sha256(b).hexdigest(), name)

    def test_manifest(self):
        rows = (FOLDER / "MANIFEST.sha256").read_text().splitlines()
        names = set()
        for row in rows:
            digest, name = row.split("  ", 1)
            names.add(name)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)
        on_disk = {p.name for p in FOLDER.iterdir() if p.name != "MANIFEST.sha256"}
        self.assertEqual(names, on_disk)


if __name__ == "__main__":
    unittest.main()
