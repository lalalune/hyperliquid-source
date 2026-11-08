import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import state_export_route115 as t  # noqa: E402

WORK = ROOT / "research" / "work-items" / t.WORK_DIR


def rep(**over):
    base_rep = {"comp": ("N", b"state.rmp"), "rmp": ("ok", 0x40, t.VEC + 0x100, 77), "alloc": t.VEC + 0x500,
                "json": ("ok", 0x80, t.VEC + 0x300, 55), "chk": 0, "write": 0x6001, "drop": 0x7001}
    base_rep.update(over)
    return base_rep


class ModelTests(unittest.TestCase):
    def test_devnull_returns_before_any_call(self):
        tr, rv, labels = t.route_model(b"/dev/null", rep())
        self.assertEqual((tr, rv, labels), ([], 0, ["devnull"]))

    def test_devnull_needs_exact_bytes(self):
        for near in (b"/dev/nul", b"/dev/NULL", b"dev/null", b"/dev/nullx", b"/dev/nulL"):
            tr, _, labels = t.route_model(near, rep())
            self.assertNotIn("devnull", labels, near)
            self.assertEqual(tr[0][0], "components")

    def test_rmp_extension_is_ascii_case_insensitive(self):
        for name in (b"a.rmp", b"a.RMP", b"a.Rmp", b"b.c.rMp"):
            _, _, labels = t.route_model(b"x/" + name, rep(comp=("N", name)))
            self.assertIn("rmp", labels, name)
        for name in (b"a.rmpx", b"a.rm", b"a.", b"a", b".rmp", b"rmp", b"a.rm\xf0"):
            _, _, labels = t.route_model(b"x/" + name, rep(comp=("N", name)))
            self.assertIn("json", labels, name)

    def test_dotdot_name_never_reaches_extension_compare(self):
        tr, _, labels = t.route_model(b"x/..", rep(comp=("N", b"..")))
        self.assertNotIn("ext_eq", [c[0] for c in tr])
        self.assertIn("dotdot", labels)

    def test_non_normal_component_goes_to_json(self):
        _, _, labels = t.route_model(b"/", rep(comp=("X", 7)))
        self.assertEqual(labels[:2], ["comp_other", "json"])

    def test_rmp_error_frees_only_nonzero_capacity(self):
        err = ("err", t.RMP_OK_TAG + 1, 5, 6, 0, t.VEC + 0x200, 0)
        tr, rv, _ = t.route_model(b"a.rmp", rep(rmp=err))
        self.assertEqual([c[0] for c in tr], ["components", "ext_eq", "rmp_serialize", "drop_rmp_err"])
        self.assertEqual(rv, 0x7001)
        err = ("err", t.RMP_OK_TAG + 1, 5, 6, 0x30, t.VEC + 0x200, 0)
        tr, _, _ = t.route_model(b"a.rmp", rep(rmp=err))
        self.assertEqual(tr[3], ("free_rmp_err", t.VEC + 0x200, 0x30, 0))

    def test_json_int_min_capacity_takes_error_drop(self):
        tr, rv, labels = t.route_model(b"a.json", rep(comp=("N", b"a.json"), json=("ok", t.INT_MIN, 9, 3)))
        self.assertIn("jo", labels)
        self.assertEqual(tr[-1][0], "drop_json_err")
        self.assertEqual(rv, 0x7001)

    def test_alloc_failure_does_not_return(self):
        tr, rv, _ = t.route_model(b"a.json", rep(comp=("N", b"a.json"), alloc=0))
        self.assertEqual((tr[-1], rv), (("alloc_error", 1, 0x80), "noreturn"))

    def test_write_skipped_when_parent_check_fails_and_value_survives_free(self):
        tr, rv, _ = t.route_model(b"a.json", rep(comp=("N", b"a.json"), chk=0x5005))
        self.assertEqual([c[0] for c in tr][-3:], ["json_serialize", "parent_check", "free_after_write"])
        self.assertEqual(rv, 0x5005)
        tr, rv, _ = t.route_model(b"a.json", rep(comp=("N", b"a.json")))
        self.assertEqual(rv, 0x6001)
        self.assertIn("file_write", [c[0] for c in tr])


class ByteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = t.Binary()

    def test_copy_table_is_uniform(self):
        t.check_role_table(self.binary)
        self.assertEqual(len(t.COPIES), 10)

    def test_every_copy_matches_model(self):
        for ci, start in enumerate(t.COPIES):
            for i, path, r in t.case_stream(ci):
                if i >= 120:
                    break
                good, _, got, rv = t.agree(self.binary, start, path, r)
                self.assertTrue(good, (hex(start), i, path, got, rv))

    def test_model_mutants_are_detected(self):
        probes = []
        for i, path, r in t.case_stream(3):
            if i >= t.PROBE_CASES:
                break
            _, _, got, rv = t.agree(self.binary, t.COPIES[3], path, r)
            probes.append((path, r, got, rv))
        for mut in t.mutant_models():
            self.assertTrue(t.mutant_detected(probes, mut), mut)
        self.assertFalse(t.mutant_detected(probes, "no_such_mutation"))

    def test_byte_damage_is_detected(self):
        patches = t.build_patch_set(self.binary, t.COPIES[3])
        self.assertGreaterEqual(len(patches), 10)
        for patch in patches:
            self.assertTrue(t.patch_detected(self.binary, t.COPIES[3], patch), patch[0])
        # the damage is undone after each probe
        self.assertTrue(t.agree(self.binary, t.COPIES[3], b"a.rmp", rep())[0])

    def test_range_controls(self):
        for name, detected in t.environment_controls(self.binary):
            self.assertTrue(detected, name)

    def test_wrong_digest_is_refused(self):
        saved = t.NODE_SHA256
        t.NODE_SHA256 = "0" * 64
        try:
            with self.assertRaises(t.ToolError):
                t.Binary()
        finally:
            t.NODE_SHA256 = saved


class EvidenceTests(unittest.TestCase):
    def test_generation_is_reproducible_and_matches_committed_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "x"
            measure = t.generate(out)
            self.assertGreaterEqual(measure["cases"], 10000)
            self.assertGreaterEqual(measure["negative_controls"], 30)
            self.assertEqual(measure["negative_detected"], measure["negative_controls"])
            self.assertEqual(json.loads((out / "measure.json").read_text()), measure)
            if WORK.is_dir():
                for f in sorted(out.iterdir()):
                    self.assertEqual(f.read_bytes(), (WORK / f.name).read_bytes(), f.name)


if __name__ == "__main__":
    unittest.main()
