import hashlib
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re009_state_export_nil_struct_115 as t  # noqa: E402

WORK = ROOT / "research" / "work-items" / "RE-009-state-export-nil-struct-115"


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.rm.Image(t.BINARY.read_bytes())
        cls.cases = {b: [t.make_case(b, k) for k in range(300)] for b in t.BODIES}
        cls.pool = [c for body in t.BODIES for c in cls.cases[body]]


class StaticFacts(Fixture):
    def test_extents_and_calls_are_known(self):
        rows = t.static_rows(self.image)
        t.check_static(self.image, rows)
        sizes = {r["name"]: r["end"] - r["start"] for r in rows}
        self.assertEqual(sizes["nil"], 536)
        self.assertEqual(sizes["struct"], 1542)
        self.assertEqual(sizes["data"], 704)
        self.assertEqual(sizes["keywriter"], 520)

    def test_unknown_import_slot_refused(self):
        with self.assertRaises(t.ToolError):
            t.check_static(self.image, [{"name": "x", "start": 0, "end": 1, "calls": [("got", 0x64dffff, 0)]}])

    def test_unknown_call_target_refused(self):
        with self.assertRaises(t.ToolError):
            t.check_static(self.image, [{"name": "x", "start": 0, "end": 1, "calls": [("c", 0x1234567, 0)]}])

    def test_shifted_body_address_refused(self):
        with self.assertRaises(t.ToolError):
            t.sweep_body(self.image, t.NIL + 4)

    def test_damaged_binary_refused(self):
        with self.assertRaises(t.ToolError):
            t.rm.Image(self.image.data[:-1])
        bad = bytearray(self.image.data)
        bad[0x1000] ^= 1
        with self.assertRaises(t.ToolError):
            t.rm.Image(bytes(bad))


class ModelAgainstBytes(Fixture):
    def test_models_match_machine(self):
        _, misses = t.evaluate(self.image, self.pool)
        self.assertEqual(misses, [])

    def test_each_model_mutant_is_detected(self):
        results, misses = t.evaluate(self.image, self.pool)
        self.assertEqual(misses, [])
        for mut in t.MODEL_MUTANTS:
            if mut in t.EQUIVALENT:
                continue
            hit = any(t.compare(t.run_model(self.image, c["body"], c, frozenset([mut])), got)
                      for c, (_, got) in zip(self.pool, results))
            self.assertTrue(hit, mut)

    def test_dotdot_mutant_is_equivalent(self):
        results, _ = t.evaluate(self.image, self.pool)
        for c, (_, got) in zip(self.pool, results):
            self.assertIsNone(t.compare(t.run_model(self.image, c["body"], c, frozenset(["no-dotdot"])), got))

    def test_two_byte_names_never_select_rmp(self):
        case = dict(t.make_case("nil", 0), comp="whole")
        for hi in range(256):
            for lo in range(256):
                name = bytes((hi, lo))
                env = t.Env(case, t.ModelMem(self.image, name))
                self.assertEqual(t.model_front(env, t.PATH_AT, 2, frozenset()), "json")

    def test_dev_null_is_a_no_op(self):
        for body in t.BODIES:
            c = dict(t.make_case(body, 1), path=b"/dev/null", comp="auto", fail_at=0)
            want = t.run_model(self.image, body, c)
            self.assertEqual(want["rax"], 0)
            self.assertEqual(want["log"], [])
            _, misses = t.evaluate(self.image, [c])
            self.assertEqual(misses, [])

    def test_rmp_and_json_selection(self):
        for body in t.BODIES:
            for path, kind in ((b"a/x.rmp", "rmp"), (b"a/x.RMP", "rmp"), (b"a/x.json", "json"), (b"a/.rmp", "json"),
                               (b"a/x.rmpx", "json"), (b"a/noext", "json"), (b"a/x.rmp/", "rmp")):
                c = dict(t.make_case(body, 3), path=path, comp="auto", fail_at=0)
                env = t.Env(c, t.ModelMem(self.image, path))
                self.assertEqual(t.model_front(env, t.PATH_AT, len(path), frozenset()), kind, (body, path))

    def test_nil_bytes(self):
        c = dict(t.make_case("nil", 5), path=b"a/x.rmp", comp="auto", fail_at=0, ensure_rc=0, write_rc=0)
        want = t.run_model(self.image, "nil", c)
        write = [e for e in want["log"] if e[0] == "write"][0]
        self.assertEqual(write[3], b"\xc0")
        c = dict(c, path=b"a/x.json")
        write = [e for e in t.run_model(self.image, "nil", c)["log"] if e[0] == "write"][0]
        self.assertEqual(write[3], b"null")

    def test_ensure_failure_skips_the_write(self):
        c = dict(t.make_case("nil", 6), path=b"a/x.rmp", comp="auto", fail_at=0, ensure_rc=0x77, write_rc=0)
        want = t.run_model(self.image, "nil", c)
        self.assertEqual(want["rax"], 0x77)
        self.assertEqual([e[0] for e in want["log"]], ["next_back", "malloc", "ensure", "free"])


class BytePatches(Fixture):
    def test_flipped_branches_are_detected(self):
        rows = t.static_rows(self.image)
        trace = set()
        t.evaluate(self.image, self.pool, trace=trace)
        for name in t.BODIES:
            sites = [s for s in t.byte_sites(self.image, rows)
                     if s[0] == name and s[1] in trace and f"{name}:{s[1]:#x}" not in t.EQUIVALENT]
            self.assertGreater(len(sites), 10)
            for _, insn, at, new in sites[:8]:
                _, miss = t.evaluate(self.image, self.cases[name], {at: new}, stop_on_first=True)
                self.assertTrue(miss, (name, hex(insn)))

    def test_constant_patches_are_detected(self):
        rows = t.static_rows(self.image)
        sites = t.immediate_sites(self.image, rows)
        self.assertGreaterEqual(len(sites), 4)
        for name, insn, at, new, label in sites:
            _, miss = t.evaluate(self.image, self.cases[name], {at: new}, stop_on_first=True)
            self.assertTrue(miss, (name, label))


class Evidence(unittest.TestCase):
    def test_manifest_lists_every_file(self):
        names = sorted(p.name for p in WORK.iterdir() if p.name != "MANIFEST.sha256")
        rows = [line.split("  ") for line in (WORK / "MANIFEST.sha256").read_text().splitlines()]
        self.assertEqual(sorted(r[1] for r in rows), names)
        for digest, name in rows:
            self.assertEqual(hashlib.sha256((WORK / name).read_bytes()).hexdigest(), digest, name)

    def test_regenerated_evidence_is_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "out"
            summary = t.generate(out)
            self.assertEqual(summary["mismatches"], 0)
            self.assertEqual(summary["controls_live"], summary["controls_detected"])
            for p in sorted(out.iterdir()):
                self.assertEqual(p.read_bytes(), (WORK / p.name).read_bytes(), p.name)


if __name__ == "__main__":
    unittest.main()
