import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re16_state_writer115 as tool  # noqa: E402

mat = tool.mat
WORK = ROOT / "research" / "work-items" / "RE-016-state-writer-115"


class StateWriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = mat.Image(mat.BINARY.read_bytes())

    def test_every_unit_matches_the_models(self):
        for fn in tool.ENDS:
            n, bad, classes, _ = tool.evaluate(self.image, fn, 250)
            self.assertEqual((n, bad), (250, 0), tool.NAMEOF[fn])
            self.assertGreaterEqual(len(classes), 2)

    def test_devnull_shortcut_is_exact(self):
        s = mat.Stream("devnull-test")
        base = tool.writer_case(s, 0)
        for fn in (tool.WA, tool.WB):
            for path, short in ((tool.DEVNULL, True), (b"/dev/nulL", False), (b"/dev/nul", False), (b"/dev/null0", False)):
                c = dict(base, path=path, tag=9, norm=b"x.json")
                want = tool.expected(fn, c)
                m = tool.EqTrace(self.image)
                got = tool.run_case(m, fn, c)
                self.assertTrue(tool.compare(fn, want, got))
                self.assertEqual(got["calls"] == [], short)

    def test_extension_rule(self):
        for norm, rmp in ((b"s.rmp", True), (b"s.RMP", True), (b"s.rMp", True), (b".rmp", False), (b"..", False),
                          (b"s.rm", False), (b"s.rmpx", False), (b"a.rmp.json", False), (b"rmp", False), (b"", False)):
            c = tool.writer_case(mat.Stream("ext-test"), 5)
            c.update(path=b"/p", norm=norm, tag=9)
            ev, _ = tool.model_writer(c, tool.WA)
            self.assertEqual("rmp_ser" in [e[0] for e in ev], rmp, norm)

    def test_wrappers_follow_the_class_table(self):
        c = tool.err_case(mat.Stream("wrap-test"), 0, False)
        for word, events in ((tool.MIN64 + 2, ["ctx"]), (tool.MIN64, ["ctx", "drop_inner"]), (0, ["ctx"]), (7, ["ctx", "dealloc"]),
                             (tool.MIN64 + 5, ["ctx", "dealloc"]), (tool.M64, ["ctx", "dealloc"])):
            c["err"][0], c["got"] = word, 0
            self.assertEqual([e[0] for e in tool.model_wrap(c, False)[0]], events, hex(word))

    def test_struct_serializer_stops_at_first_failure(self):
        c = tool.ser_case(mat.Stream("ser-test"), 0)
        c.update(flag=1, hdr=(2, 0), names=[(2, 0)] * 3, subs=[(tool.OKW, 1, 2)] * 3, vecs=[(0, 1, 0)] * 3)
        ev, out, _ = tool.model_ser(c, tool.FRAME[tool.SER], ("args", 0), 0, (0, 1, 0))
        self.assertEqual([e[0] for e in ev], ["hdr_named", "name", "sub", "name", "sub", "name", "sub"])
        self.assertEqual(out[0], tool.OKW)
        c["names"][1] = (5, 9)
        ev, out, _ = tool.model_ser(c, tool.FRAME[tool.SER], ("args", 0), 0, (0, 1, 0))
        self.assertEqual([e[0] for e in ev], ["hdr_named", "name", "sub", "name"])
        self.assertEqual(out, (tool.MIN64, 5, 9))
        c["flag"] = 0
        ev, _, _ = tool.model_ser(c, tool.FRAME[tool.SER], ("args", 0), 0, (0, 1, 0))
        self.assertEqual([e[0] for e in ev], ["hdr_plain", "sub", "sub", "sub"])

    def test_precheck_and_context_builder_rules(self):
        c = tool.pre_case(mat.Stream("pre-test"), 0)
        c.update(path=b"/a", tag=6, look=0, ex=0x100, mk=0)
        ev, ret = tool.model_pre(c)
        self.assertEqual([e[0] for e in ev], ["resolve", "exists", "mkdir"])    # only al is tested: 0x100 is "missing"
        self.assertEqual(ret, 0)
        c.update(tag=9, ex=1)
        self.assertEqual([e[0] for e in tool.model_pre(c)[0]], ["resolve", "lookup", "exists"])
        c.update(tag=7, ex=1, look=5, conv=(1, 9, 9))
        ev, _ = tool.model_pre(c)
        self.assertEqual(ev[-1], ("exists", ("path", 0), ("abs", 2)))
        c.update(conv=(2, 0x55, 4))
        self.assertEqual(tool.model_pre(c)[0][-1], ("exists", ("abs", 0x55), ("abs", 4)))
        self.assertEqual(tool.model_ctxb({"a": 7, "b": 9, "wrapret": 3})[0], [("tail", ("abs", 7), ("abs", 4))])
        self.assertEqual([e[0] for e in tool.model_ctxb({"a": 7, "b": 8, "wrapret": 3})[0]], ["fmt", "wrap"])

    def test_model_mutants_are_detected(self):
        for fn, names in tool.MODEL_MUTANTS.items():
            for name in names:
                n, bad, _, _ = tool.evaluate(self.image, fn, 400, mut=frozenset([name]), stop_on_first=True)
                self.assertGreater(bad, 0, f"{tool.NAMEOF[fn]}:{name}")

    def test_code_byte_mutants_are_detected(self):
        for fn, va, old, new, what in tool.BYTE_MUTANTS[::5]:
            self.assertEqual(self.image.code(va, 1)[0], old)
            n, bad, _, _ = tool.evaluate(self.image, fn, 400, override={va: new}, stop_on_first=True)
            self.assertGreater(bad, 0, what)

    def test_corrupt_inputs_are_rejected(self):
        corrupt = bytearray(self.image.data)
        corrupt[self.image.text["offset"] + 7] ^= 1
        with self.assertRaises(tool.ToolError):
            mat.Image(bytes(corrupt))
        with self.assertRaises(tool.ToolError):
            self.image.code(self.image.text["address"] + self.image.text["size"] + 0x100, 4)
        with self.assertRaises(tool.ToolError):
            self.image.read(0x7fff_ffff_f000, 3)

    def test_static_evidence_matches_the_binary(self):
        info, calls, _ = tool.static_evidence(self.image)
        self.assertEqual(set(info["functions"]), {f"{fn:#x}" for fn in tool.ENDS})
        self.assertEqual(info["functions"]["0x422ed40"]["fde_bytes"], 740)
        self.assertEqual(info["functions"]["0x422f030"]["fde_bytes"], 740)
        roles = {r["target"]: r["role"] for r in calls}
        self.assertEqual(roles["0x38c20b0"], "struct3")
        self.assertEqual(roles["0x159fca0"], "eq_ignore_ascii_case")
        self.assertEqual(info["functions"]["0x15020f0"]["fde_bytes"], 210)
        self.assertEqual(info["functions"]["0x43034f0"]["fde_bytes"], 58)

    def test_generated_evidence_is_reproducible(self):
        self.assertTrue(WORK.is_dir())
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "out"
            summary = tool.generate(out)
            self.assertEqual(summary["mismatches"], 0)
            self.assertEqual(summary["negative_controls"]["total"], summary["negative_controls"]["detected"])
            for path in sorted(out.iterdir()):
                self.assertEqual(path.read_bytes(), (WORK / path.name).read_bytes(), path.name)
            self.assertEqual(json.loads((out / "measure.json").read_text())["cases"], summary["cases"])


if __name__ == "__main__":
    unittest.main()
