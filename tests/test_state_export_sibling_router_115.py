import filecmp
import itertools
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import state_export_sibling_router_115 as T  # noqa: E402

FOLDER = ROOT / "research/work-items/RE-009-state-export-sibling-router-115"
IMAGE = None


def image():
    global IMAGE
    if IMAGE is None:
        IMAGE = T.load_image()
        IMAGE.data = bytearray(IMAGE.data)
        T.UNIT_NAMES = T.read_unit_names(IMAGE)
    return IMAGE


def base(**kw):
    case = dict(path=b"/s/a.rmp", name=b"a.rmp", ctag=9, tag=1, rmp_calls=[(2, 0x11)], data=b"hello", cap=8, precap=0,
                flag=0, jerr=0, jecap=0x80, jcap=0x80, gcap=0, alloc_ok=True, conv_rc=77, parent_rc=0, write_rc=5, extra=3,
                kind="t")
    case.update(kw)
    if kw.get("flag") and "rmp_calls" not in kw:
        case["rmp_calls"] = [(2, 0x11)] * 3
    return case


def pair(body, **kw):
    case = base(**kw)
    if body == "C" and "rmp_calls" not in kw:
        case["rmp_calls"] = [(2, 0x11)] * (3 if case["flag"] else 2)
    got = T.outcome(image(), body, case)
    want = T.outcome(image(), body, case, machine=False)
    return got, want


class Router(unittest.TestCase):
    def test_digest_gate(self):
        old = T.SHA
        T.SHA = "0" * 64
        try:
            with self.assertRaises(T.ToolError):
                T.load_image()
        finally:
            T.SHA = old

    def test_dev_null_is_a_no_op(self):
        for body in "ABC":
            (ret, log), want = pair(body, path=b"/dev/null")
            self.assertEqual((ret, log), (0, []))
            self.assertEqual((ret, log), want)

    def test_near_dev_null_is_not(self):
        for path in (b"/dev/nul", b"/dev/nulL", b"/dev/null/", b"/dev/null2"):
            for body in "ABC":
                got, want = pair(body, path=path, name=b"x", ctag=0)
                self.assertEqual(got, want)
                self.assertEqual(got[1][0][0], "comp")

    def test_rmp_extension_selects_rmp_writer(self):
        for body in "ABC":
            (ret, log), want = pair(body)
            self.assertEqual((ret, log), want)
            names = [row[0] for row in log]
            self.assertNotIn("json", names)
            self.assertEqual(names[-3:], ["parent", "write", "dealloc"])
            self.assertEqual(log[-2][3], b"hello")
            self.assertEqual(log[-2][6], 3)
            self.assertEqual(ret, 5)

    def test_other_extensions_select_json(self):
        for name in (b"a.json", b"a.rmq", b"a.rmpx", b"a.", b".rmp", b"rmp", b"..", b"a.rmp.json"):
            for body in "ABC":
                got, want = pair(body, path=b"/s/" + name, name=name)
                self.assertEqual(got, want)
                self.assertIn("json", [row[0] for row in got[1]], (body, name))

    def test_extension_is_case_insensitive(self):
        for name in (b"a.RMP", b"a.RmP", b"x.rMP"):
            for body in "ABC":
                got, want = pair(body, path=b"/s/" + name, name=name)
                self.assertEqual(got, want)
                self.assertNotIn("json", [row[0] for row in got[1]])

    def test_component_tag_gate(self):
        for ctag in (0, 5, 8, 10, 0xff):
            for body in "ABC":
                got, want = pair(body, ctag=ctag)
                self.assertEqual(got, want)
                self.assertIn("json", [row[0] for row in got[1]])

    def test_parent_failure_skips_write(self):
        for body in "ABC":
            got, want = pair(body, parent_rc=9)
            self.assertEqual(got, want)
            self.assertEqual(got[0], 9)
            self.assertNotIn("write", [row[0] for row in got[1]])

    def test_rmp_failure_converts_error(self):
        for body in "ABC":
            got, want = pair(body, rmp_calls=[(5, 6)] if body != "C" else [(5, 6)])
            self.assertEqual(got, want)
            self.assertEqual(got[0], 77)
            self.assertEqual(got[1][-1][:2], ("errs", T.PATH))

    def test_vec_released_on_failure(self):
        for body in "ABC":
            got, want = pair(body, rmp_calls=[(5, 6)], precap=9)
            self.assertEqual(got, want)
            self.assertIn("dealloc", [row[0] for row in got[1]])

    def test_json_long_output_grows_only_in_sibling_a(self):
        got, want = pair("A", path=b"/s/a.json", name=b"a.json", data=bytes(range(200)))
        self.assertEqual(got, want)
        self.assertIn("grow", [row[0] for row in got[1]])
        got, want = pair("A", path=b"/s/a.json", name=b"a.json", data=bytes(0x80))
        self.assertEqual(got, want)
        self.assertNotIn("grow", [row[0] for row in got[1]])
        got, want = pair("A", path=b"/s/a.json", name=b"a.json", data=bytes(0x81))
        self.assertIn("grow", [row[0] for row in got[1]])

    def test_allocation_failure_halts(self):
        for body in "ABC":
            got, want = pair(body, path=b"/s/a.json", name=b"a.json", alloc_ok=False)
            self.assertEqual(got[0], "alloc-error")
            self.assertEqual(got, want)

    def test_capacity_overflow_panics(self):
        got, want = pair("B", path=b"/s/a.json", name=b"a.json", jcap=T.NEG)
        self.assertEqual(got, want)
        self.assertEqual(got[1][-1][0], "errp")
        got, want = pair("A", path=b"/s/a.json", name=b"a.json", data=bytes(300), gcap=T.NEG)
        self.assertEqual(got, want)
        self.assertEqual(got[1][-1][0], "errp")

    def test_enum_names_follow_jump_table(self):
        seen = set()
        for tag in range(4):
            got, want = pair("B", tag=tag)
            self.assertEqual(got, want)
            seen.add([row for row in got[1] if row[0] == "unit"][0][1])
        self.assertEqual(len(seen), 4)
        self.assertEqual(seen, set(T.UNIT_NAMES))

    def test_unit_name_pattern_check(self):
        img = image()
        va = T.read_unit_names.__globals__["struct"].unpack_from("<i", img.data, img.file_offset(0x91a3e4))[0] + 0x91a3e4
        off = img.file_offset(va)
        old = img.data[off]
        img.data[off] = 0
        try:
            with self.assertRaises(T.ToolError):
                T.read_unit_names(img)
        finally:
            img.data[off] = old

    def test_tag_outside_jump_table_is_refused(self):
        for tag in (4, 9, 0xff):
            case = base(tag=tag)
            with self.assertRaises(T.ToolError):
                T.outcome(image(), "B", case, machine=False)
            with self.assertRaises(Exception):  # the jump table has four entries; the bytes run off into other code
                T.outcome(image(), "B", case)

    def test_header_flag_adds_field_call_in_c(self):
        got0, want0 = pair("C", flag=0)
        got1, want1 = pair("C", flag=1)
        self.assertEqual((got0, got1), (want0, want1))
        self.assertNotIn(("rmp", "field"), got0[1])
        self.assertIn(("rmp", "field"), got1[1])

    def test_c_stage_failures(self):
        for flag, stage in itertools.product((0, 1), (0, 1, 2)):
            if stage > 1 + flag:
                continue
            calls = [(2, 0x11)] * stage + [(3, 4)]
            got, want = pair("C", flag=flag, rmp_calls=calls)
            self.assertEqual(got, want)
            self.assertEqual(got[1][-1][0], "errs")

    def test_mutated_models_are_caught(self):
        probes = list(itertools.islice(T.cases("A"), 0, None, 11))
        for mut in ("always-json", "case-sensitive", "dot-zero", "write-despite-parent", "no-overflow"):
            self.assertTrue(T.model_detects(image(), "A", probes, mut), mut)

    def test_corrupted_bytes_are_caught(self):
        probes = list(itertools.islice(T.cases("B"), 0, None, 11))
        img = image()
        for va, new, label in T.pattern_sites(img, "B"):
            self.assertTrue(T.byte_detects(img, "B", probes, va, new), label)

    def test_patch_restores_image(self):
        img = image()
        va = T.BODIES["A"]["entry"]
        off, old = T.patch(img, va, 0xcc)
        self.assertEqual(img.data[off], 0xcc)
        T.unpatch(img, off, old)
        self.assertEqual(img.data[off], old)

    def test_generators_are_deterministic(self):
        for body in "ABC":
            a = [(k, sorted((x, repr(y)) for x, y in c.items())) for k, c in itertools.islice(T.cases(body), 300)]
            b = [(k, sorted((x, repr(y)) for x, y in c.items())) for k, c in itertools.islice(T.cases(body), 300)]
            self.assertEqual(a, b)

    def test_sampled_cases_agree(self):
        for body in "ABC":
            for k, case in itertools.islice(T.cases(body), 0, 3000, 29):
                self.assertEqual(T.outcome(image(), body, case), T.outcome(image(), body, case, machine=False), (body, k))

    def test_committed_evidence_regenerates(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(T.main(["tool", "--out", tmp]), 0)
            names = sorted(p.name for p in Path(tmp).iterdir())
            self.assertEqual(names, sorted(p.name for p in FOLDER.iterdir() if p.name not in ("README.md", "MANIFEST.sha256")))
            for name in names:
                self.assertTrue(filecmp.cmp(Path(tmp) / name, FOLDER / name, shallow=False), name)


if __name__ == "__main__":
    unittest.main()
