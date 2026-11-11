import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import evm_create_opcodes_115 as tool  # noqa: E402

IMAGE = tool.Image(tool.BINARY.read_bytes())
EXT = tool.extents(IMAGE)
SH = tool.Shell(IMAGE)
tool._SHELL[0] = SH
MACH = tool.Machine(IMAGE)


def real(c, override=None):
    return tool.run_handler(SH, tool.Machine(IMAGE) if override else MACH, c, tool.HANDLERS[c["fam"]][c["kind"]], override)


def base_case(kind="create", fam="AB", **kw):
    c = tool.make_case(0)
    c.update(kind=kind, fam=fam, mode=-1, static=0, spec=14, gas=1 << 40, mem_words=0, mem_cost=0, base=0, cell_len=0,
             cell_cap=tool.MEMSZ, flag=0, odd=0, alloc_fail=0, c200=0, c208=0, c210=0, c218=0, c265=0, c268=14,
             c48=6, c60=2, c68=32000, c70=64, c168=0, c50=3, c58=512, r190=0, r198=0, pend_tag=tool.NO_PENDING,
             pend_b8=0, pend_c0=0, pend_c8=0, membuf=b"")
    n = 4 if kind == "create2" else 3
    c["length"], c["offset"] = 64, 0
    c["stack"] = ([7] if kind == "create2" else []) + [64, 0, 5]
    c.update(kw)
    return c


class StaticEvidence(unittest.TestCase):
    def test_binary_digest(self):
        self.assertEqual(tool.SHA256, "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
        with self.assertRaises(tool.ToolError):
            tool.Image(IMAGE.data[:-1] + bytes([IMAGE.data[-1] ^ 1]))

    def test_tables_and_extents(self):
        tool.static_checks(IMAGE, EXT)
        for table in tool.TABLES.values():
            self.assertIn(IMAGE.word(table + 8 * 0xf0), {0x4338c10, 0x4f07ae0})
            self.assertIn(IMAGE.word(table + 8 * 0xf5), {0x4339270, 0x4f07460})

    def test_decode_covers_every_byte(self):
        for f in tool.ALL_FUNCS:
            rows = tool.sweep(IMAGE, f, EXT[f])
            self.assertEqual(sum(fm["len"] for _, fm in rows), EXT[f] - f)

    def test_corrupted_extent_is_refused(self):
        saved = tool.SIZES["AB"]["create"]
        tool.SIZES["AB"]["create"] = saved + 1
        try:
            with self.assertRaises(tool.ToolError):
                tool.static_checks(IMAGE, EXT)
        finally:
            tool.SIZES["AB"]["create"] = saved


class Reconstruction(unittest.TestCase):
    def check(self, c, mut=frozenset()):
        got, want = real(c), tool.model_handler(c, SH, mut)
        return got, want, tool.diff(got, want)

    def test_cases_match_machine_code(self):
        for k in range(0, 4000, 11):
            c = tool.make_case(k)
            got, want, d = self.check(c)
            self.assertEqual(d, [], f"case {k}")

    def test_resize_cases_match_machine_code(self):
        for k in range(0, 600, 13):
            c = tool.make_resize_case(k)
            got = tool.run_resize(SH, MACH, c)
            self.assertEqual(tool.diff(got, tool.model_resize(c, SH, c["words"])), [], f"case {k}")

    def test_status_bytes(self):
        for kind in ("create", "create2"):
            for fam in ("AB", "C"):
                ok = self.check(base_case(kind, fam))
                self.assertEqual(ok[0]["status"], 4)
                self.assertEqual(ok[2], [])
                self.assertEqual(self.check(base_case(kind, fam, static=1))[0]["status"], 0x28)
                self.assertEqual(self.check(base_case(kind, fam, stack=[1, 2]))[0]["status"], 0x2c)
                self.assertEqual(self.check(base_case(kind, fam, stack=([1] if kind == "create2" else []) + [1 << 64, 0, 5]))[0]["status"], 0x24)
                self.assertEqual(self.check(base_case(kind, fam, gas=0))[0]["status"], 0x20)
        self.assertEqual(self.check(base_case("create2", "AB", spec=4))[0]["status"], 0x2b)
        self.assertEqual(self.check(base_case("create", "AB", spec=4))[0]["status"], 4)

    def test_initcode_limit(self):
        c = base_case("create", "C", spec=14, stack=[0xc000 + 0x4000 + 1, 0, 5], length=0x10001)
        self.assertEqual(self.check(c)[0]["status"], 0x35)
        c = base_case("create", "C", spec=13, c268=13, stack=[0xc000 + 1, 0, 5], length=0xc001)
        self.assertEqual(self.check(c)[0]["status"], 0x35)
        c = base_case("create", "AB", spec=14, c210=1, c218=100, stack=[101, 0, 5], length=101)
        self.assertEqual(self.check(c)[0]["status"], 0x35)
        c = base_case("create", "AB", spec=14, c210=1, c218=100, stack=[100, 0, 5], length=100)
        self.assertEqual(self.check(c)[0]["status"], 4)

    def test_forwarded_gas(self):
        for fam in ("AB", "C"):
            got, want, d = self.check(base_case("create", fam, gas=100000 + 64 * 5, c68=0, c60=0, c50=0))
            self.assertEqual(d, [])
            self.assertEqual(got["gas"], (100000 + 64 * 5 - 0) // 64)

    def test_pending_replacement(self):
        for fam in ("AB", "C"):
            for pend in (dict(pend_tag=0, pend_b8=0), dict(pend_tag=0, pend_b8=1, pend_c0=tool.ARCBOX, arc_cnt=1, arc_vt=1),
                         dict(pend_tag=0, pend_b8=2, pend_c0=tool.PBOX), dict(pend_tag=1, pend_b8=tool.FAKEVT, pend_c0=3, pend_c8=4)):
                c = base_case("create2", fam, **dict(dict(box_30=11, box_38=12, arc_58=1, arc_60=2, arc_cnt=1, arc_vt=1), **pend))
                got, want, d = self.check(c)
                self.assertEqual(d, [])
                self.assertEqual(got["pend"][0], 2)
                self.assertEqual(got["pend"][2], 0)


class NegativeControls(unittest.TestCase):
    def test_model_mutants_are_detected(self):
        ks = list(range(0, 1500))
        cases = [tool.make_case(k) for k in ks]
        reals = [tool.digest(real(c)) for c in cases]
        for scope, name, _ in tool.MODEL_MUTANTS:
            if scope != "main":
                continue
            hit = any(tool.digest(tool.model_handler(c, SH, frozenset((name,)))) != r for c, r in zip(cases, reals))
            self.assertTrue(hit, name)

    def test_corrupted_code_bytes_are_detected(self):
        f = tool.HANDLERS["AB"]["create"]
        sites = [s for s in tool.code_sites(IMAGE, EXT) if s[0] == f]
        self.assertGreaterEqual(len(sites), 3)
        pool = [c for c in (tool.make_case(k) for k in range(400)) if tool.HANDLERS[c["fam"]][c["kind"]] == f]
        for _, what, at, newbyte in sites[:3]:
            found = False
            for c in pool:
                want = tool.digest(real(c))
                m = tool.Machine(IMAGE)
                try:
                    got = tool.digest(tool.run_handler(SH, m, c, f, override={at: newbyte}))
                except tool.ToolError:
                    found = True
                    break
                if got != want:
                    found = True
                    break
            self.assertTrue(found, what)

    def test_out_of_range_inputs_are_refused(self):
        with self.assertRaises(tool.ToolError):
            tool.run_handler(SH, tool.Machine(IMAGE), base_case(), tool.HANDLERS["AB"]["create"] + 3)
        with self.assertRaises(tool.ToolError):
            IMAGE.read(0x1, 8)
        with self.assertRaises(tool.ToolError):
            IMAGE.code(0x10, 4)

    def test_tamper_is_not_equal_to_model(self):
        c = base_case("create", "AB")
        got = real(c)
        wrong = tool.model_handler(dict(c, gas=c["gas"] - 1), SH)
        self.assertNotEqual(tool.diff(got, wrong), [])


class Generation(unittest.TestCase):
    def test_measure_file_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "x"
            old = (tool.N_MAIN, tool.N_RESIZE, tool.CTL_MAIN, tool.CTL_RESIZE)
            tool.N_MAIN, tool.N_RESIZE, tool.CTL_MAIN, tool.CTL_RESIZE = 600, 100, 600, 100
            try:
                summary = tool.generate(out)
            finally:
                tool.N_MAIN, tool.N_RESIZE, tool.CTL_MAIN, tool.CTL_RESIZE = old
            self.assertEqual(summary["mismatches"], 0)
            m = json.loads((out / "measure.json").read_text())
            self.assertGreaterEqual(m["negative_controls"], m["negative_detected"])
            self.assertEqual(m["cases"], 700)


if __name__ == "__main__":
    unittest.main()
