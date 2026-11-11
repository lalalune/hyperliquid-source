"""Tests for tools/evm_wei_user_record_115.py (node #115 (wei, user) record encoders: rmp x2 families + JSON).

The binary must be present; nothing here is skipped. The tool never executes the binary.
"""
import hashlib
import pathlib
import shutil
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import evm_wei_user_record_115 as t  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "evm-wei-user-record-encoders-115"
GENERATED = ("bodies.tsv", "callees.tsv", "cases-sample.tsv", "controls.tsv", "fields.tsv", "stubs.tsv",
             "summary.json", "unreached.tsv")
FAMS = ("a", "b")
JSON = t.FAMILY_BODIES["a"]["json"]


class Shared:
    image = None
    ext = None

    @classmethod
    def load(cls):
        if cls.image is None:
            data = t.BINARY.read_bytes()
            assert hashlib.sha256(data).hexdigest() == t.SHA256
            cls.image = t.Image(data)
            cls.ext = t.extents(cls.image)
        return cls


def body(fam, kind):
    return t.FAMILY_BODIES[fam][kind]


def make_case(va, flag=1, cap_slack=200, prefix=b"", fault=-1, base=0, indent=b"  ", cur=0, has_in=0, extra=0):
    """A hand-built case: records filled with a byte ramp, ok words for every stub call except `fault`."""
    st = bytearray((i * 7 + 3) & 0xff for i in range(t.ST_SIZE))
    c = {"body": va, "k": 1, "st": st, "base": base, "comp": bytearray(0x30), "svec": bytearray(0x18),
         "ser": bytearray(0x10), "flag": flag, "prefix": prefix, "cap": len(prefix) + cap_slack, "extra": extra,
         "fault": -1, "plan": [], "okplan": []}
    if t.KIND_OF[va] == "json":
        c.update({"jser": bytearray(range(0x28)), "indent": indent, "cur": cur, "has_in": has_in})
    s = t.Stream("test-case")
    for _ in range(64):
        calls = t.model(c)[0]
        if len(calls) <= len(c["plan"]):
            break
        for rec in calls[len(c["plan"]):]:
            ok, bad = t.plan_words(s, t.ROLE_KIND[rec[0]])
            c["okplan"].append(ok)
            c["plan"].append(bad)
    c["fault"] = fault
    return c


def run(c, mut=frozenset(), override=None):
    s = Shared.load()
    m = t.machine(s.image, override)
    got = t.run_case(m, c)
    return got, t.compare(c, t.model(c, mut), got)


class GeneratedFiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="evm-wei-user-record-"))
        cls.summary = t.generate(cls.tmp / "out")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_regenerated_files_equal_committed(self):
        for name in GENERATED:
            with self.subTest(name=name):
                self.assertEqual((self.tmp / "out" / name).read_bytes(), (PACKET / name).read_bytes())

    def test_manifest_lists_every_file(self):
        rows = {}
        for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ", 1)
            rows[name] = digest
        files = sorted(p.name for p in PACKET.iterdir() if p.name != "MANIFEST.sha256")
        self.assertEqual(sorted(rows), files)
        for name, digest in rows.items():
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)

    def test_summary_scale(self):
        s = self.summary
        self.assertEqual(s["binary_sha256"], t.SHA256)
        self.assertEqual(s["mismatches"], 0)
        self.assertEqual(s["cases"], 22000)
        self.assertEqual(s["bodies"], 5)
        self.assertGreaterEqual(s["controls"], 30)
        self.assertEqual(s["controls"], s["controls_detected"])
        self.assertEqual(s["model_mutants"], len(t.MODEL_MUTANTS))
        self.assertEqual(s["equivalent_sites_excluded"], 2)

    def test_unreached_instructions_are_explained(self):
        rows = (self.tmp / "out" / "unreached.tsv").read_text().splitlines()[1:]
        self.assertFalse(any(r.endswith("unexplained") for r in rows))
        in_bodies = [r for r in rows if int(r.split("\t")[0], 16) in t.BODIES]
        self.assertEqual({int(r.split("\t")[0], 16) for r in in_bodies}, {JSON})
        self.assertEqual(self.summary["body_instructions"] - self.summary["body_instructions_reached"],
                         len(in_bodies))

    def test_every_body_has_ok_and_error_cases(self):
        for va, d in self.summary["per_body"].items():
            with self.subTest(body=va):
                self.assertGreater(d["ok"], 0)
                self.assertGreater(d["error"], 0)
                if t.KIND_OF[int(va, 16)] == "ser":
                    self.assertEqual(d["reserve_calls"], 0)  # the rmp writers own the Vec there
                else:
                    self.assertGreater(d["reserve_calls"], 0)
                if int(va, 16) == JSON:
                    self.assertGreater(d["panic"], 0)
                else:
                    self.assertGreater(d["flag_one"], 0)
                    self.assertGreater(d["flag_zero"], 0)
                    self.assertGreater(d["flag_other"], 0)


class StaticChecks(unittest.TestCase):
    def setUp(self):
        Shared.load()

    def rows(self, image=None):
        return {va: t.body_row(image or Shared.image, Shared.ext, va) for va in t.CODE}

    def test_static_facts_hold(self):
        t.check_static(self.rows())

    def test_fde_extents(self):
        sizes = {va: Shared.ext[va] - va for va in t.CODE}
        for fam in FAMS:
            self.assertEqual(sizes[body(fam, "vec")], 474)
            self.assertEqual(sizes[body(fam, "ser")], 301)
        self.assertEqual(sizes[JSON], 453)
        self.assertEqual([sizes[t.HELPERS[k]] for k in ("key", "escape", "end")], [520, 552, 311])

    def test_key_texts_from_rodata(self):
        rows = self.rows()
        for va in (body("a", "ser"), body("b", "ser"), JSON):
            self.assertEqual([n for _, _, n in rows[va]["names"]], ["wei", "user"])
        # the two ser copies take "wei" from different .rodata pools, "user" from the same one
        a = rows[body("a", "ser")]["names"]
        b = rows[body("b", "ser")]["names"]
        self.assertNotEqual(a[0][1], b[0][1])
        self.assertEqual(a[1][1], b[1][1])

    def test_inline_names_are_split_immediates(self):
        for fam in FAMS:
            self.assertEqual([n for _, n in self.rows()[body(fam, "vec")]["inline"]], ["i", "we", "user"])

    def test_wrong_digest_rejected(self):
        data = bytearray(t.BINARY.read_bytes()[:4096])
        with self.assertRaises(t.ToolError):
            t.Image(bytes(data))

    def test_changed_callee_breaks_static_check(self):
        """Redirect the U256 value call of the family-b inline-Vec body: check_static must fail."""
        data = bytearray(Shared.image.data)
        site = next(v for v, how, tgt, role in self.rows()[body("b", "vec")]["calls"] if role == "u256_vec")
        _, off = Shared.image.section_of(site)
        data[off + 1] ^= 0x10
        img = t.Image(bytes(data), check=False)
        with self.assertRaises(t.ToolError):
            t.check_static(self.rows(img))

    def test_changed_header_or_breaks_static_check(self):
        data = bytearray(Shared.image.data)
        va = body("a", "vec")
        code = Shared.image.code(va, Shared.ext[va] - va)
        at = code.index(bytes.fromhex("4080cd82"))  # or bpl, 0x82
        _, off = Shared.image.section_of(va + at)
        data[off + 3] = 0x86
        img = t.Image(bytes(data), check=False)
        with self.assertRaises(t.ToolError):
            t.check_static(self.rows(img))

    def test_out_of_range_start_rejected(self):
        with self.assertRaises(t.ToolError):
            t.fde_rows(Shared.image, {body("a", "vec") + 1})

    def test_code_outside_text_rejected(self):
        with self.assertRaises(t.ToolError):
            Shared.image.code(0x10, 4)

    def test_nobits_read_rejected(self):
        bss = next(s for s in Shared.image.secs if s["name"] == ".bss")
        with self.assertRaises(t.ToolError):
            Shared.image.read(bss["address"] + 8, 8)


class RmpBehavior(unittest.TestCase):
    def test_marker_rule(self):
        self.assertEqual(t.vec_marker(0), 0x92)
        self.assertEqual(t.vec_marker(1), 0x82)
        self.assertEqual(t.vec_marker(2), 0xb2)
        self.assertEqual(t.vec_marker(0x11), 0x82)
        self.assertEqual(t.vec_marker(0x10), 0x92)
        self.assertEqual(t.vec_marker(0xff), 0xe2)

    def test_vec_flag_one_writes_inline_names(self):
        for fam in FAMS:
            with self.subTest(fam=fam):
                got, why = run(make_case(body(fam, "vec"), 1, base=t.RECORD))
                self.assertIsNone(why)
                self.assertEqual(got["buf"], b"\x82\xa3wei\xa4user")
                self.assertEqual([r[0] for r in got["calls"]], ["u256_vec", "b160_vec"])
                self.assertEqual(got["calls"][0][2], ("S", t.RECORD))
                self.assertEqual(got["calls"][1][2], ("S", t.RECORD + 0x20))

    def test_vec_flag_zero_and_other_flags(self):
        for flag, want in ((0, b"\x92"), (2, b"\xb2"), (0x11, b"\x82"), (0x80, b"\x92")):
            with self.subTest(flag=flag):
                got, why = run(make_case(body("a", "vec"), flag))
                self.assertIsNone(why)
                self.assertEqual(got["buf"], want)

    def test_vec_reserve_rules(self):
        for slack, want in ((0, [("vec_reserve", 0, 1), ("vec_reserve", 1, 1), ("vec_reserve", 2, 3)]),
                            (2, [("vec_reserve", 2, 3)]),
                            (3, [("vec_reserve", 2, 3)]),
                            (5, [("vec_reserve", 5, 1)]),
                            (10, [])):
            with self.subTest(slack=slack):
                got, why = run(make_case(body("a", "vec"), 1, cap_slack=slack))
                self.assertIsNone(why)
                res = [r for r in got["calls"] if r[0] == "vec_reserve"]
                self.assertEqual(res[:len(want)], want)

    def test_ser_flag_rules(self):
        for fam in FAMS:
            for flag, hdr, names in ((1, "map_hdr", [b"wei", b"user"]), (2, "map_hdr", []), (0, "arr_hdr", [])):
                with self.subTest(fam=fam, flag=flag):
                    got, why = run(make_case(body(fam, "ser"), flag))
                    self.assertIsNone(why)
                    self.assertEqual(got["calls"][0], (hdr, "stk", "ser", 2))
                    self.assertEqual([r[2] for r in got["calls"] if r[0] == "ser_str"], names)

    def test_header_error_is_wrapped(self):
        c = make_case(body("a", "ser"), 1, fault=0)
        got, why = run(c)
        self.assertIsNone(why)
        w = c["plan"][0]
        self.assertEqual(got["result"], t.result_bytes((t.ERR_TAG, w[0], w[1])))

    def test_str_error_is_wrapped_from_rax_rdx(self):
        c = make_case(body("b", "ser"), 1, fault=3)
        got, why = run(c)
        self.assertIsNone(why)
        w = c["plan"][3]
        self.assertEqual(got["result"], t.result_bytes((t.ERR_TAG, w[0], w[1])))
        self.assertEqual(len(got["calls"]), 4)

    def test_nested_error_is_passed_through(self):
        c = make_case(body("b", "vec"), 0, fault=0)
        got, why = run(c)
        self.assertIsNone(why)
        self.assertEqual(got["result"], t.result_bytes(tuple(c["plan"][0])))
        self.assertEqual(len(got["calls"]), 1)

    def test_success_writes_only_word_zero(self):
        for kind in ("vec", "ser"):
            with self.subTest(kind=kind):
                got, why = run(make_case(body("a", kind), 1))
                self.assertIsNone(why)
                self.assertEqual(got["result"], t.OK_TAG.to_bytes(8, "little") + b"\x5a" * 16)

    def test_same_case_same_output_in_both_families(self):
        for kind, flag in (("vec", 1), ("vec", 0x21), ("ser", 1), ("ser", 0)):
            with self.subTest(kind=kind, flag=flag):
                outs = []
                for fam in FAMS:
                    got, why = run(make_case(body(fam, kind), flag, cap_slack=1))
                    self.assertIsNone(why)
                    outs.append((got["calls"], got["buf"], got["result"], got["vec"]))
                self.assertEqual(outs[0], outs[1])


class JsonBehavior(unittest.TestCase):
    def test_pretty_object_with_two_space_indent(self):
        got, why = run(make_case(JSON, cur=0))
        self.assertIsNone(why)
        self.assertEqual(got["buf"], b'{\n  "wei": ,\n  "user": \n}')
        self.assertEqual(got["calls"], [("u256_json", ("S", 0), "ser"), ("b160_json", ("S", 0x20), "ser")])
        self.assertEqual(got["rax"], 0)
        self.assertEqual(t.u(got["ser"], 0x18, 8), 0)
        self.assertEqual(got["ser"][0x20], 1)

    def test_nested_indent_level(self):
        got, why = run(make_case(JSON, cur=2, indent=b"\t"))
        self.assertIsNone(why)
        self.assertEqual(got["buf"], b'{\n\t\t\t"wei": ,\n\t\t\t"user": \n\t\t}')
        self.assertEqual(t.u(got["ser"], 0x18, 8), 2)

    def test_empty_indent(self):
        got, why = run(make_case(JSON, cur=1, indent=b""))
        self.assertIsNone(why)
        self.assertEqual(got["buf"], b'{\n"wei": ,\n"user": \n}')

    def test_indent_overflow_panics_before_any_write(self):
        c = make_case(JSON, cur=t.M64)
        got, why = run(c)
        self.assertIsNone(why)
        self.assertEqual(got["panic"], ("add_overflow_panic", t.JSON_PANIC_LOC))
        self.assertEqual(got["len"], 0)
        self.assertEqual(got["calls"], [])

    def test_max_minus_one_indent_with_empty_text(self):
        got, why = run(make_case(JSON, cur=t.M64 - 1, indent=b""))
        self.assertIsNone(why)
        self.assertEqual(t.u(got["ser"], 0x18, 8), t.M64 - 1)

    def test_value_error_leaves_indent_raised(self):
        for fault, n_calls, has in ((0, 1, 0), (1, 2, 1)):
            with self.subTest(fault=fault):
                c = make_case(JSON, cur=3, fault=fault, has_in=0x5a)
                got, why = run(c)
                self.assertIsNone(why)
                self.assertEqual(got["rax"], c["plan"][fault][0])
                self.assertEqual(len(got["calls"]), n_calls)
                self.assertEqual(t.u(got["ser"], 0x18, 8), 4)
                self.assertEqual(got["ser"][0x20], has)
                self.assertFalse(got["buf"].endswith(b"}"))

    def test_reserve_sizes_follow_each_write(self):
        got, why = run(make_case(JSON, cur=0, cap_slack=0, indent=b"    "))
        self.assertIsNone(why)
        res = [r[2] for r in got["calls"] if r[0] == "vec_reserve"]
        self.assertEqual(res[:4], [1, 1, 4, 1])
        self.assertIn(3, res)
        self.assertIn(2, res)

    def test_prefix_is_kept(self):
        got, why = run(make_case(JSON, prefix=b"[x,", cur=0, indent=b" "))
        self.assertIsNone(why)
        self.assertEqual(got["buf"], b'[x,{\n "wei": ,\n "user": \n}')


class NegativeControls(unittest.TestCase):
    def test_model_mutants_are_detected_on_hand_cases(self):
        cases = {
            "names-when-nonzero": make_case(body("a", "vec"), 2),
            "map-when-one": make_case(body("a", "ser"), 2),
            "marker-map-array-only": make_case(body("b", "vec"), 2),
            "swap-fields": make_case(body("b", "ser"), 1),
            "indent-one-more": make_case(JSON, cur=1),
            "end-keeps-indent": make_case(JSON, cur=1),
            "indent-wraps": make_case(JSON, cur=t.M64),
            "has-value-unset": make_case(JSON, cur=0, fault=1),
        }
        for mut, c in cases.items():
            with self.subTest(mut=mut):
                self.assertIsNone(run(c)[1])
                try:
                    why = run(c, frozenset([mut]))[1]
                except (t.ToolError, t.Boundary):
                    why = "tool-error"
                self.assertIsNotNone(why)

    def test_byte_flip_of_flag_test_is_detected(self):
        s = Shared.load()
        va = body("a", "ser")
        site = next(v for v, o, i in t.body_row(s.image, s.ext, va)["flags"] if i == 0)
        f = s.image.read(site, 8)
        self.assertEqual(f[:4], bytes.fromhex("807a0b00"))
        c = make_case(va, 1)  # cmp $1 instead of $0 would pick the array header for flag 1
        try:
            got, why = run(c, override={site + 3: 1})
        except (t.ToolError, t.Boundary):
            why = "tool-error"
        self.assertIsNotNone(why)

    def test_byte_flip_in_real_helper_is_detected(self):
        """`movw $0x203a` (": ") -> `$0x203b` in the JSON body must change the output."""
        s = Shared.load()
        code = s.image.code(JSON, s.ext[JSON] - JSON)
        at = JSON + code.index(bytes.fromhex("66c704303a20")) + 4
        got, why = run(make_case(JSON, cur=0), override={at: 0x3b})
        self.assertEqual(why, "bytes")

    def test_corrupted_case_record_is_detected(self):
        c = make_case(JSON, cur=0)
        got = dict(run(c)[0])
        got["buf"] = got["buf"][:-1] + b"]"
        self.assertEqual(t.compare(c, t.model(c), got), "bytes")

    def test_controls_cover_every_body(self):
        s = Shared.load()
        cases = t.all_cases(0.02)
        res, bad, m = t.evaluate(s.image, cases)
        self.assertEqual(bad, [])
        sites = t.byte_sites(s.image, s.ext, m.seen)
        self.assertEqual({x["body"] for x in sites}, set(t.BODIES))
        self.assertFalse(any(x["insn"] in t.EQUIVALENT_SITES for x in sites))


if __name__ == "__main__":
    unittest.main()
