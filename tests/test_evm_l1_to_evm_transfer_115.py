"""Tests for tools/evm_l1_to_evm_transfer_115.py (node #115 L1ToEvmNativeTokenTransfer serializers, two families).

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
import evm_l1_to_evm_transfer_115 as t  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "evm-l1-to-evm-transfer-serializers-115"
GENERATED = ("bodies.tsv", "callees.tsv", "cases-sample.tsv", "controls.tsv", "fields.tsv", "stubs.tsv",
             "summary.json", "unreached.tsv")
FAMS = ("a", "b")


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


def make_case(va, flag, cap_slack=200, prefix=b"", tags=None, comp_w0=None, count=0, iter_idx=(0, 1, 0, 0),
              fault=-1, off=0x28):
    """A hand-built case: records filled with a byte ramp, chosen send_to_evm_data tags, ok words for every stub
    call except `fault`."""
    st = bytearray((i * 7 + 3) & 0xff for i in range(t.ST_SIZE))
    for i in range(t.NREC):
        t.put(st, i * t.RECORD + 0x28, 8, (tags or {}).get(i, 0))
    c = {"body": va, "k": 1, "st": st, "comp": bytearray(0x30), "svec": bytearray(0x18), "ser": bytearray(0x10),
         "flag": flag, "prefix": prefix, "cap": len(prefix) + cap_slack, "extra": 0, "fault": -1, "plan": [],
         "okplan": [], "off": off}
    if t.KIND_OF[va] == "seq":
        c["comp_w0"] = c["cap"] if comp_w0 is None else comp_w0
        c["count"] = count
        c["iter"] = tuple(t.ST_AT + i * t.RECORD for i in iter_idx)
    s = t.Stream("test-case")
    for _ in range(400):
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
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="evm-l1-to-evm-transfer-"))
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
        self.assertEqual(s["cases"], 20000)
        self.assertEqual(s["bodies"], 8)
        self.assertGreaterEqual(s["controls"], 30)
        self.assertEqual(s["controls"], s["controls_detected"])
        self.assertEqual(s["model_mutants"], len(t.MODEL_MUTANTS))

    def test_unreached_instructions_are_explained(self):
        rows = (self.tmp / "out" / "unreached.tsv").read_text().splitlines()[1:]
        kinds = {t.KIND_OF[int(r.split("\t")[0], 16)] for r in rows}
        self.assertEqual(kinds, {"send", "seq"})
        self.assertFalse(any(r.endswith("unexplained") for r in rows))
        self.assertEqual(self.summary["body_instructions"] - self.summary["body_instructions_reached"], len(rows))

    def test_every_body_has_ok_and_error_cases(self):
        for va, d in self.summary["per_body"].items():
            with self.subTest(body=va):
                self.assertGreater(d["ok"], 0)
                self.assertGreater(d["error"], 0)
                self.assertGreater(d["flag_one"], 0)
                self.assertGreater(d["flag_zero"], 0)
                self.assertGreater(d["flag_other"], 0)
                if t.KIND_OF[int(va, 16)] == "seq":
                    self.assertGreater(d["panic"], 0)


class StaticChecks(unittest.TestCase):
    def setUp(self):
        Shared.load()

    def test_static_facts_hold(self):
        rows = {va: t.body_row(Shared.image, Shared.ext, va) for va in t.BODIES}
        t.check_static(rows)

    def test_fde_extents(self):
        sizes = {va: Shared.ext[va] - va for va in t.BODIES}
        for fam in FAMS:
            self.assertEqual(sizes[body(fam, "vec")], 926)
            self.assertEqual(sizes[body(fam, "ser")], 574)
            self.assertEqual(sizes[body(fam, "send")], 325)
        self.assertEqual(sizes[body("a", "seq")], 622)
        self.assertEqual(sizes[body("b", "seq")], 574)

    def test_key_texts_from_rodata(self):
        rows = t.body_row(Shared.image, Shared.ext, body("a", "ser"))
        self.assertEqual([n for _, _, n in rows["names"]], ["token", "system_address", "contract", "wei", "user"])
        for fam in FAMS:
            rows = t.body_row(Shared.image, Shared.ext, body(fam, "send"))
            self.assertEqual([n for _, _, n in rows["names"]], ["send_to_evm_data"])

    def test_wrong_digest_rejected(self):
        data = bytearray(t.BINARY.read_bytes()[:4096])
        with self.assertRaises(t.ToolError):
            t.Image(bytes(data))

    def test_changed_callee_breaks_static_check(self):
        """Redirect the first uint writer call of the family-a inline-Vec body: check_static must fail."""
        data = bytearray(Shared.image.data)
        site = next(v for v, how, tgt, role in t.body_row(Shared.image, Shared.ext, body("a", "vec"))["calls"]
                    if role == "uint_vec")
        name, off = Shared.image.section_of(site)
        data[off + 1] ^= 0x10
        img = t.Image(bytes(data), check=False)
        rows = {va: t.body_row(img, Shared.ext, va) for va in t.BODIES}
        with self.assertRaises(t.ToolError):
            t.check_static(rows)

    def test_out_of_range_start_rejected(self):
        with self.assertRaises(t.ToolError):
            t.fde_rows(Shared.image, {body("a", "vec") + 1})

    def test_code_outside_text_rejected(self):
        with self.assertRaises(t.ToolError):
            Shared.image.code(0x10, 4)


class RecordBehavior(unittest.TestCase):
    def test_marker_rule(self):
        self.assertEqual(t.vec_marker(0), 0x96)
        self.assertEqual(t.vec_marker(1), 0x86)
        self.assertEqual(t.vec_marker(2), 0xb6)
        self.assertEqual(t.vec_marker(0x11), 0x86)
        self.assertEqual(t.vec_marker(0x10), 0x96)
        self.assertEqual(t.vec_marker(0xff), 0xe6)

    def test_vec_flag_one_writes_inline_and_str_names(self):
        for fam in FAMS:
            with self.subTest(fam=fam):
                c = make_case(body(fam, "vec"), 1)
                got, why = run(c)
                self.assertIsNone(why)
                self.assertEqual(got["buf"], b"\x86\xa5token\xaesystem_address\xa8contract")
                roles = [r[0] for r in got["calls"]]
                self.assertEqual(roles, ["uint_vec", "b160_vec", "b160_vec", "vec_str", "u256_vec", "vec_str",
                                         "b160_vec", "send_vec"])
                self.assertEqual(got["calls"][3][2], b"wei")
                self.assertEqual(got["calls"][5][2], b"user")
                self.assertEqual(got["calls"][4][2], ("S", 0x0))
                self.assertEqual(got["calls"][7][3], ("S", 0x28))

    def test_vec_flag_0x11_is_a_map_without_names(self):
        for fam in FAMS:
            with self.subTest(fam=fam):
                got, why = run(make_case(body(fam, "vec"), 0x11))
                self.assertIsNone(why)
                self.assertEqual(got["buf"], b"\x86")
                self.assertNotIn("vec_str", [r[0] for r in got["calls"]])

    def test_vec_flag_two_writes_a_fixstr_marker(self):
        got, why = run(make_case(body("a", "vec"), 2))
        self.assertIsNone(why)
        self.assertEqual(got["buf"], b"\xb6")

    def test_vec_reserve_rules(self):
        for slack, want in ((0, [("vec_reserve", 0, 1)]), (1, [("vec_reserve", 1, 1), ("vec_reserve", 2, 5)]), (6, [])):
            with self.subTest(slack=slack):
                c = make_case(body("a", "vec"), 1, cap_slack=slack)
                got, why = run(c)
                self.assertIsNone(why)
                res = [r for r in got["calls"] if r[0] == "vec_reserve"]
                self.assertEqual(res[:len(want)], want)

    def test_ser_flag_two_is_a_map_with_only_the_writer_name(self):
        for fam in FAMS:
            with self.subTest(fam=fam):
                c = make_case(body(fam, "ser"), 2)
                got, why = run(c)
                self.assertIsNone(why)
                self.assertEqual(got["calls"][0], ("map_hdr", "stk", "ser", 6))
                strs = [r[2] for r in got["calls"] if r[0] == "ser_str"]
                self.assertEqual(strs, [b"send_to_evm_data"])

    def test_ser_flag_zero_is_an_array_without_names(self):
        for fam in FAMS:
            with self.subTest(fam=fam):
                got, why = run(make_case(body(fam, "ser"), 0))
                self.assertIsNone(why)
                self.assertEqual(got["calls"][0], ("arr_hdr", "stk", "ser", 6))
                self.assertNotIn("ser_str", [r[0] for r in got["calls"]])

    def test_ser_flag_one_names_all_six(self):
        got, why = run(make_case(body("a", "ser"), 1))
        self.assertIsNone(why)
        strs = [r[2] for r in got["calls"] if r[0] == "ser_str"]
        self.assertEqual(strs, [b"token", b"system_address", b"contract", b"wei", b"user", b"send_to_evm_data"])

    def test_header_error_is_wrapped(self):
        c = make_case(body("a", "ser"), 1, fault=0)
        got, why = run(c)
        self.assertIsNone(why)
        w = c["plan"][0]
        self.assertEqual(got["result"], t.result_bytes((t.ERR_TAG, w[0], w[1])))

    def test_nested_error_is_passed_through(self):
        c = make_case(body("b", "vec"), 0, fault=1)
        got, why = run(c)
        self.assertIsNone(why)
        self.assertEqual(got["result"], t.result_bytes(tuple(c["plan"][1])))


class SendWriterBehavior(unittest.TestCase):
    def test_present_tag_tail_calls_the_destination_serializer(self):
        for fam in FAMS:
            with self.subTest(fam=fam):
                c = make_case(body(fam, "send"), 0, tags={0: 5})
                got, why = run(c)
                self.assertIsNone(why)
                self.assertEqual(got["calls"], [("dest_ser", "out", ("S", 0x28), "ser")])

    def test_tag_high_half_counts(self):
        c = make_case(body("a", "send"), 0, tags={0: 1 << 32})
        got, why = run(c)
        self.assertIsNone(why)
        self.assertEqual(got["calls"][0][0], "dest_ser")

    def test_none_pushes_nil_and_grows_amortized(self):
        for ln, new in ((0, 8), (4, 8), (5, 10), (17, 34)):
            with self.subTest(ln=ln):
                c = make_case(body("a", "send"), 0, cap_slack=0, prefix=bytes(range(ln)))
                got, why = run(c)
                self.assertIsNone(why)
                self.assertEqual(got["calls"], [("grow", ln, "buf", new)])
                self.assertEqual(got["buf"][ln:], b"\xc0")
                self.assertEqual(t.u(got["vec"], 0, 8), new)

    def test_grow_failure_returns_fixed_error(self):
        for fam in FAMS:
            with self.subTest(fam=fam):
                c = make_case(body(fam, "send"), 0, cap_slack=0, fault=0)
                got, why = run(c)
                self.assertIsNone(why)
                self.assertEqual(got["result"], t.result_bytes((t.ERR_TAG, 0, t.GROW_ERR)))
                self.assertEqual(got["len"], 0)

    def test_name_written_for_any_nonzero_flag(self):
        for flag in (1, 2, 0x80):
            with self.subTest(flag=flag):
                got, why = run(make_case(body("b", "send"), flag, tags={0: 1}))
                self.assertIsNone(why)
                self.assertEqual(got["calls"][0], ("ser_str", "ser", b"send_to_evm_data"))


class SequenceBehavior(unittest.TestCase):
    def test_vec_variant_counts_elements(self):
        for fam in FAMS:
            with self.subTest(fam=fam):
                c = make_case(body(fam, "seq"), 1, count=5, iter_idx=(0, 2, 4, 5))
                got, why = run(c)
                self.assertIsNone(why)
                self.assertEqual(t.u(got["comp"], t.COUNT_AT, 4), 8)
                self.assertEqual(got["buf"].count(b"\x86\xa5token"), 3)

    def test_inner_variant_does_not_count(self):
        for fam in FAMS:
            with self.subTest(fam=fam):
                c = make_case(body(fam, "seq"), 1, comp_w0=t.NICHE, count=5, iter_idx=(1, 3, 0, 0))
                got, why = run(c)
                self.assertIsNone(why)
                self.assertEqual(t.u(got["comp"], t.COUNT_AT, 4), 5)
                self.assertEqual([r[0] for r in got["calls"]].count("map_hdr"), 2)

    def test_counter_overflow_panics_after_the_element(self):
        for fam in FAMS:
            with self.subTest(fam=fam):
                c = make_case(body(fam, "seq"), 0, count=0xffffffff, iter_idx=(0, 2, 0, 0))
                got, why = run(c)
                self.assertIsNone(why)
                self.assertEqual(got["panic"], t.PANIC_LOC[fam])
                self.assertEqual(t.u(got["iter"], 0, 8), t.ST_AT + t.RECORD)

    def test_failed_element_is_consumed(self):
        c = make_case(body("a", "seq"), 0, iter_idx=(0, 3, 0, 0), fault=8)
        got, why = run(c)
        self.assertIsNone(why)
        self.assertNotEqual(got["result"][:8], t.OK_TAG.to_bytes(8, "little"))
        self.assertEqual(t.u(got["iter"], 0, 8), t.ST_AT + 2 * t.RECORD)

    def test_empty_chain_is_ok_without_calls(self):
        got, why = run(make_case(body("b", "seq"), 1, iter_idx=(3, 3, 6, 6)))
        self.assertIsNone(why)
        self.assertEqual(got["calls"], [])
        self.assertEqual(got["result"], t.result_bytes((t.OK_TAG,)))


class FamilyEquivalence(unittest.TestCase):
    def test_same_case_same_output_in_both_families(self):
        """The two copy families give the same calls, bytes, result, iterator and counter on identical inputs."""
        for kind, kw in (("vec", {"flag": 1}), ("vec", {"flag": 2}), ("ser", {"flag": 2}),
                         ("send", {"flag": 1, "cap_slack": 0}), ("seq", {"flag": 1, "iter_idx": (0, 2, 3, 4)}),
                         ("seq", {"flag": 0, "comp_w0": t.NICHE, "iter_idx": (0, 1, 2, 4)})):
            with self.subTest(kind=kind, flag=kw["flag"]):
                outs = []
                for fam in FAMS:
                    got, why = run(make_case(body(fam, kind), **kw))
                    self.assertIsNone(why)
                    outs.append((got["calls"], got["buf"], got["result"], got["iter"],
                                 got["comp"][t.COUNT_AT:t.COUNT_AT + 4]))
                self.assertEqual(outs[0], outs[1])

    def test_success_writes_only_word_zero(self):
        for kind in ("vec", "ser", "seq"):
            with self.subTest(kind=kind):
                got, why = run(make_case(body("a", kind), 1))
                self.assertIsNone(why)
                self.assertEqual(got["result"], t.OK_TAG.to_bytes(8, "little") + b"\x5a" * 16)


class NegativeControls(unittest.TestCase):
    def test_model_mutants_are_detected_on_hand_cases(self):
        cases = {
            "names-when-nonzero": make_case(body("a", "vec"), 2),
            "map-when-one": make_case(body("a", "ser"), 2),
            "send-name-when-one": make_case(body("b", "send"), 2),
            "grow-min-9": make_case(body("a", "send"), 0, cap_slack=0, prefix=bytes(4)),
            "no-count": make_case(body("a", "seq"), 1, iter_idx=(0, 1, 0, 0)),
            "iter-store-after": make_case(body("a", "seq"), 0, iter_idx=(0, 3, 0, 0), fault=8),
            "marker-map-array-only": make_case(body("b", "vec"), 2),
        }
        for mut, c in cases.items():
            with self.subTest(mut=mut):
                self.assertIsNone(run(c)[1])
                self.assertIsNotNone(run(c, frozenset([mut]))[1])

    def test_byte_flip_of_flag_test_is_detected(self):
        s = Shared.load()
        va = body("a", "ser")
        site = next(v for v, o, i in t.body_row(s.image, s.ext, va)["flags"] if i == 0)
        f = s.image.read(site, 8)
        at = site + 3  # 80 7a 0b 00 = cmp byte [rdx+0xb], 0: the immediate
        self.assertEqual(f[:4], bytes.fromhex("807a0b00"))
        c = make_case(va, 1)  # cmp $1 instead of $0 would pick the array header for flag 1
        try:
            got, why = run(c, override={at: 1})
        except (t.ToolError, t.Boundary):
            why = "tool-error"
        self.assertIsNotNone(why)

    def test_corrupted_case_record_is_detected(self):
        c = make_case(body("a", "vec"), 1)
        got = run(c)[0]
        want = t.model(c)
        got = dict(got)
        got["buf"] = got["buf"][:-1] + b"X"
        self.assertEqual(t.compare(c, want, got), "bytes")


if __name__ == "__main__":
    unittest.main()
