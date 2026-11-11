"""Tests for tools/evm_l1_transfer_json_115.py (node #115 L1ToEvmNativeTokenTransfer pretty-JSON path).

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
import evm_l1_transfer_json_115 as t  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "evm-l1-transfer-json-path-115"
GENERATED = ("callees.tsv", "cases-sample.tsv", "controls.tsv", "fields.tsv", "functions.tsv", "summary.json",
             "unreached.tsv")


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


def make_case(group, token=12345, opt=0, cur=0, indent=b"  ", cap_slack=400, prefix=b"", fault=-1, base=0,
              state=0, first=1, key=b"token", has_in=0, extra=0):
    """A hand-built case: records filled with a byte ramp, ok words for every stub call except `fault`."""
    st = bytearray((i * 7 + 3) & 0xff for i in range(t.ST_SIZE))
    t.put(st, base + 0x20, 8, token)
    t.put(st, base + 0x28, 8, opt)
    c = {"group": group, "k": 1, "st": st, "base": base, "svec": bytearray(0x18), "jser": bytearray(range(0x28)),
         "cmp": bytearray(range(0x10)), "prefix": prefix, "cap": len(prefix) + cap_slack, "extra": extra,
         "fault": -1, "plan": [], "okplan": [], "has_in": has_in, "indent": indent, "cur": cur, "state": state,
         "first": first}
    if group not in ("body", "guard"):
        c["key"] = key
    t.fill_plan(t.Stream("test-case"), c)
    c["fault"] = fault
    return c


def itoa_case(v):
    return {"group": "itoa", "k": 0, "value": v, "fill": bytes(range(0x40, 0x54))}


def run(c, mut=frozenset(), override=None):
    s = Shared.load()
    m = t.machine(s.image, override)
    got = t.run_case(m, c)
    return got, t.compare(c, t.model(c, mut), got)


class GeneratedFiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="evm-l1-transfer-json-"))
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
        self.assertEqual(s["cases"], 16500)
        self.assertEqual(s["functions"], 9)
        self.assertGreaterEqual(s["controls"], 30)
        self.assertEqual(s["controls"], s["controls_detected"])
        self.assertEqual(s["model_mutants"], len(t.MODEL_MUTANTS))
        self.assertEqual(s["equivalent_sites_excluded"], len(t.EQUIVALENT_SITES))

    def test_unreached_instructions_are_explained(self):
        rows = (self.tmp / "out" / "unreached.tsv").read_text().splitlines()[1:]
        self.assertFalse(any(r.endswith("unexplained") for r in rows))
        self.assertEqual(self.summary["instructions"] - self.summary["instructions_reached"], len(rows))
        # the option guard and the key writer are reached completely; the escaper misses only its nop padding
        for va in (t.ENTRY["guard"], t.HELPERS["key"]):
            self.assertFalse(any(int(r.split("\t")[0], 16) == va for r in rows), hex(va))
        esc = [r for r in rows if int(r.split("\t")[0], 16) == t.HELPERS["escape"]]
        self.assertEqual(len(esc), 1)
        self.assertIn("padding", esc[0])

    def test_every_group_has_its_outcomes(self):
        g = self.summary["per_group"]
        self.assertEqual(g["itoa"]["ok"], g["itoa"]["cases"])
        for name in ("body", "addrf", "optf"):
            with self.subTest(group=name):
                self.assertGreater(g[name]["ok"], 0)
                self.assertGreater(g[name]["error"], 0)
                self.assertGreater(g[name]["panic"], 0)
                self.assertGreater(g[name]["reserve_calls"], 0)
        self.assertEqual(g["u64f"]["error"], 0)  # the u64 entry cannot fail, it can only panic (state 1)
        self.assertGreater(g["u64f"]["panic"], 0)
        self.assertGreater(g["guard"]["error"], 0)


class StaticChecks(unittest.TestCase):
    def setUp(self):
        Shared.load()

    def rows(self, image=None):
        return {va: t.body_row(image or Shared.image, Shared.ext, va) for va in t.CODE}

    def test_static_facts_hold(self):
        t.check_static(Shared.image, self.rows())

    def test_fde_extents(self):
        sizes = [Shared.ext[va] - va for va in t.CODE]
        self.assertEqual(sizes, [746, 258, 151, 55, 228, 520, 552, 311, 322])

    def test_key_texts_from_rodata(self):
        rows = self.rows()
        self.assertEqual([n for _, n in rows[t.BODY]["keys"]], ["token", "system_address", "contract", "wei", "user"])
        self.assertEqual([n for _, n in rows[t.ENTRY["guard"]]["keys"]], ["send_to_evm_data"])
        self.assertEqual(rows[t.BODY]["offsets"], [0x20, 0x80, 0x94, 0xa8, 0x28])

    def test_tables_from_bytes(self):
        esc, hexd, pairs = t.tables(Shared.image)
        self.assertEqual(esc, t.ESCAPE)
        self.assertEqual(sum(1 for b in esc if b), 34)
        self.assertEqual(hexd, b"0123456789abcdef")
        self.assertEqual(pairs[:6], b"000102")

    def test_wrong_digest_rejected(self):
        data = bytearray(t.BINARY.read_bytes()[:4096])
        with self.assertRaises(t.ToolError):
            t.Image(bytes(data))

    def test_changed_callee_breaks_static_check(self):
        """Redirect the U256 value call of the body: check_static must fail."""
        data = bytearray(Shared.image.data)
        site = next(v for v, how, tgt, role in self.rows()[t.BODY]["calls"] if role == "u256_json")
        _, off = Shared.image.section_of(site)
        data[off + 1] ^= 0x10
        img = t.Image(bytes(data), check=False)
        with self.assertRaises(t.ToolError):
            t.check_static(img, self.rows(img))

    def test_changed_key_length_breaks_static_check(self):
        data = bytearray(Shared.image.data)
        code = Shared.image.code(t.BODY, Shared.ext[t.BODY] - t.BODY)
        at = code.index(bytes.fromhex("ba0e000000"))  # mov edx, 14 ("system_address")
        _, off = Shared.image.section_of(t.BODY + at)
        data[off + 1] = 0x0d
        img = t.Image(bytes(data), check=False)
        with self.assertRaises(t.ToolError):
            t.check_static(img, self.rows(img))

    def test_changed_escape_table_breaks_static_check(self):
        data = bytearray(Shared.image.data)
        va = Shared.image.word(t.ESCAPE_GOT) + 0x41
        _, off = Shared.image.section_of(va)
        data[off] = ord("u")
        img = t.Image(bytes(data), check=False)
        with self.assertRaises(t.ToolError):
            t.check_static(img, self.rows(img))

    def test_out_of_range_start_rejected(self):
        with self.assertRaises(t.ToolError):
            t.fde_rows(Shared.image, {t.BODY + 1})

    def test_code_outside_text_rejected(self):
        with self.assertRaises(t.ToolError):
            Shared.image.code(0x10, 4)

    def test_nobits_read_rejected(self):
        bss = next(s for s in Shared.image.secs if s["name"] == ".bss")
        with self.assertRaises(t.ToolError):
            Shared.image.read(bss["address"] + 8, 8)


class BodyBehavior(unittest.TestCase):
    def test_whole_object_with_null_option(self):
        got, why = run(make_case("body", token=7, opt=0))
        self.assertIsNone(why)
        self.assertEqual(got["buf"], b'{\n  "token": 7,\n  "system_address": ,\n  "contract": ,\n  "wei": ,\n'
                                     b'  "user": ,\n  "send_to_evm_data": null\n}')
        self.assertEqual(got["calls"], [("b160_json", ("S", 0x80), "ser"), ("b160_json", ("S", 0x94), "ser"),
                                        ("u256_json", ("S", 0x00), "ser"), ("b160_json", ("S", 0xa8), "ser")])
        self.assertEqual(got["rax"], 0)
        self.assertEqual(t.u(got["ser"], 0x18, 8), 0)
        self.assertEqual(got["ser"][0x20], 1)

    def test_some_option_goes_to_bytes_serializer(self):
        got, why = run(make_case("body", token=0, opt=1 << 40, base=t.RECORD, cur=1, indent=b"\t"))
        self.assertIsNone(why)
        self.assertEqual(got["calls"][-1], ("bytes_json", ("S", t.RECORD + 0x28), "ser"))
        self.assertTrue(got["buf"].startswith(b'{\n\t\t"token": 0,\n'))
        self.assertTrue(got["buf"].endswith(b'\t\t"send_to_evm_data": \n\t}'))

    def test_token_extremes(self):
        for v in (0, 9, 10, 99, 100, 10 ** 19, t.M64):
            with self.subTest(v=v):
                got, why = run(make_case("body", token=v))
                self.assertIsNone(why)
                self.assertIn(b'"token": %d,' % v, got["buf"])

    def test_value_error_returns_at_once(self):
        for fault, n_calls in ((0, 1), (1, 2), (2, 3), (3, 4)):
            with self.subTest(fault=fault):
                c = make_case("body", cur=3, fault=fault, has_in=0x5a)
                got, why = run(c)
                self.assertIsNone(why)
                self.assertEqual(got["rax"], c["plan"][fault][0])
                self.assertEqual(len([r for r in got["calls"] if r[0] != "vec_reserve"]), n_calls)
                self.assertEqual(t.u(got["ser"], 0x18, 8), 4)
                self.assertEqual(got["ser"][0x20], 1)  # the token entry already set has_value
                self.assertFalse(got["buf"].endswith(b"}"))

    def test_bytes_value_error(self):
        c = make_case("body", opt=5, fault=4)
        got, why = run(c)
        self.assertIsNone(why)
        self.assertEqual(got["rax"], c["plan"][4][0])
        self.assertTrue(got["buf"].endswith(b'"send_to_evm_data": '))

    def test_indent_overflow_panics_before_any_write(self):
        got, why = run(make_case("body", cur=t.M64))
        self.assertIsNone(why)
        self.assertEqual(got["panic"], ("add_overflow_panic", t.INDENT_PANIC_LOC))
        self.assertEqual(got["len"], 0)

    def test_reserve_rules(self):
        got, why = run(make_case("body", token=10 ** 19, cap_slack=0, indent=b""))
        self.assertIsNone(why)
        res = [r[2] for r in got["calls"] if r[0] == "vec_reserve"]
        self.assertEqual(res[:5], [1, 1, 1, 5, 1])  # '{', '\n', '"', "token" run, '"'
        self.assertIn(20, res)  # the 20 digits of 10^19 do not fit the spare capacity
        self.assertIn(4, res)   # "null"


class EntryBehavior(unittest.TestCase):
    def test_u64_entry_rest_state(self):
        got, why = run(make_case("u64f", token=42, first=2, cur=1, key=b"k"))
        self.assertIsNone(why)
        self.assertEqual(got["buf"], b',\n  "k": 42')
        self.assertEqual(got["cmp"][1], 2)

    def test_state_one_panics_in_key_writer(self):
        for g in ("u64f", "addrf", "optf"):
            with self.subTest(group=g):
                got, why = run(make_case(g, state=1))
                self.assertIsNone(why)
                self.assertEqual(got["panic"], ("unreachable_panic", (t.UNREACHABLE_MSG, t.UNREACHABLE_LEN)))
                self.assertEqual(got["len"], 0)

    def test_other_states_behave_as_map(self):
        got, why = run(make_case("addrf", state=2, key=b"user"))
        self.assertIsNone(why)
        self.assertEqual(got["buf"], b'\n"user": ')

    def test_guard_rejects_non_map_state(self):
        for state in (1, 2, 0xff):
            with self.subTest(state=state):
                c = make_case("guard", state=state)
                got, why = run(c)
                self.assertIsNone(why)
                self.assertEqual(got["calls"], [("error_ctor", t.ERROR_CODE, 0, 0)])
                self.assertEqual(got["rax"], c["okplan"][0][0])
                self.assertEqual(got["len"], 0)

    def test_guard_null_and_some(self):
        got, why = run(make_case("guard", opt=0))
        self.assertIsNone(why)
        self.assertEqual(got["buf"], b'\n"send_to_evm_data": null')
        got, why = run(make_case("guard", opt=0x100))
        self.assertIsNone(why)
        self.assertEqual(got["calls"], [("bytes_json", ("S", 0x28), "ser")])

    def test_null_reserve_edge(self):
        for slack, want in ((3 + 5, [4]), (4 + 5, [])):  # 5 bytes before "null": \n "" ": "
            with self.subTest(slack=slack):
                got, why = run(make_case("optf", key=b"", cap_slack=slack, indent=b""))
                self.assertIsNone(why)
                self.assertEqual([r[2] for r in got["calls"] if r[0] == "vec_reserve"], want)

    def test_escape_arms(self):
        key = b'a"b\\c\x01\x08\t\n\x0c\r\x1f\x7f\xc3'
        got, why = run(make_case("addrf", key=key, indent=b""))
        self.assertIsNone(why)
        self.assertEqual(got["buf"], b'\n"a\\"b\\\\c\\u0001\\b\\t\\n\\f\\r\\u001f\x7f\xc3": ')

    def test_escape_reserve_edges(self):
        for slack in range(0, 12):
            with self.subTest(slack=slack):
                got, why = run(make_case("addrf", key=b"\x02x\"", cap_slack=slack, indent=b""))
                self.assertIsNone(why)


class ItoaBehavior(unittest.TestCase):
    def test_digits(self):
        for v in t.U64_EDGES:
            with self.subTest(v=v):
                got, why = run(itoa_case(v))
                self.assertIsNone(why)
                self.assertEqual(got["buf"][20 - got["rdx"]:], b"%d" % v)

    def test_buffer_prefix_untouched(self):
        got, why = run(itoa_case(5))
        self.assertIsNone(why)
        self.assertEqual(got["buf"][:19], bytes(range(0x40, 0x53)))
        self.assertEqual(got["rax"], t.ITB_AT + 19)


class NegativeControls(unittest.TestCase):
    def test_model_mutants_are_detected_on_hand_cases(self):
        cases = {
            "indent-wraps": make_case("body", cur=t.M64),
            "order-wei-first": make_case("body"),
            "itoa-hex": make_case("body", token=10),
            "null-reserve-lt": make_case("optf", key=b"", cap_slack=4 + 5, indent=b""),
            "guard-state-ignored": make_case("guard", state=2),
            "escape-upper-hex": make_case("addrf", key=b"\x1f"),
            "escape-del": make_case("addrf", key=b"\x7f"),
            "first-any-nonzero": make_case("u64f", first=2),
            "opt-tag-byte": make_case("body", opt=0x100),
            "end-on-error": make_case("body", fault=1),
        }
        for mut, c in cases.items():
            with self.subTest(mut=mut):
                self.assertIsNone(run(c)[1])
                try:
                    why = run(c, frozenset([mut]))[1]
                except (t.ToolError, t.Boundary):
                    why = "tool-error"
                self.assertIsNotNone(why)

    def test_byte_flip_of_colon_is_detected(self):
        """`movw $0x203a` (": ") -> `$0x203b` in the body must change the output."""
        s = Shared.load()
        code = s.image.code(t.BODY, s.ext[t.BODY] - t.BODY)
        at = t.BODY + code.index(bytes.fromhex("66c704303a20")) + 4
        got, why = run(make_case("body"), override={at: 0x3b})
        self.assertEqual(why, "bytes")

    def test_byte_flip_of_null_is_detected(self):
        s = Shared.load()
        va = t.ENTRY["optf"]
        code = s.image.code(va, s.ext[va] - va)
        at = va + code.index(b"null")
        got, why = run(make_case("optf"), override={at: ord("N")})
        self.assertEqual(why, "bytes")

    def test_corrupted_case_record_is_detected(self):
        c = make_case("body")
        got = dict(run(c)[0])
        got["buf"] = got["buf"][:-1] + b"]"
        self.assertEqual(t.compare(c, t.model(c), got), "bytes")

    def test_controls_cover_every_function(self):
        s = Shared.load()
        cases = t.all_cases(0.03)
        res, bad, m = t.evaluate(s.image, cases)
        self.assertEqual(bad, [])
        sites = t.byte_sites(s.image, s.ext, m.seen)
        self.assertEqual({x["body"] for x in sites}, set(t.CODE))
        self.assertFalse(any(x["insn"] in t.EQUIVALENT_SITES for x in sites))


if __name__ == "__main__":
    unittest.main()
