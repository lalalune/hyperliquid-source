"""Tests for tools/send_to_evm_data_json_115.py (node #115 send_to_evm_data pretty-JSON path).

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
import send_to_evm_data_json_115 as t  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "evm-send-to-evm-data-json-115"
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


def make_case(group, chain=7, gas=8, nonce=9, cur=0, indent=b"  ", cap_slack=400, prefix=b"", fault=-1, base=0,
              state=0, first=1, key=b"gas_limit", has_in=0, extra=0, chain_hi=0):
    """A hand-built case: records filled with a byte ramp, ok words for every stub call except `fault`."""
    st = bytearray((i * 7 + 3) & 0xff for i in range(t.ST_SIZE))
    t.put(st, base + 0x50, 4, chain)
    t.put(st, base + 0x54, 4, chain_hi)
    t.put(st, base + 0x40, 8, gas)
    t.put(st, base + 0x48, 8, nonce)
    c = {"group": group, "k": 1, "st": st, "base": base, "svec": bytearray(0x18), "jser": bytearray(range(0x28)),
         "cmp": bytearray(range(0x10)), "prefix": prefix, "cap": len(prefix) + cap_slack, "extra": extra,
         "fault": -1, "plan": [], "okplan": [], "has_in": has_in, "indent": indent, "cur": cur, "state": state,
         "first": first}
    if group != "body":
        c["key"] = key
    t.fill_plan(t.Stream("test-case"), c)
    c["fault"] = fault
    return c


def itoa_case(group, v):
    return {"group": group, "k": 0, "value": v, "fill": bytes(range(0x40, 0x54))}


def run(c, mut=frozenset(), override=None):
    s = Shared.load()
    m = t.machine(s.image, override)
    got = t.run_case(m, c)
    return got, t.compare(c, t.model(c, mut), got)


class GeneratedFiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="send-to-evm-data-json-"))
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
        self.assertEqual(s["cases"], 15000)
        self.assertEqual(s["functions"], 11)
        self.assertGreaterEqual(s["controls"], 30)
        self.assertEqual(s["controls"], s["controls_detected"])
        self.assertEqual(s["model_mutants"], len(t.MODEL_MUTANTS))
        self.assertEqual(s["equivalent_sites_excluded"], len(t.EQUIVALENT_SITES))

    def test_unreached_instructions_are_explained(self):
        rows = (self.tmp / "out" / "unreached.tsv").read_text().splitlines()[1:]
        self.assertFalse(any(r.endswith("unexplained") for r in rows))
        self.assertEqual(self.summary["instructions"] - self.summary["instructions_reached"], len(rows))
        self.assertFalse(any(int(r.split("\t")[0], 16) == t.HELPERS["key"] for r in rows))

    def test_every_group_has_its_outcomes(self):
        g = self.summary["per_group"]
        for name in ("itoa32", "itoa64", "itoa64b"):
            self.assertEqual(g[name]["ok"], g[name]["cases"])
        self.assertGreater(g["body"]["ok"], 0)
        self.assertGreater(g["body"]["error"], 0)   # recipient serializer errors
        self.assertGreater(g["body"]["panic"], 0)   # current_indent overflow
        for name in ("chainf", "gasf", "noncef", "dataf"):
            with self.subTest(group=name):
                self.assertGreater(g[name]["ok"], 0)
                self.assertEqual(g[name]["error"], 0)   # these entries cannot fail, they can only panic (state 1)
                self.assertGreater(g[name]["panic"], 0)
                self.assertGreater(g[name]["reserve_calls"], 0)


class StaticChecks(unittest.TestCase):
    def setUp(self):
        Shared.load()

    def rows(self, image=None):
        return {va: t.body_row(image or Shared.image, Shared.ext, va) for va in t.CODE}

    def test_static_facts_hold(self):
        t.check_static(Shared.image, self.rows())

    def test_fde_extents(self):
        sizes = [Shared.ext[va] - va for va in t.CODE]
        self.assertEqual(sizes, [519, 251, 258, 251, 147, 520, 552, 311, 321, 322, 322])

    def test_key_texts_from_rodata(self):
        rows = self.rows()
        self.assertEqual([n for _, n in rows[t.BODY]["keys"]],
                         ["destination_recipient", "destination_chain_id", "gas_limit", "nonce", "data"])
        self.assertEqual(rows[t.BODY]["offsets"], [0x20, 0x50, 0x40, 0x48])

    def test_tables_from_bytes(self):
        esc, hexd, pairs = t.tables(Shared.image, self.rows())
        self.assertEqual(esc, t.ESCAPE)
        self.assertEqual(sum(1 for b in esc if b), 34)
        self.assertEqual(hexd, b"0123456789abcdef")
        self.assertEqual({va: p for va, (_, p) in pairs.items()}, {va: t.PAIRS for va in t.ITOAS})
        # each itoa body (including the rip-relative u64 copy) reads its own copy of the digit-pair table
        self.assertEqual(len({at for at, _ in pairs.values()}), 3)

    def test_itoa_copies_differ_only_in_rip_displacements(self):
        a = Shared.image.code(0x25fba40, 322)
        b = Shared.image.code(0x2caca90, 322)
        diff = [i for i in range(322) if a[i] != b[i]]
        self.assertTrue(diff)
        self.assertLess(len(diff), 24)

    def test_wrong_digest_rejected(self):
        data = bytearray(t.BINARY.read_bytes()[:4096])
        with self.assertRaises(t.ToolError):
            t.Image(bytes(data))

    def test_changed_callee_breaks_static_check(self):
        """Redirect the recipient value call of the body: check_static must fail."""
        data = bytearray(Shared.image.data)
        site = next(v for v, how, tgt, role in self.rows()[t.BODY]["calls"] if role == "recipient_json")
        _, off = Shared.image.section_of(site)
        data[off + 1] ^= 0x10
        img = t.Image(bytes(data), check=False)
        with self.assertRaises(t.ToolError):
            t.check_static(img, self.rows(img))

    def test_changed_key_length_breaks_static_check(self):
        data = bytearray(Shared.image.data)
        code = Shared.image.code(t.BODY, Shared.ext[t.BODY] - t.BODY)
        at = code.index(bytes.fromhex("ba09000000"))  # mov edx, 9 ("gas_limit")
        _, off = Shared.image.section_of(t.BODY + at)
        data[off + 1] = 0x08
        img = t.Image(bytes(data), check=False)
        with self.assertRaises(t.ToolError):
            t.check_static(img, self.rows(img))

    def test_changed_digit_pairs_break_static_check(self):
        data = bytearray(Shared.image.data)
        at = self.rows()[0x243bf10]["leas"][0] + 3
        _, off = Shared.image.section_of(at)
        data[off] ^= 1
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
    def test_whole_object(self):
        got, why = run(make_case("body", chain=7, gas=8, nonce=9))
        self.assertIsNone(why)
        self.assertEqual(got["buf"], b'{\n  "destination_recipient": ,\n  "destination_chain_id": 7,\n'
                                     b'  "gas_limit": 8,\n  "nonce": 9,\n  "data": \n}')
        st = make_case("body")["st"]
        self.assertEqual(got["calls"], [("recipient_json", ("S", 0x20), "ser"),
                                        ("bytes_writer", t.u(st, 8, 8), t.u(st, 0x10, 8), "ser")])
        self.assertEqual(got["rax"], 0)
        self.assertEqual(t.u(got["ser"], 0x18, 8), 0)
        self.assertEqual(got["ser"][0x20], 1)

    def test_chain_id_is_u32(self):
        got, why = run(make_case("body", chain=0xffffffff, chain_hi=0xdeadbeef, base=t.RECORD))
        self.assertIsNone(why)
        self.assertIn(b'"destination_chain_id": 4294967295,', got["buf"])

    def test_u64_extremes(self):
        for v in (0, 9, 10, 99, 100, 10 ** 19, t.M64):
            with self.subTest(v=v):
                got, why = run(make_case("body", gas=v, nonce=t.M64 - v))
                self.assertIsNone(why)
                self.assertIn(b'"gas_limit": %d,' % v, got["buf"])
                self.assertIn(b'"nonce": %d,' % (t.M64 - v), got["buf"])

    def test_recipient_error_returns_at_once(self):
        c = make_case("body", cur=3, fault=0, has_in=0x5a)
        got, why = run(c)
        self.assertIsNone(why)
        self.assertEqual(got["rax"], c["plan"][0][0])
        self.assertEqual(t.u(got["ser"], 0x18, 8), 4)
        self.assertEqual(got["ser"][0x20], 0)  # cleared at object start, never set
        self.assertTrue(got["buf"].endswith(b'"destination_recipient": '))

    def test_bytes_writer_result_is_ignored(self):
        c = make_case("body")
        k = next(i for i, r in enumerate(t.model(c)["calls"]) if r[0] == "bytes_writer")
        c["okplan"][k] = (0x8000000000000000, 0, 0)
        got, why = run(c)
        self.assertIsNone(why)
        self.assertEqual(got["rax"], 0)
        self.assertTrue(got["buf"].endswith(b"}"))

    def test_indent_overflow_panics_before_any_write(self):
        got, why = run(make_case("body", cur=t.M64))
        self.assertIsNone(why)
        self.assertEqual(got["panic"], ("add_overflow_panic", t.INDENT_PANIC_LOC))
        self.assertEqual(got["len"], 0)

    def test_reserve_rules(self):
        got, why = run(make_case("body", gas=10 ** 19, cap_slack=0, indent=b""))
        self.assertIsNone(why)
        res = [r[2] for r in got["calls"] if r[0] == "vec_reserve"]
        self.assertEqual(res[:5], [1, 1, 1, 21, 1])  # '{', '\n', '"', "destination_recipient" run, '"'
        self.assertIn(20, res)  # the 20 digits of 10^19 do not fit the spare capacity


class EntryBehavior(unittest.TestCase):
    def test_rest_state(self):
        got, why = run(make_case("gasf", gas=42, first=2, cur=1, key=b"k"))
        self.assertIsNone(why)
        self.assertEqual(got["buf"], b',\n  "k": 42')
        self.assertEqual(got["cmp"][1], 2)

    def test_state_one_panics_in_key_writer(self):
        for g in ("chainf", "gasf", "noncef", "dataf"):
            with self.subTest(group=g):
                got, why = run(make_case(g, state=1))
                self.assertIsNone(why)
                self.assertEqual(got["panic"], ("unreachable_panic", (t.UNREACHABLE_MSG, t.UNREACHABLE_LEN)))
                self.assertEqual(got["len"], 0)

    def test_other_states_behave_as_map(self):
        got, why = run(make_case("noncef", state=2, key=b"nonce", nonce=5))
        self.assertIsNone(why)
        self.assertEqual(got["buf"], b'\n"nonce": 5')

    def test_data_entry_hands_ptr_and_len(self):
        c = make_case("dataf", key=b"data", base=t.RECORD)
        got, why = run(c)
        self.assertIsNone(why)
        st = c["st"]
        self.assertEqual(got["calls"], [("bytes_writer", t.u(st, t.RECORD + 8, 8), t.u(st, t.RECORD + 0x10, 8),
                                         "ser")])
        self.assertEqual(got["buf"], b'\n"data": ')

    def test_itoa_reserve_edge(self):
        for slack, want in ((5 + 2, [3]), (5 + 3, [])):  # 5 bytes before the digits: \n "" ": "
            with self.subTest(slack=slack):
                got, why = run(make_case("gasf", key=b"", gas=123, cap_slack=slack, indent=b""))
                self.assertIsNone(why)
                self.assertEqual([r[2] for r in got["calls"] if r[0] == "vec_reserve"], want)

    def test_escape_arms(self):
        key = b'a"b\\c\x01\x08\t\n\x0c\r\x1f\x7f\xc3'
        got, why = run(make_case("dataf", key=key, indent=b""))
        self.assertIsNone(why)
        self.assertEqual(got["buf"], b'\n"a\\"b\\\\c\\u0001\\b\\t\\n\\f\\r\\u001f\x7f\xc3": ')

    def test_escape_reserve_edges(self):
        for slack in range(0, 12):
            with self.subTest(slack=slack):
                got, why = run(make_case("chainf", key=b"\x02x\"", cap_slack=slack, indent=b""))
                self.assertIsNone(why)


class ItoaBehavior(unittest.TestCase):
    def test_digits(self):
        for g, size in (("itoa64", 20), ("itoa64b", 20), ("itoa32", 10)):
            for v in t.U64_EDGES:
                with self.subTest(group=g, v=v):
                    got, why = run(itoa_case(g, v))
                    self.assertIsNone(why)
                    want = v & 0xffffffff if g == "itoa32" else v
                    self.assertEqual(got["buf"][size - got["rdx"]:], b"%d" % want)

    def test_buffer_prefix_untouched(self):
        for g, size in (("itoa64", 20), ("itoa32", 10)):
            got, why = run(itoa_case(g, 5))
            self.assertIsNone(why)
            self.assertEqual(got["buf"][:size - 1], bytes(range(0x40, 0x40 + size - 1)))
            self.assertEqual(got["rax"], t.ITB_AT + size - 1)


class WidthAndOrder(unittest.TestCase):
    def test_u32_itoa_ignores_upper_half_of_rdi(self):
        for v in (0, 1, 4294967295, 123456789):
            for junk in (1, 0xdeadbeef, 0xffffffff):
                with self.subTest(v=v, junk=junk):
                    got, why = run(itoa_case("itoa32", v | junk << 32))
                    self.assertIsNone(why)
                    self.assertEqual(got["buf"][10 - got["rdx"]:], b"%d" % v)

    def test_u64_copies_agree(self):
        for v in (0, 7, 10 ** 10, t.M64, 1 << 63):
            with self.subTest(v=v):
                a, why_a = run(itoa_case("itoa64", v))
                b, why_b = run(itoa_case("itoa64b", v))
                self.assertIsNone(why_a)
                self.assertIsNone(why_b)
                self.assertEqual(a["buf"], b["buf"])
                self.assertEqual(a["rdx"], b["rdx"])

    def test_key_order_is_not_memory_order(self):
        got, why = run(make_case("body", chain=1, gas=2, nonce=3))
        self.assertIsNone(why)
        text = got["buf"]
        pos = [text.index(b'"%s"' % k.encode()) for k, _, _, _ in t.FIELDS]
        self.assertEqual(pos, sorted(pos))
        self.assertEqual([off for _, _, off, _ in t.FIELDS], [0x20, 0x50, 0x40, 0x48, 0x00])

    def test_second_struct_slot_reads_its_own_fields(self):
        c = make_case("body", base=t.RECORD, chain=11, gas=22, nonce=33)
        got, why = run(c)
        self.assertIsNone(why)
        self.assertIn(b'"destination_chain_id": 11,', got["buf"])
        self.assertIn(b'"gas_limit": 22,', got["buf"])
        self.assertIn(b'"nonce": 33,', got["buf"])
        self.assertEqual(got["calls"][0], ("recipient_json", ("S", t.RECORD + 0x20), "ser"))

    def test_entries_leave_state_byte_alone(self):
        for g in ("chainf", "gasf", "noncef", "dataf"):
            for state in (0, 2, 0x80, 0xff):
                with self.subTest(group=g, state=state):
                    got, why = run(make_case(g, state=state, key=b"k"))
                    self.assertIsNone(why)
                    self.assertEqual(got["cmp"][0], state)
                    self.assertEqual(got["cmp"][1], 2)

    def test_state_recheck_arm_is_unreachable_from_the_body(self):
        """The body's error arm needs a non-zero local state byte; no entry writer stores to [compound+0]."""
        s = Shared.load()
        for e in t.ENTRY.values():
            for v, f in t.sweep(s.image, e, s.ext[e]):
                if f["op"] in (0x88, 0xc6) and f["rm"][0] == "m" and f["rm"][4] == 0:
                    self.assertNotIn(f["rm"][1], (3, 14), (hex(e), hex(v)))


class NegativeControls(unittest.TestCase):
    def test_model_mutants_are_detected_on_hand_cases(self):
        cases = {
            "indent-wraps": make_case("body", cur=t.M64),
            "order-data-first": make_case("body"),
            "gas-nonce-swapped": make_case("body"),
            "itoa-hex": make_case("body", gas=10),
            "u32-no-truncate": itoa_case("itoa32", 1 << 40),
            "chain-u64": make_case("body", chain_hi=1),
            "escape-upper-hex": make_case("gasf", key=b"\x1f"),
            "escape-del": make_case("gasf", key=b"\x7f"),
            "first-any-nonzero": make_case("gasf", first=2),
            "end-on-error": make_case("body", fault=0),
            "has-not-cleared": make_case("body", fault=0, has_in=1),
            "data-len-ptr-swapped": make_case("dataf", key=b"data"),
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

    def test_byte_flip_of_chain_offset_is_detected(self):
        """`lea rcx, [rbx+0x50]` -> `[rbx+0x51]` reads the wrong chain id."""
        s = Shared.load()
        code = s.image.code(t.BODY, s.ext[t.BODY] - t.BODY)
        at = t.BODY + code.index(bytes.fromhex("488d4b50")) + 3
        got, why = run(make_case("body", chain=0x12345678), override={at: 0x51})
        self.assertIsNotNone(why)

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
