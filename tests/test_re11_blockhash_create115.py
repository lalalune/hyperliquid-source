import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_blockhash_create115 as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-011-blockhash-create-frame-115"


class Family:
    """View of one family: a bare name resolves to the prefixed family name first, then to the shared core."""

    def __init__(self, pfx):
        self._pfx = pfx

    def __getattr__(self, n):
        p = self._pfx
        cand = p.upper() + "_" + n if n.upper() == n else (p.capitalize() + n if n[0].isupper() else p + "_" + n)
        if hasattr(tool, cand):
            return getattr(tool, cand)
        return getattr(tool, n)


class SharedLayout(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()

    def test_both_families_read_the_same_tables(self):
        rows = tool.shared_layout(self.image)
        self.assertEqual(rows["0x6441210"], {"SLOAD": "0x2993ff0", "BLOCKHASH": "0x2995350",
                                             "CREATE": "0x299bea0", "CREATE2": "0x299b760"})
        self.assertEqual(rows["0x6441f00"], {"SLOAD": "0x2993bd0", "BLOCKHASH": "0x29951e0",
                                             "CREATE": "0x299bea0", "CREATE2": "0x299b760"})

    def test_moved_slot_rejected(self):
        for slot, value in ((0x6441f00 + 8 * 0x40, 0x2995350), (0x6441210 + 8 * 0xf5, 0x299bea0),
                            (0x6441f00 + 8 * 0x54, 0x2993ff0)):
            with self.subTest(slot=hex(slot)):
                saved = dict(self.image.relative)
                try:
                    self.image.relative[slot] = value
                    with self.assertRaises(tool.ToolError):
                        tool.shared_layout(self.image)
                finally:
                    self.image.relative = saved

    def test_sample_listing_keeps_every_eighth_row(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "x.tsv"
            p.write_text("h\n" + "".join(f"{i}\n" for i in range(20)))
            pin = tool.sample_listing(p)
            self.assertEqual(pin["rows"], 20)
            self.assertEqual(p.read_text(), "h\n0\n8\n16\n")

    def test_packet_summary_totals(self):
        summary = json.loads((PACKET / "summary.json").read_text())
        self.assertEqual(summary["binary_sha256"], tool.SHA256)
        parts = summary["parts"]
        self.assertEqual(summary["cases"], sum(p["cases"] for p in parts.values()))
        self.assertEqual(summary["mismatches"], 0)
        nc = summary["negative_controls"]
        self.assertEqual(nc["total"], nc["detected"])
        self.assertEqual(nc["total"], sum(p["negative_controls"]["total"] for p in parts.values()))


class BlockHash115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = t = Family("bh")
        cls.image = tool.load_image()
        cls.cases = t.all_cases()

    def detected(self, mut=frozenset(), override=None):
        # scan the full case list until the first mismatch, so rare paths are not sampled away
        _, bad, _ = self.t.evaluate(self.image, override=override, mut=mut, stop_on_first=True, cases=self.cases)
        return bad > 0

    def test_wrong_digest_rejected(self):
        data = bytearray(tool.BINARY.read_bytes())
        data[self.image.text["offset"] + 1] ^= 0x40
        with self.assertRaises(tool.ToolError):
            tool.Image(bytes(data))

    def test_code_outside_text_rejected(self):
        end = self.image.text["address"] + self.image.text["size"]
        with self.assertRaises(tool.ToolError):
            self.image.code(end + 0x10, 4)
        with self.assertRaises(tool.ToolError):
            self.image.code(end - 2, 4)

    def test_static_constants(self):
        consts, decoded = self.t.static_evidence(self.image)
        self.assertEqual(consts["calls"]["0x29951e0"], {"0x29952e8": "got 0x64e6450 -> 0x43c8b20"})
        self.assertEqual(consts["calls"]["0x2995350"], {"0x299557c": "got 0x64e6450 -> 0x43c8b20",
                                                        "0x2995695": "got 0x64e6df0 -> 0x4efb820"})
        self.assertEqual(consts["functions"]["0x29951e0"]["instructions"], 100)
        self.assertEqual(consts["functions"]["0x2995350"]["instructions"], 220)
        slots = consts["opcode_table_slots"]
        self.assertEqual(slots["0x6441210+0x200"], {"opcode": "0x40", "target": "0x2995350"})
        self.assertEqual(slots["0x6441f00+0x200"], {"opcode": "0x40", "target": "0x29951e0"})
        self.assertEqual(slots["0x6441210+0x2a0"]["target"], "0x2993ff0")  # SLOAD anchors the table base
        self.assertEqual(consts["hash_seed"]["target"], "0x64ffe90")
        self.assertFalse(consts["hash_seed"]["target_section_has_file_bytes"])
        self.assertEqual(sorted(decoded), sorted(self.t.FUNCS))

    def test_wrong_opcode_slot_rejected(self):
        saved = dict(self.image.relative)
        try:
            self.image.relative[0x6441210 + 0x200] = 0x29951e0
            with self.assertRaises(tool.ToolError):
                self.t.opcode_slots(self.image)
        finally:
            self.image.relative = saved

    def test_window_examples(self):
        window = self.t.window
        self.assertIsNone(window(100, 100))  # the current block is not served
        self.assertIsNone(window(100, 101))
        self.assertEqual(window(1000, 999), 999)
        self.assertEqual(window(1000, 744), 744)  # exactly 256 back
        self.assertIsNone(window(1000, 743))  # 257 back
        self.assertIsNone(window(0, 0))
        self.assertEqual(window((1 << 64) + 10, (1 << 64) + 9), tool.M64)  # saturating u64 conversion
        self.assertEqual(window((1 << 64) + 10, tool.M64), tool.M64)

    def test_hash_example(self):
        # with secret 0 and seed 1 the hash is the number folded twice by multiply with 1
        self.assertEqual(self.t.number_hash(5, 0, 1), 5)
        self.assertNotEqual(self.t.number_hash(5, 3, 9), self.t.number_hash(5, 3, 9, frozenset(["hash_no_secret"])))

    def test_small_table_mirror(self):
        full = self.t.ctrl_layout(4, [1, 2, 3, 0xff])
        self.assertEqual(full[:4], [1, 2, 3, 0xff])
        self.assertEqual(full[4:16], [0xff] * 12)
        self.assertEqual(full[16:20], [1, 2, 3, 0xff])
        # a probe that lands on padding past a full slot falls back to group 0
        self.assertEqual(self.t.insert_slot(4, [1, 2, 3, 0xff], 1), 3)

    def test_table_needs_an_empty_slot(self):
        c = {"buckets_n": 16, "tombs": [], "decoys": [(i, 1, bytes(32)) for i in range(16)], "order": [],
             "secret": 0, "seed": 1}
        with self.assertRaises(tool.ToolError):
            self.t.build_table(c)

    def test_sample_matches(self):
        _, bad, _ = self.t.evaluate(self.image, cases=self.cases[::5])
        self.assertEqual(bad, 0)

    def test_outcome_families_present(self):
        rows, bad, _ = self.t.evaluate(self.image, cases=self.cases[:1200])
        self.assertEqual(bad, 0)
        seen = {self.t.outcome(c, want, got) for _, c, want, got, _ in rows}
        for want in ("cached/underflow", "cached/zero/out-of-window", "cached/cache-hit", "cached/miss-insert",
                     "cached/miss-insert/reserve", "cached/miss-insert/saturated", "direct/underflow",
                     "direct/zero/out-of-window", "direct/provider", "direct/provider/saturated"):
            self.assertIn(want, seen)

    def test_rejects_changed_check_byte(self):
        data = bytearray(self.image.data)
        sec = self.image.text
        data[0x2995431 - sec["address"] + sec["offset"]] = 0x02
        with self.assertRaises(tool.ToolError):
            self.t.static_evidence(tool.Image(bytes(data), check=False))

    def test_model_mutants_detected(self):
        for name in self.t.MODEL_MUTANTS:
            with self.subTest(name=name):
                self.assertTrue(self.detected(mut=frozenset([name])))

    def test_code_mutants_detected(self):
        for va, byte, _ in self.t.BYTE_MUTANTS:
            with self.subTest(va=hex(va)):
                self.assertNotEqual(self.image.code(va, 1)[0], byte)
                self.assertTrue(self.detected(override={va: byte}))

    def test_packet_cases_sampled(self):
        summary = json.loads((PACKET / "summary.json").read_text())
        self.assertEqual(summary["parts"]["blockhash"]["cases"], len(self.cases))
        rows = (PACKET / "blockhash-cases.tsv").read_text().splitlines()[1:]
        self.assertEqual(len(rows), (len(self.cases) + 7) // 8)
        self.assertTrue(all(r.endswith("\tyes") for r in rows))


class CreateFrame115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = t = Family("cr")
        cls.image = tool.load_image()
        cls.vt = t.vtables(cls.image)
        cls.cases = t.all_cases(cls.vt)
        per = {}
        cls.subset = []
        for c in cls.cases:
            per[c["op"]] = per.get(c["op"], 0) + 1
            if per[c["op"]] <= 600:
                cls.subset.append(c)

    def test_static_pins_and_tables(self):
        fdes, insns = self.t.static_evidence(self.image)
        for op, va in self.t.BODIES.items():
            self.assertIn(va, fdes)
            self.assertEqual(insns[op][0][0], va)
            for table in self.t.OP_TABLES:
                self.assertEqual(self.image.relative[table + 8 * op], va)
        self.assertEqual(self.image.import_name(self.t.MEMCPY_GOT), "memcpy")

    def test_subset_matches(self):
        rows, _ = self.t.evaluate(self.image, cases=self.subset)
        self.assertEqual([r[0]["id"] for r in rows if not r[3]], [])
        kinds = {self.t.outcome(r[0], r[1]).split("+")[0] for r in rows}
        for k in ("create-action", "out-of-gas", "underflow", "not-activated", "static-call", "operand-too-large",
                  "initcode-too-large", "growth-error", "alloc-error-buffer", "add-overflow@0x643e110",
                  "div-zero@0x6443898"):
            self.assertIn(k, kinds)

    def test_model_reference_points(self):
        self.assertEqual(self.t.words32(0), 0)
        self.assertEqual(self.t.words32(33), 2)
        self.assertEqual(self.t.words32(tool.M64), 1 << 59)
        self.assertEqual(self.t.sat_add_i64((1 << 63) - 5, 100), (1 << 63) - 1)
        self.assertEqual(self.t.sat_add_i64(tool.M64, 1), 0)

    def test_model_mutants_detected(self):
        for mt in self.t.MODEL_MUTANTS:
            with self.subTest(mt=mt):
                rows, _ = self.t.evaluate(self.image, mut=frozenset([mt]), stop_on_first=True, cases=self.cases)
                self.assertFalse(rows[-1][3], mt)

    def test_byte_mutants_detected(self):
        for va, value, label in self.t.BYTE_MUTANTS:
            with self.subTest(label=label):
                try:
                    rows, _ = self.t.evaluate(self.image, override={va: value}, stop_on_first=True, cases=self.cases)
                    detected = not rows[-1][3]
                except tool.ToolError:
                    detected = True  # the corrupted code left the modelled contract (same rule as the tool)
                self.assertTrue(detected, label)

    def test_growth_stub_contract_violation_fails(self):
        t = self.t
        c = self.cases[0]
        m = t.CaseMachine(self.image)
        m.case = c
        t.install(m, self.image)
        m.regs[7], m.regs[6], m.regs[2] = t.INTERP_AT + t.I_MEMWORDS + 8, t.INTERP_AT, t.HOST_AT + t.H_PARAMS
        with self.assertRaises(tool.ToolError):
            m.stubs[self.image.word(t.RESIZE_GOT)](m)

    def test_corrupted_pin_fails(self):
        data = bytearray(self.image.data)
        off = 0x299b78c - self.image.text["address"] + self.image.text["offset"]
        data[off] ^= 1
        bad = tool.Image(bytes(data), check=False)
        with self.assertRaises(tool.ToolError):
            self.t.static_evidence(bad)

    def test_wrong_digest_rejected(self):
        data = bytearray(self.image.data)
        data[0x2000] ^= 0xff
        with self.assertRaises(tool.ToolError):
            tool.Image(bytes(data))

    def test_out_of_range_code_rejected(self):
        with self.assertRaises(tool.ToolError):
            self.image.code(self.image.text["address"] + self.image.text["size"] - 2, 8)

    def test_packet_summary_consistent(self):
        summary = json.loads((PACKET / "summary.json").read_text())["parts"]["create-frame"]
        self.assertEqual(summary["cases"], len(self.cases))
        self.assertEqual(summary["mismatches"], 0)
        self.assertEqual(summary["negative_controls"]["total"], summary["negative_controls"]["detected"])
        self.assertNotIn("no:unreached", summary["instruction_reach"])
        ids = [line.split("\t")[0] for line in (PACKET / "create-frame-cases.tsv").read_text().splitlines()[1:]]
        self.assertEqual(ids, [c["id"] for c in self.cases][::8])

    def test_packet_functions_regenerate(self):
        fdes, _ = self.t.static_evidence(self.image)
        rows = (PACKET / "create-frame-functions.tsv").read_text().splitlines()[1:]
        for op, va in self.t.BODIES.items():
            s, e = fdes[va]
            self.assertIn(f"handler\t{self.t.name(op)}\t{s:#x}\t{e:#x}", "\n".join(rows))


if __name__ == "__main__":
    unittest.main()
