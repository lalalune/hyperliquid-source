"""Tests for tools/adl_shortfall_budget.py: evidence bytes and negative controls."""
import filecmp
import hashlib
import pathlib
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import adl_shortfall_budget as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-004-adl-shortfall-budget-94"
BUMP_FN = tool.BUMP_FUNCTIONS[0]
SETTER = tool.DISPATCHERS[0]
BLOCK = 0x2357503


def bump_ok(image, fn=BUMP_FN):
    for mode in (0, tool.MAINNET):
        tool.check_bump(tool.bump_pieces(image, fn, mode), mode, fn)


def date_ok(image, fn=BUMP_FN):
    for date_b in tool.DATE_EDGES:
        tool.check_date(tool.date_pieces(image, fn, date_b), fn, date_b)


def setter_ok(image, dispatcher=SETTER):
    for mode in (0, tool.MAINNET):
        rows = tool.without_exit(tool.setter_pieces(image, dispatcher, mode))
        if rows != tool.expected_setter(mode):
            raise tool.ToolError(f"setter rows differ: {rows}")


def set_up(cls):
    cls.image = tool.Image(tool.load_target())
    cls.result = tool.analyse(cls.image)


class Evidence(unittest.TestCase):
    setUpClass = classmethod(set_up)

    def test_generated_files_match_the_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            tool.write_evidence(self.result, temp)
            names = sorted(path.name for path in pathlib.Path(temp).iterdir())
            kept = sorted(path.name for path in FOLDER.iterdir() if path.name not in ("README.md", "MANIFEST.sha256"))
            self.assertEqual(names, kept)
            for name in names:
                self.assertTrue(filecmp.cmp(pathlib.Path(temp) / name, FOLDER / name, shallow=False), name)

    def test_manifest(self):
        rows = (FOLDER / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
        listed = {}
        for row in rows:
            digest, name = row.split("  ", 1)
            listed[name] = digest
        names = {path.name for path in FOLDER.iterdir()} - {"MANIFEST.sha256"}
        self.assertEqual(set(listed), names)
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_counts(self):
        self.assertEqual(len(self.result["bump_rows"]), 18)
        self.assertEqual(len(self.result["setter_rows"]), 18)
        self.assertEqual(len(self.result["debit_rows"]), 121)
        self.assertEqual(len(self.result["gate_rows"]), 121)
        self.assertEqual(self.result["kinds"]["value_read_0x248"], 6)
        self.assertEqual(self.result["kinds"]["size_pass_0x248"], 3)
        self.assertEqual(self.result["recorder"], "l1/src/qtys/impl_ntl.rs:26:1")
        self.assertEqual(self.result["texts"][tool.TAG_ABOVE_CAP][2], "Adl shortfall too large")

    def test_every_piece_list_covers_the_whole_domain(self):
        for rows in ([r[:5] for r in self.result["bump_rows"]], [r[:5] for r in self.result["setter_rows"]]):
            groups = {}
            for first, second, name, lo, hi in rows:
                groups.setdefault((first, second, name), []).append((lo, hi))
            for pieces in groups.values():
                self.assertEqual(pieces[0][0], 0)
                self.assertEqual(pieces[-1][1], tool.U64)
                for left, right in zip(pieces, pieces[1:]):
                    self.assertEqual(left[1] + 1, right[0])

    def test_closed_form_at_every_piece_end(self):
        for fn, _, name, lo, hi, _, form, recorded in self.result["bump_rows"]:
            mode = tool.MAINNET if name == "byte_3" else 0
            cap = tool.CAP_MAINNET if mode == tool.MAINNET else tool.CAP_OTHER
            for x in (lo, hi):
                self.assertEqual(tool.apply(form, x), min(cap, min(x + tool.BUMP, tool.U64)))
                self.assertEqual(bool(recorded), x + tool.BUMP > tool.U64)

    def test_date_guard_is_signed_less_than(self):
        rows = [r for r in self.result["date_rows"] if r[0] == BUMP_FN and r[1] == 0]
        self.assertEqual(rows, [(BUMP_FN, 0, 0, 0x7fffffff, "unchanged"),
                                (BUMP_FN, 0, 0x80000000, 0xffffffff, "bumped")])


class Controls(unittest.TestCase):
    setUpClass = classmethod(set_up)

    def mutated(self, va, raw):
        return self.image.patched([(va, bytes.fromhex(raw))])

    def test_wrong_hash(self):
        saved = tool.SHA256
        tool.SHA256 = saved[:-1] + ("0" if saved[-1] != "0" else "1")
        try:
            with self.assertRaises(tool.ToolError):
                tool.load_target()
        finally:
            tool.SHA256 = saved

    def test_nobits_sections_are_not_resolved(self):
        self.assertTrue(all(s["type"] != 8 for s in self.image.sections))
        bss = next(s for s in tool.elf_index.sections(self.image.data) if s["name"] == ".bss")
        with self.assertRaises(tool.ToolError):
            self.image.file_offset(bss["address"] + 1)

    def test_address_outside_every_fde(self):
        with self.assertRaises(tool.ToolError):
            self.image.fde_of(0x10)

    def test_bump_mutations(self):
        threshold = struct.pack("<Q", tool.U64 + 1 - tool.BUMP + 1).hex()
        amount = struct.pack("<Q", tool.BUMP + 1).hex()
        edits = [(0x2702373, threshold), (0x2702382, amount), (0x270237e, "77"), (0x27023a7, "45"), (0x27023ae, "42"),
                 (0x2702390, "02"), (0x27023c7, "909090909090")]
        for va, raw in edits:
            with self.subTest(va=hex(va)), self.assertRaises(tool.ToolError):
                bump_ok(self.mutated(va, raw))

    def test_bump_mutation_in_every_copy(self):
        for fn in tool.BUMP_FUNCTIONS:
            with self.subTest(fn=hex(fn)), self.assertRaises(tool.ToolError):
                bump_ok(self.mutated(fn + 0x60, "02"), fn)

    def test_state_offsets_are_held_to_the_known_layouts(self):
        with self.assertRaises(tool.ToolError):
            tool.bump_layout(self.mutated(0x270234e, "f3"), BUMP_FN)
        with self.assertRaises(tool.ToolError):
            tool.setter_layout(self.mutated(BLOCK + 8, "f3"), SETTER)

    def test_wrong_field_is_an_unread_slot(self):
        with self.assertRaises(tool.ToolError):
            bump_ok(self.mutated(0x270236d, "40"))

    def test_date_mutations(self):
        for raw in ("7f", "73"):
            with self.subTest(raw=raw), self.assertRaises(tool.ToolError):
                date_ok(self.mutated(0x270233b, raw))

    def test_setter_mutations(self):
        limit = struct.pack("<Q", tool.WIRE_LIMIT - 1).hex()
        cap = struct.pack("<Q", tool.CAP_OTHER + 1).hex()
        edits = [(0x2357554, "83"), (0x2357523, limit), (0x2357544, cap), (0x235754e, "45"), (0x2357537, "02"),
                 (0x235752f, "87")]
        for va, raw in edits:
            with self.subTest(va=hex(va)), self.assertRaises(tool.ToolError):
                setter_ok(self.mutated(va, raw))

    def test_setter_mutation_in_every_copy(self):
        for dispatcher in tool.DISPATCHERS:
            block = tool.setter_layout(self.image, dispatcher)["block"]
            image = self.mutated(block + 0x1a + (0 if dispatcher == SETTER else -2), "04")
            with self.subTest(dispatcher=hex(dispatcher)), self.assertRaises(tool.ToolError):
                setter_ok(image, dispatcher)

    def test_jump_table_entry(self):
        table, block = tool.dispatch_block(self.image, SETTER, tool.CASE_REMAINING)
        self.assertEqual(block, BLOCK)
        other = tool.dispatch_block(self.image, SETTER, tool.CASE_FEE)[1]
        image = self.image.patched([(table + 4 * tool.CASE_REMAINING, struct.pack("<i", other - table))])
        with self.assertRaises(tool.ToolError):
            tool.setter_layout(image, SETTER)

    def test_debit_mutations(self):
        for va, raw in ((0x370389c, "42"), (0x370387f, "78"), (0x3703898, "01")):
            image = self.mutated(va, raw)
            wrong = 0
            with self.subTest(va=hex(va)):
                for x in tool.EDGES_I64:
                    for budget in tool.EDGES_U64:
                        try:
                            wrong += tool.debit_run(image, x & tool.U64, budget) != tool.debit_model(x, budget)
                        except tool.ToolError:
                            wrong += 1
                self.assertGreater(wrong, 0)

    def test_gate_mutation(self):
        image = self.mutated(tool.SITE_GATE + 12, "83")
        self.assertEqual(tool.gate_run(self.image, 1, 2), "skip")
        self.assertEqual(tool.gate_run(image, 1, 2), "collect")

    def test_static_bytes(self):
        tool.static_checks(self.image)
        edits = [(BUMP_FN + tool.SATURATE_OFFSET + 3, "7f"), (tool.SITE_INIT + 7, "01"), (tool.SITE_POINTER + 3, "50"), (tool.SITE_GATE + 9, "39"),
                 (tool.SITE_DEBIT + 3, "25"), (tool.SITE_LOG_ARGS + 4, "81"), (tool.SITE_DEBIT_DEX, "4c"),
                 (tool.SITE_FLAG + 11, "02"), (0x222a277 - 1, "90"), (0x222a27c, "90"), (0x59c9bf, "42")]
        for va, raw in edits:
            with self.subTest(va=hex(va)), self.assertRaises(tool.ToolError):
                tool.static_checks(self.mutated(va, raw))

    def test_extra_immediate_is_counted(self):
        image = self.image.patched([(0x2702420, struct.pack("<Q", tool.BUMP))])
        with self.assertRaises(tool.ToolError):
            tool.analyse(image)

    def test_field_key_sites_need_the_load(self):
        image = self.mutated(0x370c8a4 - 5, "40")
        kinds = tool.field_rows(image)[1]
        self.assertEqual(sum(row[3] == "value_read_0x248" for row in kinds), 5)

    def test_unknown_opcode_stops_the_evaluator(self):
        with self.assertRaises(tool.ToolError):
            bump_ok(self.mutated(BUMP_FN + 6, "f4"))

    def test_refine_rejects_a_cut_outside_the_interval(self):
        def run(lo, hi):
            raise tool.Split(hi + 1)
        with self.assertRaises(tool.ToolError):
            tool.refine(run, 0, 10)

    def test_tool_calls_no_external_program(self):
        source = (ROOT / "tools" / "adl_shortfall_budget.py").read_text(encoding="utf-8")
        self.assertNotIn("subprocess", source)
        self.assertNotIn("os.system", source)

    def test_format_pieces(self):
        pieces = tool.format_pieces(self.image, 0x1e5653)
        self.assertEqual(pieces[1], f"] {chr(64)} [self.adl_shortfall_remaining: ")
        self.assertEqual(tool.safe_text(pieces)[1], "] [at] [self.adl_shortfall_remaining: ")


if __name__ == "__main__":
    unittest.main()
