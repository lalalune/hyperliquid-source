import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re16_db_home_chain115 as tool  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-016-db-home-chain-115"
LOADED = []


def shared_image():
    """The checked image, read once for the whole module."""
    if not LOADED:
        LOADED.append(tool.Image(tool.BINARY.read_bytes()))
    tool.load_consts(LOADED[0])
    return LOADED[0]


class DbHomeChainTests(unittest.TestCase):
    def setUp(self):
        self.image = shared_image()
        self.cache = {w: tool.all_cases(w)[:300] for w in "abcd"}

    def test_each_function_matches_the_model(self):
        for which in "abcd":
            rows, bad, _ = tool.evaluate(self.image, which, cases=self.cache[which])
            self.assertEqual(bad, 0, which)
            self.assertEqual(len(rows), 300)

    def test_every_body_instruction_is_executed(self):
        consts, _, _ = tool.static_evidence(self.image)
        for which in "abcd":
            _, _, m = tool.evaluate(self.image, which, cases=tool.all_cases(which))
            lo = tool.FUNCS[which]
            pad = int(consts["functions"][which]["landing_pad_start"], 16)
            decoded = tool.sweep(self.image, lo, int(consts["functions"][which]["fde_end"], 16))
            body = [va for va, f in decoded if va < pad and f["op"] != 0x0f1f]   # alignment NOPs are never fallen into
            self.assertEqual([va for va in body if va not in m.seen], [], which)

    def test_model_mutants_are_caught(self):
        for which, name in tool.MODEL_MUTANTS:
            _, bad, _ = tool.evaluate(self.image, which, mut=frozenset([name]), stop_on_first=True,
                                      cases=tool.all_cases(which))
            self.assertGreater(bad, 0, name)

    def test_code_mutants_are_caught(self):
        for which, va, old, new, what in tool.BYTE_MUTANTS:
            self.assertEqual(self.image.code(va, 1)[0], old, what)
            _, bad, _ = tool.evaluate(self.image, which, override={va: new}, stop_on_first=True,
                                      cases=tool.all_cases(which))
            self.assertGreater(bad, 0, what)

    def test_corrupted_binary_is_refused(self):
        data = bytearray(self.image.data)
        data[self.image.text["offset"] + 100] ^= 0x10
        with self.assertRaises(tool.ToolError):
            tool.Image(bytes(data))

    def test_address_outside_text_is_refused(self):
        with self.assertRaises(tool.ToolError):
            self.image.code(self.image.text["address"] + self.image.text["size"], 4)

    def test_unknown_function_start_is_refused(self):
        with self.assertRaises(tool.ToolError):
            tool.fde_rows(self.image, [tool.FN_A + 1])

    def test_second_caller_runs_the_trio_for_real(self):
        rows, bad, _ = tool.evaluate(self.image, "d", cases=tool.all_cases("d")[:400])
        self.assertEqual(bad, 0)
        names = {call[0] for _, want, _, _ in rows for call in want["calls"]}
        for needed in ("save_records", "list", "fmt_write", "cp", "alloc", "block", "dealloc", "expect_failed"):
            self.assertIn(needed, names)
        ok = [w for _, w, _, _ in rows if w["abort"] is None]
        self.assertTrue(ok)
        for want in ok:
            self.assertEqual(want["calls"][-1][0] in ("dealloc", "block"), True)

    def test_format_texts_come_from_the_bytes(self):
        want = {0x43b857: "{}", 0x43aa84: "{}/{}", 0x434739: "{}/checkpoint", 0x44f3c9: "{}/lt_hashes.json"}
        for va, text in want.items():
            self.assertEqual(tool.parse_pieces(self.image, va)[0], text)
        with self.assertRaises(tool.ToolError):
            tool.parse_pieces(self.image, 0x43b858)

    def test_operation_plans_hold_on_every_case(self):
        for which in "abcd":
            rows, bad, _ = tool.evaluate(self.image, which, cases=self.cache[which])
            for c, want, got, ok in rows:
                mode_zero = which == "d" or (which == "b" and not c["mode"] & 0xff)
                self.assertEqual(tool.plan_errors(which, tool.plan_of(got["calls"]), mode_zero, bool(got["abort"])), [])

    def test_plan_mutations_are_caught(self):
        full = sorted(tool.b_full_plans())
        self.assertEqual(len(full), 8)
        bad = ("is_dir", "cp", "write_state", "join_kind")
        self.assertTrue(tool.plan_errors("b", bad, False, False))
        self.assertTrue(tool.plan_errors("a", ("is_dir", "remove_dir"), False, False))
        self.assertTrue(tool.plan_errors("d", ("cp", "cp", "write_state"), True, False))
        self.assertFalse(tool.plan_errors("b", full[0], False, False))

    def test_decision_flip_changes_the_trace(self):
        c = dict(self.cache["b"][0])
        base = tool.model_b(c)
        c["gate"] = 0 if c["gate"] else 1
        self.assertNotEqual(base["calls"], tool.model_b(c)["calls"])

    def test_committed_evidence_matches_regeneration(self):
        if not FOLDER.exists():
            self.skipTest("evidence folder is not part of this checkout")
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp)
            tool.generate(out)
            for f in sorted(out.iterdir()):
                self.assertEqual(f.read_bytes(), (FOLDER / f.name).read_bytes(), f.name)
            measure = json.loads((out / "measure.json").read_text())
            self.assertGreaterEqual(measure["cases"], 10000)
            self.assertEqual(measure["negative_controls"], measure["negative_detected"])
            self.assertGreaterEqual(measure["negative_controls"], 30)

    def test_manifest_hashes(self):
        manifest = FOLDER / "MANIFEST.sha256"
        if not manifest.exists():
            self.skipTest("evidence folder is not part of this checkout")
        for line in manifest.read_text().splitlines():
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)


def names(calls):
    return [c[0] for c in calls]


def base_case(which, **fields):
    """A deterministic case with every optional outcome off, then overridden by the keyword fields."""
    c = tool.make_case(tool.Stream("hand-written-" + which), which, 1)
    c.update({"gate": 0, "fw": [0, 0, 0], "isdir": [1, 1, 1], "isfile": [0, 0, 0], "cp": [0, 0], "mkdir": 0, "cpf": 0,
              "rm": 0, "op09": 0, "wstate": 0, "mk": 0})
    c.update(fields)
    return c


class HandWrittenFlowTests(unittest.TestCase):
    """The flows written out by hand from the disassembly, independent of the case generator."""

    def setUp(self):
        self.image = shared_image()

    def run_real(self, which, c):
        m = tool.TraceMachine(self.image)
        got = tool.run_case(m, c, which)
        self.assertTrue(tool.compare(c, tool.MODELS[which](c), got, which))
        return got

    def test_a_removes_only_after_two_positive_probes(self):
        got = self.run_real("a", base_case("a"))
        self.assertEqual(names(got["calls"])[:5], ["fmt_write", "is_dir", "fmt_format", "is_dir", "remove_dir"])
        got = self.run_real("a", base_case("a", isdir=[0, 1, 1]))
        self.assertNotIn("remove_dir", names(got["calls"]))
        self.assertNotIn("fmt_format", names(got["calls"]))

    def test_a_gate_adds_exactly_one_diagnostic(self):
        quiet = names(self.run_real("a", base_case("a"))["calls"]).count("log")
        loud = names(self.run_real("a", base_case("a", gate=7))["calls"]).count("log")
        self.assertEqual((quiet, loud), (0, 1))

    def test_b_mode_zero_is_one_copy_and_the_state_write(self):
        got = self.run_real("b", base_case("b", mode=0, strs=base_case("b")["strs"]))
        ops = tool.plan_of(got["calls"])
        self.assertEqual(ops, ("is_dir", "cp", "write_state"))

    def test_b_missing_directory_is_created_with_mode_and_recursion(self):
        got = self.run_real("b", base_case("b", mode=0, isdir=[0, 1, 1]))
        create = [c for c in got["calls"] if c[0] == "create_dir"]
        self.assertEqual(len(create), 1)
        self.assertEqual(create[0][4], (0x1ff, 1))

    def test_b_checkpoint_route_with_marker_present_stops_early(self):
        got = self.run_real("b", base_case("b", mode=1, isfile=[1, 0, 0]))
        self.assertEqual(tool.plan_of(got["calls"]), ("is_dir", "cp", "join_kind", "is_file", "write_state"))

    def test_b_checkpoint_route_full(self):
        got = self.run_real("b", base_case("b", mode=1, isfile=[0, 1, 0]))
        self.assertEqual(tool.plan_of(got["calls"]),
                         ("is_dir", "cp", "join_kind", "is_file", "cp", "join_kind", "op_09e0", "is_file", "copy_file",
                          "write_state"))

    def test_b_only_the_low_mode_byte_counts(self):
        a = tool.plan_of(self.run_real("b", base_case("b", mode=0x100))["calls"])
        b = tool.plan_of(self.run_real("b", base_case("b", mode=0))["calls"])
        self.assertEqual(a, b)

    def test_c_sort_choice_by_item_count(self):
        want = {0: None, 1: None, 2: "sort_small", 20: "sort_small", 21: "sort_big", 40: "sort_big"}
        for n, sort in want.items():
            c = base_case("c", nitems=n, alloc=[0x200000, 0x300000, 0x400000, 0x500000], state_len=0)
            c["state"] = tool.w64(0, tool.SDATA_AT, 0)
            got = self.run_real("c", c)
            seen = [x for x in names(got["calls"]) if x.startswith("sort")]
            self.assertEqual(seen, [sort] if sort else [], n)

    def test_c_block_words(self):
        c = base_case("c", nitems=3, alloc=[0x200000, 0x300000, 0x400000, 0x500000], tree=(9, 8, 7))
        got = self.run_real("c", c)
        self.assertEqual(tool.u(got["box"], 0, 16), tool.u(tool.w64(1, 1), 0, 16))
        self.assertEqual(tool.u(got["box"], 0x28, 8), 9)
        self.assertEqual(tool.u(got["box"], 0x30, 8), 8)
        self.assertEqual(tool.u(got["box"], 0x38, 8), 7)

    def test_d_key_and_sentinel_rules(self):
        b = 0x1234
        ents = [(5, 0x1000, 3, b + 1), (tool.SENT, 0x2000, 3, b), (6, 0x3000, 4, b), (7, 0x4000, 5, b)]
        c = base_case("d", b=b, entries=ents, lcap=0)
        got = self.run_real("d", c)
        deallocs = [x for x in got["calls"] if x[0] == "dealloc"]
        self.assertEqual(deallocs[0][1:], (("abs", 0x1000), 5, 0))     # key mismatch: text freed
        self.assertEqual(deallocs[1][1:], (("abs", 0x4000), 7, 0))     # entry after the found one: freed
        c = base_case("d", b=b, entries=[(tool.SENT, 0x2000, 3, b)], lcap=0)
        got = self.run_real("d", c)
        self.assertEqual(got["calls"][-1][0], "expect_failed")


if __name__ == "__main__":
    unittest.main()
