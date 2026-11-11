import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import json_pretty_writers_115 as t  # noqa: E402
from decimal_scaled_u64 import ToolError  # noqa: E402


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.img = t.new_image()
        cls.tab = t.derive_tables(cls.img)

    def obs(self, group, case):
        got, _ = t.observe(group, self.img, self.tab, case)
        return got


class TablesFromBytes(Base):
    def test_escape_table_is_the_serde_json_table(self):
        self.assertEqual(self.tab["esc"], t.CANON_ESCAPE)
        self.assertEqual(self.tab["esc"][0x0a], ord("n"))
        self.assertEqual(self.tab["esc"][0x7f], 0)
        self.assertEqual(self.tab["esc"][0x1f], ord("u"))

    def test_hex_digits_are_lower_case(self):
        self.assertEqual(self.tab["hex"], b"0123456789abcdef")

    def test_decimal_pairs_and_key_text(self):
        self.assertEqual(self.tab["lut"], b"".join(b"%02d" % i for i in range(100)))
        self.assertEqual(self.tab["key"], b"exchange")

    def test_copy_slot_is_memcpy(self):
        self.assertEqual(t.copy_symbol_name(self.img), "memcpy")

    def test_function_extents_cover_entries(self):
        for _, start in t.FUNCTIONS:
            lo, hi = self.img.fde_of(start)
            self.assertEqual(lo, start)
            self.assertGreater(hi, lo)

    def test_function_rows_hash_the_fde_bytes(self):
        rows = {r[0]: r for r in t.function_rows(self.img)}
        lo, hi = self.img.fde_of(t.F_KEY)
        self.assertEqual(rows["object_key"][5], hashlib.sha256(t.read_va(self.img, lo, hi - lo)).hexdigest())


class Goldens(Base):
    """Hand-derived expectations, independent of the reference functions."""

    def test_escape_golden(self):
        data = b'a"\\\n\x01\x7f\xe9'
        want = b'a\\"\\\\\\n\\u0001\x7f\xe9'
        self.assertEqual(self.obs("escape", (b"", data, 64)), ("ret", want))

    def test_escape_unicode_uses_lower_hex(self):
        self.assertEqual(self.obs("escape", (b"", b"\x1f\x0b", 4)), ("ret", b"\\u001f\\u000b"))

    def test_escape_empty_input_writes_nothing(self):
        self.assertEqual(self.obs("escape", (b"zz", b"", 2)), ("ret", b"zz"))

    def test_key_first_and_later_entries(self):
        self.assertEqual(self.obs("key", (b"", 0, 1, b"  ", 1, b"k", 2)), ("ret", b'\n  "k"', 2))
        self.assertEqual(self.obs("key", (b"", 0, 2, b"  ", 2, b"k", 2)), ("ret", b',\n    "k"', 2))

    def test_key_with_error_byte_panics(self):
        self.assertEqual(self.obs("key", (b"", 1, 1, b" ", 1, b"k", 8))[0], "panic")

    def test_key_depth_zero_has_no_indent(self):
        self.assertEqual(self.obs("key", (b"", 0, 2, b"\t", 0, b"a", 0)), ("ret", b',\n"a"', 2))

    def test_array_golden(self):
        want = b"[\n    0,\n    9,\n    10,\n    99,\n    100,\n    255\n  ]"
        got = self.obs("array", (b"", b"  ", 1, bytes([0, 9, 10, 99, 100, 255]), 7))
        self.assertEqual(got, ("ret", want, (1, 1)))

    def test_array_empty_has_no_newline(self):
        self.assertEqual(self.obs("array", (b"", b" ", 2, b"", 0)), ("ret", b"[]", (2, 0)))

    def test_array_depth_counter_overflow_panics(self):
        self.assertEqual(self.obs("array", (b"", b" ", t.U64, b"\x01", 9))[0], "panic")

    def test_end_only_closes_when_state_nonzero(self):
        self.assertEqual(self.obs("end", (b"", 0, 0, 4)), ("ret", b""))
        self.assertEqual(self.obs("end", (b"", 0, 2, 0)), ("ret", b"}"))
        self.assertEqual(self.obs("end", (b"", 1, 2, 4))[0], "panic")

    def test_close_golden(self):
        self.assertEqual(self.obs("close", (b"", b"  ", 2, 1, 0)), ("ret", b"\n  }", (1, 1)))
        self.assertEqual(self.obs("close", (b"", b"  ", 1, 0, 0)), ("ret", b"}", (0, 0)))
        self.assertEqual(self.obs("close", (b"", b"  ", 0, 1, 8))[0], "panic")

    def test_begin_golden_success_path(self):
        got = self.obs("begin", (b"", b" ", 0, False, 3))
        self.assertEqual(got[:3], ("ret", b'{\n "exchange": <V>\n}', (0, 1)))
        self.assertEqual(got[4], 0)

    def test_begin_value_failure_keeps_depth_and_skips_close(self):
        got = self.obs("begin", (b"", b" ", 1, True, 3))
        self.assertEqual(got[:3], ("ret", b'{\n  "exchange": <V>', (2, 0)))
        self.assertEqual(got[4], 0x1234)

    def test_begin_overflow_panics(self):
        self.assertEqual(self.obs("begin", (b"", b" ", t.U64, False, 9))[0], "panic")


class Agreement(Base):
    def test_every_group_agrees_on_a_sample(self):
        for group in t.GROUPS:
            for case in t.gen_cases(group, 45):
                got, _ = t.observe(group, self.img, self.tab, case)
                self.assertEqual(t.comparable(group, got), t.comparable(group, t.expected(group, self.tab, case)),
                                 (group, case))

    def test_output_does_not_depend_on_the_starting_capacity(self):
        data = bytes(range(0, 50))
        outs = {t.observe("escape", self.img, self.tab, (b"p", data, cap))[0] for cap in (1, 2, 9, 64, 1000)}
        self.assertEqual(len(outs), 1)

    def test_tight_capacity_forces_growth(self):
        _, grown = t.observe("escape", self.img, self.tab, (b"", b"abc\n", 0))
        self.assertGreater(grown, 0)
        _, roomy = t.observe("escape", self.img, self.tab, (b"", b"abc\n", 100))
        self.assertEqual(roomy, 0)

    def test_generator_is_deterministic(self):
        self.assertEqual(list(t.gen_cases("array", 30)), list(t.gen_cases("array", 30)))

    def test_every_group_hits_a_panic_or_documents_none(self):
        for group in ("array", "key", "end", "close", "begin"):
            outcomes = {t.observe(group, self.img, self.tab, c)[0][0] for c in t.gen_cases(group, 400)}
            self.assertIn("panic", outcomes, group)
            self.assertIn("ret", outcomes, group)


class NegativeControls(Base):
    def panel(self, group, n=20):
        return list(t.gen_cases(group, n))

    def test_wrong_models_differ(self):
        for group, var in (("key", t.Variant(next=b"\n")), ("escape", t.Variant(skip_escape=True)),
                           ("array", t.Variant(pad=True)), ("close", t.Variant(brace=b"{")),
                           ("begin", t.Variant(colon=b":")), ("end", t.Variant(brace=b"]"))):
            hits = 0
            for case in t.gen_cases(group, 60):
                got, _ = t.observe(group, self.img, self.tab, case)
                hits += t.comparable(group, got) != t.comparable(group, t.expected(group, self.tab, case, var))
            self.assertGreater(hits, 0, group)

    def test_code_byte_patch_is_detected_and_restored(self):
        before = bytes(t.read_va(self.img, 0x26078e9, 8))
        self.assertTrue(t.patch_detect(self.img, self.tab, "key", 0x26078e9 + 3, 1, self.panel("key")))
        self.assertEqual(bytes(t.read_va(self.img, 0x26078e9, 8)), before)

    def test_patch_of_an_unrelated_byte_is_not_flagged(self):
        # the int3 padding after the key writer is never executed, so nothing may differ
        pad = self.img.fde_of(t.F_KEY)[1]
        self.assertFalse(t.patch_detect(self.img, self.tab, "key", pad, 1, self.panel("key")))

    def test_table_corruption_is_detected(self):
        slot = self.img.slots[t.SLOT_ESC]
        self.assertTrue(t.table_detect(self.img, self.tab, "escape", slot + 10, 0x6d,
                                       [(b"", b"\n", 8)]))

    def test_start_outside_code_is_rejected(self):
        with self.assertRaises(ToolError):
            self.img.fde_of(0x1000)

    def test_wrong_digest_is_rejected(self):
        old = t.DIGEST
        t.DIGEST = "0" * 64
        try:
            with self.assertRaises(ToolError):
                t.new_image()
        finally:
            t.DIGEST = old

    def test_all_declared_controls_are_unique_and_enough(self):
        names = [row[0] for row in t.make_controls()]
        self.assertEqual(len(names), len(set(names)))
        self.assertGreaterEqual(len(names), 30)

    def test_unmapped_source_bytes_fail_loudly(self):
        m = t.Emu(self.img, {})
        t.put_writer(m, b"", 8)
        with self.assertRaises(ToolError):
            t.execute(m, t.F_ESC, {t.core.RDI: t.WRITER, t.core.RSI: 0x7999_0000, t.core.RDX: 1})


class EvidenceRun(Base):
    def test_build_writes_consistent_measure_and_is_repeatable(self):
        with tempfile.TemporaryDirectory() as one:
            stats = t.build(one)
            measure = json.loads((pathlib.Path(one) / "measure.json").read_text())
            self.assertEqual(measure["cases"], sum(v[0] for v in stats.values()))
            self.assertEqual(measure["negative_controls"], measure["negative_detected"])
            self.assertGreaterEqual(measure["cases"], 10000)
            self.assertGreaterEqual(measure["negative_controls"], 30)
            names = sorted(p.name for p in pathlib.Path(one).iterdir())
            self.assertEqual(names, ["cases.tsv", "controls.tsv", "functions.tsv", "groups.tsv", "measure.json",
                                     "tables.tsv"])
            controls = (pathlib.Path(one) / "controls.tsv").read_text().splitlines()[1:]
            self.assertTrue(all(line.endswith("True") for line in controls))


if __name__ == "__main__":
    unittest.main()
