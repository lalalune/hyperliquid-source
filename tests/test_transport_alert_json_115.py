import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import transport_alert_json_115 as tool  # noqa: E402


class AlertJsonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.cases = list(tool.all_cases(1500))

    def harness(self, patches=None):
        return tool.Harness(self.image, patches)

    def test_real_bytes_match_rules_on_every_kind(self):
        stats, _ = tool.check_stream(self.harness(), self.cases)
        self.assertEqual(stats["mismatches"], 0)
        self.assertGreaterEqual(stats["cases"], 1500)
        kinds = {kind for kind, _ in stats["kinds"]}
        self.assertEqual(kinds, {"alert", "entry", "itoa", "grow", "finish"})
        outcomes = {outcome for _, outcome in stats["kinds"]}
        self.assertEqual(outcomes, {"ok", "panic"})

    def test_pretty_object_text(self):
        case = tool.Case("alert", cap=0, data=b"", indent=b"  ", depth=0, value=7, has_value=0)
        got = self.harness().run_case(case)
        self.assertEqual(got[2], b'{\n  "bucket_limit_mult_threshold": 7\n}')
        self.assertEqual(got[3], 64)

    def test_nested_object_indents_by_depth(self):
        case = tool.Case("alert", cap=512, data=b"", indent=b"\t", depth=2, value=tool.U64, has_value=1)
        got = self.harness().run_case(case)
        self.assertEqual(got[2], b'{\n\t\t\t"bucket_limit_mult_threshold": 18446744073709551615\n\t\t}')
        self.assertEqual(got[5], 2)

    def test_depth_overflow_panics_before_writing(self):
        case = tool.Case("alert", cap=64, data=b"ab", indent=b" ", depth=tool.U64, value=1, has_value=0)
        self.assertEqual(self.harness().run_case(case), ("panic", "overflow", ()))

    def test_escape_classes(self):
        case = tool.Case("entry", cap=64, data=b"", indent=b"", depth=0, value=0, key=b'a"\\\n\x01\x7f\xff', state=0, first=1)
        got = self.harness().run_case(case)
        self.assertEqual(got[2], b'\n"a\\"\\\\\\n\\u0001\x7f\xff": 0')

    def test_member_state_one_panics(self):
        case = tool.Case("entry", cap=64, data=b"", indent=b"", depth=0, value=0, key=b"k", state=1, first=1)
        self.assertEqual(self.harness().run_case(case), ("panic", "expect:40", ()))

    def test_decimal_boundaries(self):
        for value in (0, 9, 10, 99, 100, 9999, 10000, 10 ** 19, tool.U64):
            got = self.harness().run_case(tool.Case("itoa", value=value))
            self.assertEqual(got[3], str(value).encode())
            self.assertEqual(got[1], 20 - len(str(value)))

    def test_growth_rule(self):
        got = self.harness().run_case(tool.Case("grow", cap=0, length=0, add=1, align=1, esize=1))
        self.assertEqual(got[1], 8)
        got = self.harness().run_case(tool.Case("grow", cap=100, length=100, add=1, align=1, esize=1))
        self.assertEqual(got[1], 200)
        got = self.harness().run_case(tool.Case("grow", cap=0, length=0, add=1, align=1, esize=2000))
        self.assertEqual(got[1], 1)
        got = self.harness().run_case(tool.Case("grow", cap=0, length=0, add=0, align=1, esize=0))
        self.assertEqual(got[0], "panic")

    def test_allocation_limit(self):
        over = self.harness().run_case(tool.Case("finish", oldcap=0, newcap=1 << 63, align=1, esize=1))
        self.assertEqual(over[1:3], (1, 0))
        edge = self.harness().run_case(tool.Case("finish", oldcap=0, newcap=(1 << 63) - 1, align=1, esize=1))
        self.assertEqual(edge[1], 0)

    def test_wrong_readings_are_refused(self):
        subset = self.cases[:60] + self.cases[::11]
        for name, flags in tool.VARIANTS:
            stats, _ = tool.check_stream(self.harness(), subset, frozenset(flags), first_only=True)
            self.assertGreater(stats["mismatches"], 0, name)

    def test_image_table_equals_rule_list(self):
        self.assertEqual(tool.image_table(self.image), tool.spec_escape_table())
        self.assertNotEqual(tool.image_table(self.image), tool.spec_escape_table_tampered())

    def test_byte_edits_are_caught(self):
        picked = self.cases[::40]
        for patch_at, byte in ((tool.ITOA + 4, 0xFF), (tool.ALERT, 0xCC), (tool.GROW + 2, 0x90)):
            harness = self.harness({patch_at: byte})
            harness.machine.step_limit = 20000
            caught = False
            for case in picked:
                try:
                    got = harness.run_case(case)
                except (tool.Halt, tool.Panicked, tool.EvidenceError, ValueError):
                    got = ("error",)
                if got != tool.spec_case(case):
                    caught = True
                    break
            self.assertTrue(caught, hex(patch_at))

    def test_container_checks(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(tool.core.BINARY, "0" * 64)
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.ALERT + 1)
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(self.image.named[".bss"]["address"] + 8)
        with self.assertRaises(tool.EvidenceError):
            tool.decode_range(self.image, tool.ALERT, self.image.exact_fde(tool.ALERT)[1] - 1)

    def test_controls_all_detected(self):
        controls = tool.structural_controls(self.image, self.harness(), self.cases)
        self.assertTrue(all(detected for _, detected, _ in controls), [c for c in controls if not c[1]])
        self.assertGreaterEqual(len(controls), 16)

    def test_slot_relocations_are_listed(self):
        rows = tool.slot_rows(self.image)
        self.assertEqual(len(rows), len(tool.CALL_SLOTS) + len(tool.DATA_SLOTS))


if __name__ == "__main__":
    unittest.main()
