"""Static split-plan fields and independent list-splice controls for node94."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-009-evm-full-leaf-split-plan-94"
SPEC = importlib.util.spec_from_file_location("leaf_split_plan94", PACKET / "verify.py")
v = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(v)


class FullLeafSplitPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = v.NODE.read_bytes()
        cls.secs = v.sections(cls.data)
        cls.fields = v.validate_fields(cls.data, cls.secs)
        cls.plan = json.loads((PACKET / "PLAN.json").read_text())

    def mutate(self, address, replacement):
        sec = next(s for s in self.secs if s["type"] != 8 and
                   s["address"] <= address < s["address"] + s["size"])
        at = sec["offset"] + address - sec["address"]
        changed = bytearray(self.data)
        self.assertNotEqual(changed[at], replacement)
        changed[at] = replacement
        return changed

    def test_complete_target_record_and_call_edge(self):
        record = v.analyze(self.data)
        self.assertEqual(record, json.loads((PACKET / "evidence.json").read_text()))
        self.assertEqual(record["primary"]["lsda"], "0x967024")
        self.assertEqual(len(bytes.fromhex(record["primary"]["body_hex"])), 3363)
        self.assertEqual(record["counts"], {"primary_FDEs": 1,
            "retained_primary_bytes": 3363, "selected_primary_windows": 3,
            "selected_primary_bytes": 452, "credited_context_bytes": 134,
            "valid_model_positions": 12})
        self.assertEqual(record["caller_edge"]["target"], "0x1ab3d20")

    def test_all_twelve_frozen_native_cases(self):
        self.assertTrue(self.plan["frozen_before_model"])
        self.assertEqual([r[0] for r in self.plan["frozen_cases"]], list(range(12)))
        actual = [v.split_plan(i, self.fields) for i in range(12)]
        self.assertEqual(actual, self.plan["frozen_cases"])
        self.assertEqual(actual[5], [5, 5, "left", 5, 6, 5])
        self.assertEqual(actual[6], [6, 5, "right", 0, 5, 6])

    def test_plan_reassembles_independent_list_insertion(self):
        # This checks plan geometry. It does not execute target byte movers.
        old = [(f"key{i}", f"value{i}") for i in range(11)]
        new = ("new-key", "new-value")
        for i in range(12):
            _, pivot, side, local, left_count, right_count = v.split_plan(i, self.fields)
            left, promoted, right = old[:pivot], old[pivot], old[pivot+1:]
            (left if side == "left" else right).insert(local, new)
            oracle = old[:i] + [new] + old[i:]
            with self.subTest(index=i):
                self.assertEqual(left + [promoted] + right, oracle)
                self.assertEqual((len(left), len(right)), (left_count, right_count))
                self.assertEqual(sorted((left_count, right_count)), [5, 6])
                self.assertNotIn(promoted, left + right)

    def test_all_predeclared_native_field_mutations(self):
        self.assertEqual(len(self.plan["predeclared_mutations"]), 9)
        for mutation in self.plan["predeclared_mutations"]:
            changed = self.mutate(int(mutation["va"], 16), int(mutation["byte"], 16))
            with self.subTest(field=mutation["field"]):
                self.assertNotEqual(v.decode_fields(changed, self.secs), self.fields)
                with self.assertRaisesRegex(ValueError, "planning fields changed"):
                    v.validate_fields(changed, self.secs)

    def test_wrong_cut_and_side_have_frozen_case_counterexamples(self):
        cases = ((0x1AB3D7E, 4, 5), (0x1AB3E89, 0xFA, 7),
                 (0x1AB3FC5, 0x45, 5))
        for address, replacement, index in cases:
            altered = v.decode_fields(self.mutate(address, replacement), self.secs)
            with self.subTest(address=hex(address), index=index):
                self.assertNotEqual(v.split_plan(index, altered), self.plan["frozen_cases"][index])

    def test_cmp_flag_corridor_width_and_branch_mutations(self):
        # Replacing a MOV by ADD would invalidate the preserved CMP flags.
        for address, replacement in ((0x1AB3D80, 0x01),
                                     (0x1AB3D92, 0x82),
                                     (0x1AB3EF2, 0x11)):
            with self.subTest(address=hex(address)):
                with self.assertRaisesRegex(ValueError, "instruction form"):
                    v.decode_fields(self.mutate(address, replacement), self.secs)
        changed = self.mutate(0x1AB3D44, 0x2E)
        self.assertNotEqual(v.decode_fields(changed, self.secs)["targets"], self.fields["targets"])
        with self.assertRaisesRegex(ValueError, "planning fields changed"):
            v.validate_fields(changed, self.secs)

    def test_identity_admission_is_separate_from_field_checks(self):
        changed = self.mutate(0x1AB3D7E, 4)
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            v.analyze(changed)
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            v.analyze(self.data[:-1])

    def test_model_restricts_its_domain_without_target_rejection_claim(self):
        for index in (-1, 12, True, 5.0, "5"):
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, "model domain"):
                v.split_plan(index, self.fields)

    def test_selected_listing_completeness_and_corruption(self):
        listing = (PACKET / "selected.asm").read_text()
        v.check_listing(listing, self.data, self.secs)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            v.check_listing("", self.data, self.secs)
        with self.assertRaisesRegex(ValueError, "differ"):
            v.check_listing(listing.replace("\t49 89 cd", "\t49 89 ce", 1), self.data, self.secs)

    def test_invalid_virtual_ranges_and_transfer_opcode(self):
        for address,size in ((-1,1), (v.START,0), (True,1), (2**64,1)):
            with self.subTest(address=address), self.assertRaises(ValueError):
                v.read_va(self.data, self.secs, address, size)
        sec = next(s for s in self.secs if s["address"] <= v.START < s["address"] + s["size"])
        for mapping in ([sec,sec], [{**sec,"type":8}]):
            with self.assertRaisesRegex(ValueError, "uniquely file backed"):
                v.read_va(self.data, mapping, v.START, 1)
        with self.assertRaisesRegex(ValueError, "exceeds input"):
            v.read_va(self.data[:10], [sec], v.START, 1)
        with self.assertRaisesRegex(ValueError, "unexpected native control"):
            v.control(self.mutate(0x2854859, 0x90), self.secs, 0x2854859)


if __name__ == "__main__":
    unittest.main()
