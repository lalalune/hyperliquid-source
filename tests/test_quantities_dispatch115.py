import json
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import quantities_dispatch115 as Q  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-004-quantity-name-dispatch-115"
FIXTURE = json.loads((FOLDER / "code-bytes.json").read_text())
SENT = Q.SENT
M64 = Q.M64


def image():
    return Q.FixtureImage(FIXTURE)


def fresh_harness(patches=None):
    img = image()
    targets = Q.table_targets(img)
    return Q.Harness(img, patches, targets), targets


def wrong_asset_id(bound, offset, ceiling=0x270F):
    def fn(value):
        if value <= ceiling:
            return value
        if value <= bound:
            return (value + offset) & 0xFFFFFFFF
        return 0xFFFFFFFF
    return fn


ID_TABLE = [(0, 0), (1, 1), (9999, 9999), (10000, 110000), (10001, 110001), (0x5F45A5E, 0x5F45A5E + 100000), (0x5F45A5F, 0x5F45A5F + 100000),
            (0x5F45A60, 0xFFFFFFFF), (1 << 32, 0xFFFFFFFF), (M64, 0xFFFFFFFF)]


class Fixture(unittest.TestCase):
    def test_fixture_is_the_dispatcher(self):
        self.assertEqual(FIXTURE["root"]["va"], Q.FN)
        self.assertEqual(FIXTURE["root"]["size"], Q.FN_END - Q.FN)
        self.assertEqual(FIXTURE["range"]["size"], Q.RANGE_END - Q.RANGE_FN)
        img = image()
        self.assertEqual(img.blob[Q.FN:Q.FN + 1], b"\x55")
        self.assertEqual(img.blob[Q.FN_END - 5:Q.FN_END - 4], b"\xe8")

    def test_jump_table(self):
        targets = Q.table_targets(image())
        self.assertEqual(targets[:7], [0x291379C, 0x29139A9, 0x29138E9, 0x2913979, 0x291388C, 0x29139EE, 0x2913A49])
        self.assertTrue(all(Q.FN <= t < Q.FN_END for t in targets[:7]))
        self.assertFalse(any(Q.FN <= t < Q.FN_END for t in targets[7:]))
        self.assertEqual(len(targets), 14)


class PureHelpers(unittest.TestCase):
    def test_asset_id_table(self):
        for value, expected in ID_TABLE:
            self.assertEqual(Q.asset_id(value), expected, hex(value))

    def test_wrong_asset_ids_are_caught(self):
        wrong = [wrong_asset_id(0x5F45A5E, 100000), wrong_asset_id(0x5F45A60, 100000), wrong_asset_id(0x5F45A5F, 100001),
                 wrong_asset_id(0x5F45A5F, 100000, 0x2710), wrong_asset_id(0x5F45A5F, 100000, 0x270E), wrong_asset_id(0x5F45A5F, 10000)]
        for fn in wrong:
            self.assertTrue(any(fn(v) != e for v, e in ID_TABLE))

    def test_arm_index(self):
        self.assertEqual(Q.arm_index(SENT + 13), 0)
        self.assertEqual(Q.arm_index(SENT + 19), 6)
        for tag in (0, 1, SENT - 1, SENT, SENT + 12):
            self.assertEqual(Q.arm_index(tag), 5)
        self.assertNotEqual(Q.arm_index(SENT + 14), Q.arm_index(SENT + 13))

    def test_oracle_tags(self):
        for n in range(300):
            key = n.to_bytes(4, "little")
            ok = Q.oracle("A", key, True, {8: n})
            bad = Q.oracle("A", key, False, {8: n})
            self.assertEqual(int.from_bytes(ok[:2], "little"), 0x1A2)
            self.assertEqual(int.from_bytes(ok[8:16], "little"), n)
            self.assertNotEqual(int.from_bytes(bad[:2], "little"), 0x1A2)
            self.assertEqual(len(ok), 0x70)
        self.assertNotEqual(Q.oracle("A", b"k", True, {}), Q.oracle("B", b"k", True, {}))

    def test_expand_is_deterministic_and_sized(self):
        self.assertEqual(Q.expand(b"s", 100), Q.expand(b"s", 100))
        self.assertEqual(len(Q.expand(b"s", 33)), 33)
        self.assertNotEqual(Q.expand(b"s", 8), Q.expand(b"t", 8))

    def test_range_model(self):
        log = []
        case = {"r_end": 3, "r_scale": 7, "alloc_fail": False}
        self.assertEqual(Q.model_range(case, log), ([70000, 70001, 70002], None))
        self.assertEqual(log, [("ALLOC", 24)])
        self.assertEqual(Q.model_range(dict(case, r_scale=Q.MAXOK + 1), [])[1], "mul")
        self.assertEqual(Q.model_range(dict(case, r_end=0), [])[0], [])
        self.assertEqual(Q.model_range(dict(case, r_end=1 << 60), [])[1], "alloc-error")
        self.assertEqual(Q.model_range(dict(case, r_end=2000, r_scale=Q.MAXOK), [])[1], "add")
        self.assertEqual(Q.model_range(dict(case, r_end=1616, r_scale=Q.MAXOK), [])[1], None)

    def test_direct_range_model(self):
        base = {"range_a": 5, "r_end": 8, "r_scale": 2, "alloc_fail": False}
        self.assertEqual(Q.model_direct(base)[0:3], ("ret", [("ALLOC", 24)], 3))
        self.assertEqual(Q.model_direct(base)[4], [20005, 20006, 20007])
        self.assertEqual(Q.model_direct(dict(base, range_a=8))[2:4], (0, 8))
        self.assertEqual(Q.model_direct(dict(base, range_a=9))[2:4], (0, 8))
        wrap = dict(base, range_a=M64 - 2, r_end=M64, r_scale=1)
        self.assertEqual(Q.model_direct(wrap)[0], "panic:add")
        self.assertEqual(Q.model_direct(dict(wrap, r_scale=0))[4], [M64 - 2, M64 - 1])
        self.assertEqual(Q.model_direct(dict(base, r_scale=SENT))[0], "panic:mul")

    def test_generation_is_deterministic(self):
        targets = list(range(100, 114))
        first, _ = Q.generate(targets)
        second, _ = Q.generate(targets)
        self.assertEqual([c["index"] for c in first], [c["index"] for c in second])
        self.assertEqual([c["inp"] for c in first if "inp" in c][:50], [c["inp"] for c in second if "inp" in c][:50])
        self.assertGreaterEqual(len(first), 10000)

    def test_model_hand_cases(self):
        targets = list(range(14))
        case = Q.build(0, 0, SENT + 13, 5, {"inp": {8: 9, 0x18: 101}})
        kind, exp, log, r468 = Q.model(case, targets)
        self.assertEqual((kind, log, r468), ("ret", [("FREE", Q.u64(case["inp"], 0x10), 9, 0)], None))
        self.assertEqual(exp[0], (0, 2, b"\x58\x01"))
        self.assertEqual(exp[1], (0x18, 8, (101).to_bytes(8, "little")))
        case = Q.build(1, 6, SENT + 19, 6, {"inp": {8: 4}, "limit": 4})
        kind, exp, log, r468 = Q.model(case, targets)
        self.assertEqual((kind, log, exp[0][2]), ("ret", [], b"\xfa\x00"))
        case = Q.build(2, 6, SENT + 19, 6, {"inp": {8: 3}, "limit": 4})
        self.assertEqual(Q.model(case, targets)[2][0][0], "Y")
        case = Q.build(3, 9, SENT + 22, 6)
        self.assertEqual(Q.model(case, list(range(100, 114)))[0], "trap:0x6d")

    def test_mutant_table_is_well_formed(self):
        labels = [m[3] for m in Q.MUTANTS]
        self.assertEqual(len(set(labels)), len(labels))
        for va, old, new, label in Q.MUTANTS:
            self.assertEqual(len(old), len(new))
            self.assertNotEqual(old, new)
            self.assertTrue(Q.FN <= va < Q.FN_END or Q.RANGE_FN <= va < Q.RANGE_END, label)
        self.assertEqual(Q.patch_map((0x10, "aabb", "aacc")), {0x11: 0xCC})

    def test_mutant_originals_match_fixture_and_corruption_is_refused(self):
        img = image()
        Q.verify_mutants(img)
        broken = Q.FixtureImage(FIXTURE)
        segments = [(s, bytearray(d)) for s, d in broken.blob.segments]
        for s, d in segments:
            if s == Q.FN:
                d[0x29137A8 - Q.FN + 3] ^= 0x01
        broken.blob = Q.SparseBlob([(s, bytes(d)) for s, d in segments])
        with self.assertRaises(Q.EvidenceError):
            Q.verify_mutants(broken)

    def test_binary_digest_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "node"
            path.write_bytes(b"not the node")
            with self.assertRaises(Q.EvidenceError):
                Q.load_image(path)
            with self.assertRaises(Q.EvidenceError):
                Q.load_image(path, "0" * 64)

    def test_no_forbidden_path_text(self):
        banned = ["/" + word + "/" for word in ("home", "mnt", "srv", "root", "tmp", "opt", "var", "etc")]
        for path in (ROOT / "tools" / "quantities_dispatch115.py", pathlib.Path(__file__)):
            text = path.read_text()
            for item in banned:
                self.assertNotIn(item, text, path.name)


class EmulatorOnFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness, cls.targets = fresh_harness()
        cls.ordered, cls.natural = Q.generate(cls.targets)

    def test_every_fifth_case_matches_model(self):
        bad = []
        for case in self.natural[::5]:
            reason = Q.check(case, self.harness, self.targets)
            if reason:
                bad.append((case["index"], reason))
        self.assertEqual(bad, [])

    def test_all_outcome_kinds_occur(self):
        kinds = set()
        for case in self.natural:
            if case["arm"] == 3 and case["r_end"] in (1 << 60, 1700, 60) or case["arm"] in (6, 7):
                kinds.add(self.harness.run(case)[0])
        self.assertTrue({"ret", "panic:alloc-error", "panic:add", "panic:mul"} <= kinds)
        self.assertTrue(any(k.startswith("trap:") for k in kinds))

    def test_arm_zero_ids_reach_the_encoder_unchanged(self):
        for value, expected in ID_TABLE:
            case = Q.build(0, 0, SENT + 13, 77, {"b_value": value, "s_flag": 0, "inp": {8: 0, 0x18: 3}})
            run = self.harness.run(case)
            key = [entry for entry in run[2] if entry[0] == "W"][0][1]
            self.assertEqual(int.from_bytes(key[8:12], "little"), expected, hex(value))

    def test_model_variants_are_rejected(self):
        original = Q.asset_id
        try:
            Q.asset_id = wrong_asset_id(0x5F45A5F, 100000, 0x2710)
            bad = [c for c in self.natural if c["arm"] == 0 and Q.check(c, self.harness, self.targets)]
            self.assertTrue(bad)
        finally:
            Q.asset_id = original

    def test_model_length_gate_variant_rejected(self):
        original = Q.model
        probe = Q.build(0, 0, SENT + 13, 3, {"inp": {8: 1, 0x18: 100}})
        self.assertIsNone(Q.check(probe, self.harness, self.targets))

        def shifted(case, targets):
            patched = dict(case, inp=bytes(case["inp"][:0x18]) + (case["inp"][0x18] + 1).to_bytes(1, "little") + case["inp"][0x19:])
            return original(patched, targets)
        try:
            Q.model = shifted
            self.assertIsNotNone(Q.check(probe, self.harness, self.targets))
        finally:
            Q.model = original

    def test_mutants_are_detected_on_fixture(self):
        missed = []
        for row in Q.MUTANTS:
            mutant, targets = fresh_harness(Q.patch_map(row))
            hit = False
            for case in self.ordered:
                try:
                    if Q.check(case, mutant, targets):
                        hit = True
                        break
                except (Q.Halt, Q.EvidenceError):
                    hit = True
                    break
            if not hit:
                missed.append(row[3])
        self.assertEqual(missed, [])

    def test_unpatched_control_is_clean(self):
        for case in self.ordered[:200]:
            self.assertIsNone(Q.check(case, self.harness, self.targets))

    def test_stack_and_registers_are_preserved(self):
        run = self.harness.run(self.natural[0])
        self.assertEqual(run[0], "ret")
        self.assertEqual(self.harness.machine.regs[Q.RSP], Q.STACK_TOP - 0x100)


class ModelConstantVariants(unittest.TestCase):
    """A model whose single constant is wrong must disagree with the emulated bytes on some generated case."""

    VARIANTS = [("LEN_GATE", 0x66), ("LEN_GATE", 0x64), ("STRIDE", 10001), ("STRIDE", 9999), ("ID_OFFSET", 100001), ("ID_OFFSET", 99999),
                ("SMALL_MAX", 0x2710), ("SMALL_MAX", 0x270E), ("LIMIT_MASK_ROW", 0x5F45A5E), ("LIMIT_MASK_ROW", 0x5F45A60),
                ("TAG_LONG", 0x159), ("TAG_SENTINEL", 0x157), ("TAG_NEXT", 0x1A2), ("TAG_RANGE", 0xFB)]

    @classmethod
    def setUpClass(cls):
        cls.harness, cls.targets = fresh_harness()
        cls.ordered, _ = Q.generate(cls.targets)

    def test_each_variant_is_rejected(self):
        for name, value in self.VARIANTS:
            original = getattr(Q, name)
            setattr(Q, name, value)
            try:
                found = any(Q.check(case, self.harness, self.targets) for case in self.ordered[:3000])
            finally:
                setattr(Q, name, original)
            self.assertTrue(found, "%s=%#x was not rejected" % (name, value))
        self.assertIsNone(Q.check(self.ordered[0], self.harness, self.targets))

    def test_canonical_traces_replay(self):
        text = Q.flow_report(self.harness, self.targets)
        for title, arm, tag, fields in Q.CANONICAL:
            self.assertIn("## " + title, text)
        self.assertIn("call ALLOC(0x18)", text)
        self.assertEqual(text + "\n", (FOLDER / "canonical-traces.md").read_text())

    def test_canonical_trace_with_broken_constant_fails(self):
        original = Q.TAG_LONG
        Q.TAG_LONG = 0x159
        try:
            with self.assertRaises(Q.EvidenceError):
                Q.flow_report(self.harness, self.targets)
        finally:
            Q.TAG_LONG = original


class EvidenceFiles(unittest.TestCase):
    def test_measure_is_consistent(self):
        measure = json.loads((FOLDER / "measure.json").read_text())
        self.assertEqual(measure["negative_detected"] + measure["equivalent"], measure["negative_controls"])
        self.assertEqual(measure["negative_controls"], len(Q.MUTANTS))
        self.assertGreaterEqual(measure["cases"], 10000)
        controls = (FOLDER / "controls.tsv").read_text().splitlines()
        self.assertEqual(len(controls) - 1, measure["negative_controls"])
        self.assertEqual(sum(1 for line in controls[1:] if line.split("\t")[5] == "1"), measure["negative_detected"])
        equivalent = (FOLDER / "equivalent-mutants.tsv").read_text().splitlines()
        self.assertEqual(len(equivalent) - 1, measure["equivalent"])

    def test_instruction_listing_covers_both_extents(self):
        rows = [line.split("\t") for line in (FOLDER / "instructions.tsv").read_text().splitlines()[1:]]
        self.assertEqual(int(rows[0][0], 16), Q.RANGE_FN)
        self.assertEqual(sum(int(r[1]) for r in rows), (Q.RANGE_END - Q.RANGE_FN) + (Q.FN_END - Q.FN))
        executed = sum(int(r[6]) for r in rows)
        self.assertEqual(executed, json.loads((FOLDER / "measure.json").read_text())["instructions_executed"])


if __name__ == "__main__":
    unittest.main()
