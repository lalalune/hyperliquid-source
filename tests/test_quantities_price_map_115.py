import copy
import hashlib
import json
import math
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import quantities_price_map_115 as tool  # noqa: E402


class SpecTests(unittest.TestCase):
    """Properties of the independent specification; no binary needed."""

    def test_round_reference(self):
        self.assertEqual(tool.round_ref(0.5), 1.0)
        self.assertEqual(tool.round_ref(2.5), 3.0)
        self.assertEqual(tool.round_ref(0.49999999999999994), 0.0)
        self.assertEqual(tool.round_ref(-1.5), -2.0)
        self.assertTrue(math.isinf(tool.round_ref(float("inf"))))
        self.assertTrue(math.isnan(tool.round_ref(float("nan"))))

    def test_saturating_cast(self):
        self.assertEqual(tool.saturate_u64(-3.0), 0)
        self.assertEqual(tool.saturate_u64(1.8446744073709552e19), tool.U64)
        self.assertEqual(tool.saturate_u64(1.844674407370955e19), 18446744073709549568)
        self.assertEqual(tool.saturate_u64(7.0), 7)

    def test_early_outs(self):
        case = tool.simple_case(5, 1.0, flag=1)
        self.assertEqual(tool.spec(case)[0], ("ret", 0x101))
        case = tool.simple_case(5, 1.0, o378=tool.NICHE)
        self.assertEqual(tool.spec(case)[0], ("ret", 0x19E))
        case = tool.simple_case(5, 1.0, o408=tool.NICHE + 1, flag=1)
        self.assertEqual(tool.spec(case)[0], ("ret", 0x19E), "the option words are tested before the flag")

    def test_index_past_count_is_unwrap_panic(self):
        self.assertEqual(tool.spec(tool.simple_case(5, 1.0, index=1))[0], ("panic", "unwrap"))

    def test_scale_factor_names(self):
        base = tool.simple_case(5, 7.0, 3, name=b"HYPE", rows=2, asset=1)
        first = base["markets"][0]
        self.assertEqual(tool.scale_factor(base, 1, first), 1.0)
        base["rows"][1] = (b"HYPD", 3)
        self.assertEqual(tool.scale_factor(base, 1, first), 7.0)
        other = tool.simple_case(5, 7.0, 3, name=b"PURR", rows=2, asset=1, dex=1)
        self.assertEqual(tool.scale_factor(other, 1, other["markets"][0]), 7.0, "the names matter only for dex 0")

    def test_factor_is_rebuilt_with_two_adds(self):
        case = tool.simple_case(5, 1e-12)
        self.assertEqual(tool.scale_factor(case, 0, case["markets"][0]), (1e-12 - 1.0) + 1.0)
        self.assertNotEqual(tool.scale_factor(case, 0, case["markets"][0]), 1e-12, "the two adds lose low bits of the factor")

    def test_inf_product_clamps_to_zero_then_one(self):
        events = tool.spec(tool.simple_case(1, float("inf"), 6))[1]
        insert = [event for event in events if event[0] == "insert"][0]
        self.assertEqual(insert[2], tool.pack_decimal(*tool.decimal_of(1.0)))

    def test_generator_is_deterministic(self):
        self.assertEqual(repr(tool.make_case(2, 17)), repr(tool.make_case(2, 17)))
        self.assertNotEqual(repr(tool.make_case(2, 17)), repr(tool.make_case(2, 18)))

    def test_tree_shapes(self):
        self.assertTrue(tool.tree_fits(11, 0))
        self.assertFalse(tool.tree_fits(12, 0))
        self.assertTrue(tool.tree_fits(40, 1))


class ByteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.Harness(cls.image)
        cls.directed = tool.directed()

    def test_directed_cases_agree(self):
        for number, case in enumerate(self.directed):
            self.assertIsNone(tool.judge(self.harness, case), "directed %d" % number)

    def test_generated_cases_agree(self):
        for variant in (1, 2, 3, 4):
            for number in range(150):
                self.assertIsNone(tool.judge(self.harness, tool.make_case(variant, number)), "%d.%d" % (variant, number))

    def test_wrong_specification_is_caught(self):
        case = tool.simple_case(12345, 7.0, 3, name=b"HYPE", rows=2, asset=1)
        original = tool.scale_factor
        try:
            tool.scale_factor = lambda c, a, f: (c["factor"] - 1.0) + 1.0
            self.assertIsNotNone(tool.judge(self.harness, case), "ignoring the HYPE special case must differ")
        finally:
            tool.scale_factor = original
        self.assertIsNone(tool.judge(self.harness, case))

    def test_wrong_rounding_is_caught(self):
        case = tool.simple_case(5, 0.5, 0)
        original = tool.round_ref
        try:
            tool.round_ref = lambda x: math.floor(x)
            self.assertIsNotNone(tool.judge(self.harness, case))
        finally:
            tool.round_ref = original

    def test_mutated_bytes_are_caught(self):
        pool = tool.directed()
        start, _ = tool.root_extent(self.image)
        found = {(address, kind): patch for address, kind, patch in tool.mutants(self.image)}
        for key in ((0x55BE0EB, "jcc"), (0x55BE176, "imm")):
            if key in found:
                self.assertIsNotNone(tool.kill_mutant(self.image, found[key], pool), key)
        some = [item for item in tool.mutants(self.image) if item[1] == "jcc"][:12]
        self.assertTrue(some)
        for address, kind, patch in some:
            with self.subTest(address=hex(address)):
                self.assertIsNotNone(tool.kill_mutant(self.image, patch, pool + [tool.make_case(1, n) for n in range(40)]))

    def test_unpatched_root_survives_the_pool(self):
        self.assertIsNone(tool.kill_mutant(self.image, {}, tool.directed()))

    def test_machine_events_for_a_known_case(self):
        case = tool.simple_case(12345, 1.0, 3)
        outcome, events = self.harness.run(case)
        self.assertEqual(outcome, ("ret", None))
        names = [event[0] for event in events]
        self.assertEqual(names, ["drop", "drop", "price", "drop", "insert", "final"])
        self.assertEqual(events[4][1], 0)
        self.assertEqual(events[4][2], tool.pack_decimal(*tool.decimal_of(12.345)))

    def test_digest_mismatch_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            damaged = pathlib.Path(folder) / "node"
            data = bytearray(tool.BINARY.read_bytes())
            data[0x1000] ^= 1
            damaged.write_bytes(bytes(data))
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(damaged)

    def test_out_of_range_address_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(0x10)
        with self.assertRaises(tool.EvidenceError):
            self.image.exact_fde(tool.ROOT_FN + 1)

    def test_root_extent_is_the_fde(self):
        self.assertEqual(tool.root_extent(self.image), (0x55BE0D0, 0x55BE981))


class RegenerationTests(unittest.TestCase):
    def test_small_build_is_deterministic_and_counts_every_mutant(self):
        with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
            first = tool.build(pathlib.Path(one), (60, 30, 30, 30), 3)
            second = tool.build(pathlib.Path(two), (60, 30, 30, 30), 3)
            self.assertEqual(first, second)
            for name in ("cases.tsv", "controls.tsv", "equivalent-mutants.tsv", "outcomes.tsv", "measure.json"):
                self.assertEqual((pathlib.Path(one) / name).read_bytes(), (pathlib.Path(two) / name).read_bytes(), name)
            measure = json.loads((pathlib.Path(one) / "measure.json").read_text())
            self.assertEqual(measure["negative_detected"] + measure["equivalent"] + measure["unexplained"], measure["negative_controls"])
            self.assertEqual(measure["unexplained"], 0)
            rows = (pathlib.Path(one) / "controls.tsv").read_text().splitlines()
            self.assertEqual(len(rows) - 1, measure["negative_controls"])
            self.assertNotIn("SURVIVED", "\n".join(rows))

    def test_no_server_paths_in_the_tool(self):
        text = pathlib.Path(tool.__file__).read_text()
        for prefix in ("/" + name + "/" for name in ("home", "mnt", "srv", "root", "tmp", "opt", "var", "etc")):
            self.assertNotIn(prefix, text)
        self.assertEqual(hashlib.sha256(tool.BINARY.read_bytes()).hexdigest(), tool.SHA256)


if __name__ == "__main__":
    unittest.main()
