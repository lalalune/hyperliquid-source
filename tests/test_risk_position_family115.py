import itertools
import math
import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import risk_position_family115 as tool  # noqa: E402


class PositionFamilyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.sites = tool.Sites(cls.image)
        cls.world = tool.World(cls.image)

    def run_case(self, case, variant=frozenset()):
        before, got = tool.run_case(self.world, case)
        want = tool.SPECS[case.family](case, self.sites, variant)
        return got, want

    def named(self, family, name):
        return next(case for case in tool.NAMED[family]() if case.name == name)

    def test_digest_is_pinned(self):
        self.assertEqual(tool.SHA256, "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
        blob = bytearray(self.image.blob)
        blob[1000] ^= 1
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(self._write(bytes(blob)))

    def _write(self, data):
        import tempfile
        handle = tempfile.NamedTemporaryFile(delete=False)
        handle.write(data)
        handle.close()
        self.addCleanup(lambda: pathlib.Path(handle.name).unlink())
        return handle.name

    def test_functions_are_whole_fdes(self):
        for target in tool.TARGETS:
            start, end = self.image.exact_fde(target)
            self.assertEqual(start, target)
            self.assertGreater(end - start, 100)
        self.assertEqual(self.image.exact_fde(tool.TOTAL)[1] - tool.TOTAL, 898)
        self.assertEqual(self.image.exact_fde(tool.CHECK)[1] - tool.CHECK, 990)
        self.assertEqual(self.image.exact_fde(tool.OKAY)[1] - tool.OKAY, 783)

    def test_non_function_addresses_refused(self):
        for va in (tool.TOTAL + 1, tool.CHECK - 1, tool.OKAY + 8, tool.LOW, 0x7FFFFFFFFF):
            with self.assertRaises(tool.EvidenceError):
                self.image.exact_fde(va)

    def test_f64_constants_from_bytes(self):
        self.assertEqual(self.sites.consts, {"low": 0.5, "one": 1.0, "bound": 2.0 ** 63, "top": 2.0 ** 63 - 1024})

    def test_location_records(self):
        relative = self.image.relative()
        paths = {name: self.image.location(getattr(self.sites, name), relative) for name in ("fold_size", "check_size", "test_size", "fold_index", "check_index", "probe_index")}
        for path, line, column in paths.values():
            self.assertTrue(path.endswith(".rs"), path)
            self.assertGreater(line, 0)
        self.assertEqual(paths["fold_size"], paths["check_size"])
        self.assertEqual(paths["fold_size"], paths["test_size"])
        self.assertEqual(paths["fold_index"][0], paths["check_index"][0])

    def test_all_named_cases_agree(self):
        for family in tool.NAMED:
            for case in tool.NAMED[family]():
                got, want = self.run_case(case)
                self.assertEqual(got, want, (family, case.name))

    def test_siphash_is_one_three(self):
        # all-zero key and message: the value is fixed by the independent rule list and by the bytes
        self.assertEqual(tool.siphash13(0, 0, bytes(20)), self.run_hash(0, 0, bytes(20)))
        for k0, k1 in ((1, 2), (tool.TOP, 0), (0x0706050403020100, 0x0F0E0D0C0B0A0908)):
            for key in (bytes(range(20)), b"\xff" * 20, tool.key20(3)):
                self.assertEqual(tool.siphash13(k0, k1, key), self.run_hash(k0, k1, key))

    def run_hash(self, k0, k1, key):
        got, want = self.run_case(tool.HashCase("t", k0, k1, key))
        self.assertEqual(got, want)
        return got[1]

    def test_hash_depends_on_every_key_byte(self):
        base = self.run_hash(5, 6, bytes(20))
        seen = {base}
        for position in range(20):
            key = bytearray(20)
            key[position] = 1
            seen.add(self.run_hash(5, 6, bytes(key)))
        self.assertEqual(len(seen), 21)

    def test_fold_stored_balance_skips_or_applies(self):
        skip = self.run_case(self.named("fold", "tag one equal skips"))[0]
        apply_ = self.run_case(self.named("fold", "tag one one below applies"))[0]
        above = self.run_case(self.named("fold", "tag one one above skips"))[0]
        self.assertEqual(skip[0], "ret")
        self.assertEqual(skip[1], 0)
        self.assertEqual(above[1], 0)
        self.assertEqual(apply_[1], 1)

    def test_fold_empty_container_returns_the_negated_accumulator(self):
        self.assertEqual(self.run_case(self.named("fold", "empty positive accumulator"))[0][1], 0)
        self.assertEqual(self.run_case(self.named("fold", "empty negative accumulator"))[0][1], 77)
        self.assertEqual(self.run_case(self.named("fold", "empty min accumulator"))[0][1], tool.MAX64)

    def test_fold_divide_by_zero_is_a_fault(self):
        got, want = self.run_case(self.named("fold", "divide by zero"))
        self.assertEqual(got[:2], ("fault", "divide"))
        self.assertEqual(got, want)

    def test_fold_quotient_with_high_bit_is_the_formatted_panic(self):
        got, want = self.run_case(self.named("fold", "quotient too big"))
        self.assertEqual(got[0], "fmt")
        self.assertEqual(got[1][1], 0x2B)
        self.assertEqual(self.run_case(self.named("fold", "most negative product halved"))[0][0], "ret")

    def test_fold_key_is_taken_modulo_10000_including_multiples(self):
        for name in ("exact multiple of 10000", "second exact multiple", "largest exact multiple", "largest key"):
            got, want = self.run_case(self.named("fold", name))
            self.assertEqual(got, want, name)
        got = self.run_case(self.named("fold", "largest key"))[0]
        self.assertEqual(got[:3], ("index", tool.TOP % 10000, 1))

    def test_fold_walks_trees_of_three_heights(self):
        for name in ("tree two levels", "tree height two", "tree height two minimum", "tree 200 keys"):
            got, want = self.run_case(self.named("fold", name))
            self.assertEqual(got, want, name)

    def test_check_gate_codes(self):
        expected = {"below lower bound": 0x46, "above upper bound": 0x46, "infinity above": 0x46, "negative zero": 0x46, "asset beyond count": None, "mode zero": 0x14E,
                    "mode one": 0x14E, "mode three": 0x14E, "map empty uses default": 0x1A2, "key absent from account": 0x1A2, "tag low bit clear": 0x1A2,
                    "difference zero": 0x1A2, "difference negative": 0x1A2, "difference cannot overflow low": 0x1A2, "difference overflow high": 0xC4}
        for name, code in expected.items():
            got, want = self.run_case(self.named("check", name))
            self.assertEqual(got, want, name)
            if code is not None:
                self.assertEqual(int.from_bytes(got[1][:2], "little"), code, name)

    def test_check_nan_fraction_passes_the_range_gate(self):
        got, want = self.run_case(self.named("check", "nan passes the gate"))
        self.assertEqual(got, want)
        self.assertNotEqual(int.from_bytes(got[1][:2], "little"), 0x46)

    def test_check_emits_the_helper_result(self):
        got, want = self.run_case(self.named("check", "emitted request"))
        case = self.named("check", "emitted request")
        self.assertEqual(got[1], case.emit[:tool.OUT_SIZE])
        self.assertEqual([entry[0] for entry in got[2]], ["emit"])
        got = self.run_case(self.named("check", "emit reports no change"))[0]
        self.assertEqual(int.from_bytes(got[1][:2], "little"), 0x1A2)

    def test_check_scaled_value_edges(self):
        for name in ("scaled value above 2^63", "scaled value at 2^63", "scaled value between 2^62 and 2^63", "fraction rounding boundary"):
            got, want = self.run_case(self.named("check", name))
            self.assertEqual(got, want, name)
        self.assertEqual(int.from_bytes(self.run_case(self.named("check", "fraction rounding boundary"))[0][1][:2], "little"), 0x1A2)

    def test_check_once_word_is_forwarded(self):
        got = self.run_case(self.named("check", "once word set"))[0]
        self.assertEqual(got[2][0][:3], ("once", tool.ONCE, 1))
        self.assertEqual(got[2][0][-1], tool.DEFAULT)

    def test_margin_test_outcomes(self):
        two = self.run_case(self.named("test", "tag two returns two"))[0]
        self.assertEqual(two[1], 2)
        self.assertEqual(self.run_case(self.named("test", "negative figure"))[0][0], "fmt")
        floor = [self.run_case(self.named("test", name))[0][1] for name in ("remainder at floor", "remainder below floor", "other at floor", "other below floor")]
        self.assertEqual(floor, [1, 0, 1, 0])
        self.assertEqual(self.run_case(self.named("test", "tag one negative unit panics"))[0][0], "panic")

    def test_margin_test_side_word_selects_key_and_flip_separately(self):
        a = self.run_case(self.named("test", "side word 256 uses second key unflipped"))[0]
        b = self.run_case(self.named("test", "side one uses second key"))[0]
        self.assertEqual(a[2][0][:1], b[2][0][:1])

    def test_map_lookup_shapes(self):
        for case in tool.map_cases():
            got, want = self.run_case(case)
            self.assertEqual(got, want, case.name)
        corrupt = self.named("map", "bad2-1")
        got = self.run_case(corrupt)[0]
        self.assertEqual(got[:3], ("index", 2, 2))
        self.assertEqual(got[3], self.sites.probe_index)

    def test_vectors_agree_with_the_rule_list(self):
        for family in tool.VECTORS:
            count = 0
            for case in tool.vector_stream(family, 300):
                got, want = self.run_case(case)
                self.assertEqual(got, want, case.name)
                count += 1
            self.assertEqual(count, 300)

    def test_every_wrong_reading_is_refused(self):
        samples = {family: list(tool.NAMED[family]()) + list(tool.vector_stream(family, 160, seed=0x78)) for family in tool.VARIANTS}
        for family, names in tool.VARIANTS.items():
            for name in names:
                failure = tool.first_failure(self.world, samples[family], self.sites, frozenset((name,)))
                self.assertIsNotNone(failure, (family, name))

    def test_wrong_constants_and_sites_are_refused(self):
        check = list(tool.NAMED["check"]())
        wrong = tool.Sites(self.image)
        wrong.consts = dict(wrong.consts, low=0.25)
        self.assertIsNotNone(tool.first_failure(self.world, check, wrong))
        wrong = tool.Sites(self.image)
        wrong.check_size = wrong.check_key
        self.assertIsNotNone(tool.first_failure(self.world, check, wrong))
        fold = list(tool.NAMED["fold"]())
        wrong = tool.Sites(self.image)
        wrong.fold_sat_sum, wrong.fold_sat_sub = wrong.fold_sat_sub, wrong.fold_sat_sum
        self.assertIsNotNone(tool.first_failure(self.world, fold, wrong))

    def test_altered_case_is_not_matched(self):
        case = self.named("test", "tag one passes")
        got, want = self.run_case(case)
        case.route = (case.route[0] + 1, case.route[1])
        self.assertNotEqual(tool.spec_test(case, self.sites), got)
        case = self.named("map", "m2-a9") if any(c.name == "m2-a9" for c in tool.map_cases()) else tool.map_cases()[8]
        before, got = tool.run_case(self.world, case)
        case.qkey = bytes(20)
        self.assertNotEqual(tool.spec_map(case, self.sites), got)

    def test_byte_edits_are_killed(self):
        world = tool.World(self.image)
        for case in itertools.chain(tool.NAMED["fold"](), tool.NAMED["check"](), tool.NAMED["test"](), tool.NAMED["map"](), tool.NAMED["hash"]()):
            tool.run_case(world, case)
        seen = set(world.machine.seen)
        table = tool.decoded_table(self.image)
        samples = tool.mutation_samples()
        results = tool.run_mutants(self.image, table, seen, samples, self.sites)
        killed = [row for row in results if row[2] == "killed"]
        self.assertGreater(len(results), 380)
        self.assertGreater(len(killed), 360)
        for row in results:
            if row[2] == "survived":
                self.assertIn((row[0], row[1]), tool.EXPECTED_SURVIVORS)

    @classmethod
    def fingerprint(cls, value):
        if hasattr(value, "__dict__"):
            return sorted((key, cls.fingerprint(item)) for key, item in vars(value).items())
        if isinstance(value, dict):
            return sorted((key, cls.fingerprint(item)) for key, item in value.items())
        if isinstance(value, (list, tuple)):
            return [cls.fingerprint(item) for item in value]
        return repr(value)

    def test_generation_is_deterministic(self):
        for family in tool.VECTORS:
            first = [self.fingerprint(case) for case in tool.vector_stream(family, 40)]
            second = [self.fingerprint(case) for case in tool.vector_stream(family, 40)]
            self.assertEqual(first, second)
        files = tool.render(tool.analyse(self.image, mutate=False))
        self.assertEqual(sorted(files), sorted(tool.render(tool.analyse(self.image, mutate=False))))

    def test_measure_summary_counts(self):
        files = tool.render(tool.analyse(self.image, mutate=False))
        import json
        summary = json.loads(files["measure.json"])
        self.assertGreaterEqual(summary["cases"], 10000)
        self.assertEqual(summary["negative_controls"], summary["negative_detected"])


if __name__ == "__main__":
    unittest.main()
