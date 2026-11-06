import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import mid_market_order_builder_115 as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-014-mid-market-order-builder-115"


def load(cls):
    cls.image = tool.load_image()
    cls.harness = tool.Harness(cls.image)


class MidMarketOrderBuilderTest(unittest.TestCase):
    setUpClass = classmethod(load)

    def limit_of(self, result):
        self.assertIn("insert", result)
        return struct.unpack_from("<Q", result["insert"][2], 0x90)[0]

    def test_digest_mismatch_is_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256 mismatch"):
            tool.load_image(expected="0" * 64)

    def test_nobits_and_unmapped_addresses_are_rejected(self):
        bss = self.image.named[".bss"]
        self.assertEqual(bss["type"], 8)
        with self.assertRaisesRegex(tool.EvidenceError, "outside file-backed"):
            self.image.offset(bss["address"] + bss["size"] - 8)
        with self.assertRaisesRegex(tool.EvidenceError, "not an FDE start"):
            self.image.exact_fde(tool.BUILDERS[0] + 1)

    def test_sell_adds_a_whole_tick_on_an_exact_multiple(self):
        buy = tool.BuilderCase("buy", 2500000, 2500000, side=0)
        sell = tool.BuilderCase("sell", 2500000, 2500000, side=1)
        self.assertEqual(self.limit_of(self.harness.run_builder(0, buy)), 2575000)
        self.assertEqual(self.limit_of(self.harness.run_builder(0, sell)), 2425100)
        self.assertEqual(self.limit_of(self.harness.run_builder(2, sell)), 2000100)

    def test_every_copy_matches_on_named_cases(self):
        cases = tool.builder_cases()[:60]
        for copy in range(len(tool.BUILDER_ROWS)):
            for case in cases:
                self.assertIsNone(tool.compare_builder(self.harness, copy, case))

    def test_empty_side_gives_the_no_price_word(self):
        result = self.harness.run_builder(1, tool.BuilderCase("empty", 0, 7))
        self.assertEqual(result["out"], (tool.TAG_NONE, tool.NO_PRICE))
        self.assertEqual(result["drops"], [tool.ERROR_WORD])

    def test_panics_carry_their_locations(self):
        result = self.harness.run_builder(0, tool.BuilderCase("dex", 5, 5, asset=10000, markets=1))
        self.assertEqual(result["stop"], ("unwrap", tool.LOCATION_BUILDER, tool.ERROR_WORD, tool.UNWRAP_MESSAGE))
        result = self.harness.run_builder(4, tool.BuilderCase("decimals", 5, 5, decimals=7))
        self.assertEqual(result["stop"], ("index", tool.LOCATION_TICK_DECIMALS))
        relative = {slot: addend for slot, kind, addend, _ in self.image.relocations() if kind == 8}
        path, line, column = self.image.location(tool.LOCATION_BUILDER, relative)
        self.assertTrue(path.endswith("clearinghouses.rs"))
        self.assertEqual((line, column), (11, 29))

    def test_tick_ladder_and_cap(self):
        for helper in tool.TICKS:
            self.assertEqual(self.harness.run_tick(3, 99999, 0, 8, 0, helper), {"tick": 1})
            self.assertEqual(self.harness.run_tick(3, 100000, 0, 8, 0, helper), {"tick": 10})
            self.assertEqual(self.harness.run_tick(3, 10 ** 19, 0, 8, 0, helper), {"tick": 10 ** 6})
            self.assertEqual(self.harness.run_tick(3, 10 ** 12, 4, 8, 0, helper), {"tick": 100})
            self.assertEqual(self.harness.run_tick(10000, 5, 2, 8, 1, helper), {"tick": 1})
            self.assertEqual(self.harness.run_tick(3, 5, 7, 8, 0, helper)["stop"], ("index", tool.LOCATION_TICK_DECIMALS))
            self.assertEqual(self.harness.run_tick(8, 5, 2, 8, 0, helper)["stop"], ("panic", tool.LOCATION_TICK_MARKET))

    def test_round_is_half_away_from_zero(self):
        for value, expected in ((2.5, 3.0), (-2.5, -3.0), (0.49999999999999994, 0.0), (1234.5, 1235.0)):
            self.assertEqual(self.harness.run_round(value), tool.to_bits(expected))

    def test_wrong_reconstructions_are_caught(self):
        cases = tool.builder_cases()
        for name, _ in tool.NEGATIVES:
            caught = any(tool.compare_builder(self.harness, copy, case, name)
                         for copy in (0, 2) for case in cases)
            self.assertTrue(caught, name)

    def test_flipped_side_branch_is_detected(self):
        rows = tool.decode_range(self.image, *self.image.exact_fde(tool.BUILDERS[0]))
        side = next(row for row in rows if row.op == "jcc" and row.size == 2 and row.va > tool.BUILDERS[0] + 0x100)
        harness = tool.Harness(self.image, tool.mutate_patch(self.image, side.va, 0))
        failures = [tool.compare_builder(harness, 0, case) for case in tool.builder_cases()[:4]]
        self.assertTrue(any(failures))

    def test_factor_bytes_are_pinned(self):
        blob = bytearray(self.image.blob)
        at = self.image.offset(tool.FACTOR_AT[0.97])
        blob[at] ^= 1
        with self.assertRaisesRegex(tool.EvidenceError, "price factors"):
            tool.builder_pins(tool.Image(bytes(blob)))
        pins = tool.builder_pins(self.image)
        self.assertEqual([pin["record_48"] for pin in pins], [6, 6, 1, 1, 6, 1])
        self.assertEqual([pin["field_set"] for pin in pins], [0, 1, 0, 1, 0, 0])

    def test_static_files_regenerate(self):
        files = tool.render(tool.analyse(self.image, full=False))
        for name, text in files.items():
            if name in ("mutations.tsv", "evidence.json"):
                continue
            self.assertEqual((PACKET / name).read_text(encoding="ascii"), text, name)

    def test_manifest_matches(self):
        import hashlib
        rows = (PACKET / "MANIFEST.sha256").read_text().splitlines()
        self.assertTrue(rows)
        for row in rows:
            digest, name = row.split("  ", 1)
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)


if __name__ == "__main__":
    unittest.main()
