import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import hyperliquidity_seed_115 as h  # noqa: E402

DATA = h.TARGET.read_bytes()
IMAGE = h.cpu.Image(DATA)
h.init(IMAGE)


class Digest(unittest.TestCase):
    def test_digest_matches(self):
        self.assertTrue(h.check_digest(DATA))

    def test_flipped_byte_is_refused(self):
        damaged = bytearray(DATA)
        damaged[1234] ^= 0x40
        self.assertFalse(h.check_digest(bytes(damaged)))

    def test_body_extent(self):
        self.assertEqual(h.body_extent(IMAGE, h.ENTRY), h.SIZE)
        with self.assertRaises(h.cpu.ToolError):
            h.body_extent(IMAGE, h.ENTRY + 1)


class Messages(unittest.TestCase):
    def test_texts(self):
        self.assertEqual(h.MESSAGES["too_many"], b"too many Hyperliquidity orders")
        self.assertEqual(h.MESSAGES["quote"], b"quote token must be USDC for Hyperliquidity")
        self.assertEqual(h.MESSAGES["funds"], b"insufficient usdc for seeding hyperliquidity")
        self.assertTrue(h.MESSAGES["mcap"].startswith(b"market cap must be in range [1B, 100B] USDC"))
        self.assertEqual(len(h.MESSAGES["mcap"]), 119)

    def test_unknown_text_does_not_classify(self):
        self.assertEqual(h.classify(("err", b"other")), "err:?")


class Specification(unittest.TestCase):
    def test_saturation_edges(self):
        c = h.CONV
        self.assertEqual(h.saturate(float("nan"), c), 0)
        self.assertEqual(h.saturate(float("inf"), c), 0)
        self.assertEqual(h.saturate(-1.5, c), 0)
        self.assertEqual(h.saturate(-0.0, c), 0)
        self.assertEqual(h.saturate(12345.9, c), 12345)
        self.assertEqual(h.saturate(2.0 ** 63, c), 1 << 63)
        self.assertEqual(h.saturate(2.0 ** 64, c), h.U64)
        self.assertEqual(h.saturate(1e300, c), h.U64)

    def test_tree_search(self):
        self.assertIsNone(h.tree_search(0, [], None, 5))
        self.assertIsNotNone(h.tree_search(0, [1, 5, 9], None, 5))
        kids = [([1, 2], None), ([6, 7], None)]
        self.assertIsNotNone(h.tree_search(1, [5], kids, 7))
        self.assertIsNone(h.tree_search(1, [5], kids, 3))

    def test_cases_are_deterministic(self):
        self.assertEqual(h.make_case(77), h.make_case(77))
        self.assertNotEqual(h.make_case(77), h.make_case(78))


class Bytes(unittest.TestCase):
    def test_sample_matches_specification(self):
        self.assertIsNone(h.run_cases(IMAGE, 600))

    def test_outcome_classes_are_reached(self):
        seen = set()
        for i in range(len(h.CLASSES) * 4):
            seen.add(h.classify(h.compare(IMAGE, h.make_case(i))[1]))
        for want in ("ok", "err:exists", "err:hold", "err:quote", "err:no_supply", "err:config", "err:balance",
                     "err:start_value", "err:mcap", "err:funds", "panic:panic_rows"):
            self.assertIn(want, seen)

    def test_hype_is_exempt_from_the_market_cap_band(self):
        hit = 0
        for i in range(h.CLASSES.index("hype"), 40 * len(h.CLASSES), len(h.CLASSES)):
            got = h.compare(IMAGE, h.make_case(i))[1]
            hit += got[0] == "ok" or got[0] == "err" and got[1] != h.MESSAGES["mcap"]
        self.assertGreater(hit, 0)


class NegativeControls(unittest.TestCase):
    def test_wrong_specifications_are_caught(self):
        for name in ("many_gt", "hold_inv", "cost_ge", "hype_any", "order_swap", "supply_skip"):
            self.assertIsNotNone(h.run_cases(IMAGE, 700, (name,)), name)

    def test_damaged_bytes_are_caught(self):
        for patch in h.BYTE_PATCHES[:12:3]:
            self.assertIsNotNone(h.run_cases(h.patched_image(IMAGE, patch), 700), patch[0])

    def test_missing_pattern_is_refused(self):
        with self.assertRaises(h.cpu.ToolError):
            h.patched_image(IMAGE, ("none", b"\x00\x01\x02\x03\x04\x05\x06\x07\x08", 0, 1, "absent"))

    def test_misc_controls_all_detected(self):
        for name, meaning, detected in h.misc_controls(IMAGE):
            self.assertTrue(detected, name)

    def test_unknown_call_site_is_refused(self):
        m = h.Recorder(IMAGE)
        m.setup({})
        with self.assertRaises(h.cpu.ToolError):
            m.call(0, h.ENTRY + 2)


if __name__ == "__main__":
    unittest.main()
