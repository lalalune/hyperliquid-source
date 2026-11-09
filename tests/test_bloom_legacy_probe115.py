import hashlib
import json
import pathlib
import random
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import bloom_legacy_probe115 as t  # noqa: E402

FOLDER = ROOT / "research" / "work-items" / "RE-009-legacy-bloom-probe-115"


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.Image(t.BINARY.read_bytes())
        cls.rows = t.function_rows(cls.image)


class ModelTests(Base):
    def test_hash_matches_machine_on_every_tail_length(self):
        hn = t.Harness(self.image)
        rng = random.Random(7)
        for n in range(0, 25):
            data = bytes(rng.randrange(256) for _ in range(n))
            got, _ = hn.run_hash(data, t.SEED)
            self.assertEqual(got, t.hash32(data), n)

    def test_hash_sign_extends_tail_bytes(self):
        hn = t.Harness(self.image)
        data = b"\xff\x80\x81"
        self.assertEqual(hn.run_hash(data, t.SEED)[0], t.hash32(data))
        self.assertNotEqual(t.hash32(data), t.hash32(data, mut=("zext",)))

    def test_hash_aligned_lengths_skip_final_mix(self):
        data = b"abcd"
        h = (t.SEED ^ (4 * t.MUL)) & t.M32
        h = ((h + int.from_bytes(data, "little")) * t.MUL) & t.M32
        h ^= h >> 16
        self.assertEqual(t.hash32(data), h)

    def test_probe_geometry_single_key(self):
        rng = random.Random(3)
        hn = t.Harness(self.image)
        key = b"user-key"
        data = bytearray(3 << 6)
        t.set_bits(data, 3, 6, key, 6)
        self.assertTrue(hn.run_single(bytes(data), 6, 3, 6, key)[0])
        self.assertTrue(t.single_may_match(bytes(data), 6, 3, 6, key))
        self.assertFalse(hn.run_single(bytes(3 << 6), 6, 3, 6, key)[0])
        self.assertTrue(hn.run_single(bytes(3 << 6), 0, 3, 6, key)[0])
        self.assertIsNotNone(rng)

    def test_multi_matches_single_per_key(self):
        keys = [b"a", b"bb", b"ccc", b"", b"dddd"]
        data = bytearray(7 << 6)
        for k in keys[::2]:
            t.set_bits(data, 7, 6, k, 8)
        hn = t.Harness(self.image)
        outs, _ = hn.run_multi(bytes(data), 8, 7, 6, keys)
        singles = [int(hn.run_single(bytes(data), 8, 7, 6, k)[0]) for k in keys]
        self.assertEqual(outs, singles)
        self.assertEqual(outs, [int(x) for x in t.multi_may_match(bytes(data), 8, 7, 6, keys)])

    def test_addkey_suppresses_only_the_last_duplicate_and_grows_at_capacity(self):
        hn = t.Harness(self.image)
        h = t.hash32(b"k")
        got, grows, _ = hn.run_addkey([5, h], 4, b"k")
        self.assertEqual((got, grows), ([5, h], 0))
        got, grows, _ = hn.run_addkey([h, 5], 4, b"k")
        self.assertEqual((got, grows), ([h, 5, h], 0))
        got, grows, _ = hn.run_addkey([h, 5], 2, b"k")
        self.assertEqual((got, grows), ([h, 5, h], 1))
        got, grows, _ = hn.run_addkey([], 0, b"k")
        self.assertEqual((got, grows), ([h], 1))

    def test_full_run_has_no_mismatch(self):
        res, _ = t.evaluate(self.image, counts=(200, 300, 100, 200))
        self.assertEqual(res["mismatches"], 0)
        self.assertEqual(res["cases"], 800)


class StaticTests(Base):
    def test_function_extents(self):
        want = {"hash": (0x61c34a0, 0x61c3525), "single": (0x612d930, 0x612d9e4),
                "multi": (0x612d7b0, 0x612d929), "addkey": (0x61365c0, 0x6136645)}
        self.assertEqual({n: (s, e) for n, s, e in self.rows}, want)

    def test_call_edges(self):
        _, targets = t.static_rows(self.image, self.rows)
        for name in ("single", "multi", "addkey"):
            self.assertIn(t.HASH, targets[name])
        self.assertIn(t.GROW, targets["addkey"])
        self.assertNotIn("hash", targets)

    def test_seed_immediate_in_all_callers(self):
        pat = bytes.fromhex("ba341d9fbc")
        for name, s, e in self.rows:
            if name != "hash":
                self.assertIn(pat, self.image.code(s, e - s), name)


class NegativeTests(Base):
    def test_wrong_models_are_detected(self):
        for name, mut in t.mutant_names():
            self.assertTrue(t.battery(self.image, None, mut), name)

    def test_corrupted_code_bytes_are_detected(self):
        for name, va, new in t.byte_controls(self.image, self.rows):
            self.assertTrue(t.battery(self.image, {va: new}), name)

    def test_unmodified_battery_agrees(self):
        self.assertFalse(t.battery(self.image))

    def test_damaged_binary_is_rejected(self):
        data = bytearray(self.image.data)
        data[1000] ^= 1
        with self.assertRaises(t.ToolError):
            t.Image(bytes(data))

    def test_non_fde_start_is_not_a_function(self):
        starts = {s for _, s, _ in self.rows}
        for va in (t.HASH + 4, 0, 0x600000):
            self.assertNotIn(va, starts)

    def test_zero_line_filter_is_rejected_by_the_machine(self):
        hn = t.Harness(self.image)
        m = hn.setup_filter(bytes(64), 6, 0, 6)
        with self.assertRaises(t.ToolError):
            hn.call(t.SINGLE, t.SELF_AT, hn.put_key(m, 0, b"x", 0))


@unittest.skipUnless(FOLDER.exists(), "packet folder not present")
class EvidenceTests(Base):
    def test_manifest_hashes(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = t.generate(tmp)
            self.assertEqual(summary["negative_controls"], summary["negative_detected"])
            for path in sorted(pathlib.Path(tmp).iterdir()):
                self.assertEqual(path.read_bytes(), (FOLDER / path.name).read_bytes(), path.name)

    def test_measure_matches_summary(self):
        measure = json.loads((FOLDER / "measure.json").read_text())
        summary = json.loads((FOLDER / "summary.json").read_text())
        self.assertEqual(measure["cases"], summary["cases"])
        self.assertEqual(measure["negative_controls"], summary["negative_controls"])
        self.assertEqual(measure["negative_detected"], summary["negative_detected"])


if __name__ == "__main__":
    unittest.main()
