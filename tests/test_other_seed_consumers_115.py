"""Tests for the RE-001 remaining per-thread LCG-seed consumers (node #115).

The expectations are grounded in the disassembly excerpts shipped in
research/work-items/RE-001-other-picker-seed-consumers-115/:
the shared advance (seed * 0x41a7 folded mod 0x7fffffff), the
geometric height draw of 0x6063150, the per-level descent pick of
0x6066b80, the 1-in-1024 / 1-in-256 sample flags, the sampler loop of
0x6066f20, the ZSTD gate of 0x60e5610, the bitmap-node fields of
0x60f4a00 and the LevelIterator record built by 0x5f6b000 /
0x5f999d0. Seeded random inputs drive the derivations end to end;
the height draw is cross-checked against an independent transcription
of the disassembly loop.
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from other_seed_consumers_115 import (  # noqa: E402
    bitmap_start,
    bitmap_word_count,
    descent_pick,
    height_byte_offset,
    height_draw,
    level_record,
    level_record_flag_byte,
    log2_byte,
    mersenne_step,
    sampler_step,
    sample_flag_1024,
    sample_flag_256,
    seed_init,
    zstd_gate,
    LEVELITER_RECORD_SIZE,
    LEVELITER_VTABLE,
    LEVELITER_PLUS_0X70,
    LEVELITER_PLUS_0XC8,
    NODE_DESCRIPTOR,
    ONESHOT_PATH_POINTER,
    ONESHOT_PATH_STRING,
    SAMPLE_MAGIC_1024,
)

MOD = 0x7FFFFFFF


def _reference_step(seed):
    """Independent transcription of the advance, written from the
    instruction sequence itself (imul / and / shr / add / lea /
    cmovs): fold the product, then subtract the modulus once when
    the 32-bit sum sets the sign flag."""
    v = seed * 0x41A7
    folded = (v & MOD) + (v >> 31)
    folded &= 0xFFFFFFFF
    if folded & 0x80000000:
        folded = (folded - MOD) & 0xFFFFFFFF
    return folded


def _reference_height_draw(seed, bound, count):
    """Independent transcription of the 0x6063150 loop: tries start
    at 1, each try advances once and stops at the first seed < bound;
    tries + 1 == count exhausts with height = count, tries + 1 == 32
    caps at 32; count <= 1 never advances and returns height 1."""
    if count <= 1:
        return (1, seed, 0)
    tries = 1
    cur = seed
    while True:
        cur = _reference_step(cur)
        if cur < bound:
            return (tries, cur, tries)
        if tries + 1 == count:
            return (count, cur, tries)
        if tries + 1 == 32:
            return (32, cur, tries)
        tries += 1


class TestMersenneStep(unittest.TestCase):
    def test_matches_reference_on_random_seeds(self):
        rng = random.Random(0x115)
        for _ in range(20000):
            seed = rng.randrange(0, MOD + 1)
            self.assertEqual(mersenne_step(seed), _reference_step(seed))

    def test_matches_true_modulus_except_zero_edge(self):
        # The instruction fold equals (seed * 0x41a7) % 0x7fffffff
        # everywhere except when low + high == 0x7fffffff exactly,
        # where the binary keeps 0x7fffffff and the modulus is 0.
        rng = random.Random(0x61C4080)
        for _ in range(20000):
            seed = rng.randrange(0, MOD + 1)
            v = seed * 0x41A7
            low, high = v & MOD, v >> 31
            if low + high == MOD:
                self.assertEqual(mersenne_step(seed), MOD)
            else:
                self.assertEqual(mersenne_step(seed), v % MOD)

    def test_range_and_fixed_points(self):
        self.assertEqual(mersenne_step(0), 0)
        self.assertEqual(mersenne_step(1), 0x41A7)
        for seed in (1, 2, 0x133, 0x3FF, 0x7FFFF, MOD):
            self.assertTrue(0 <= mersenne_step(seed) <= MOD)

    def test_deterministic(self):
        self.assertEqual(mersenne_step(123456789), mersenne_step(123456789))


class TestSeedInit(unittest.TestCase):
    def test_init_is_nonzero_and_in_range(self):
        for tid in (b"\x01\x00\x00\x00\x00\x00\x00\x00",
                    b"\xff\xff\xff\xff\xff\xff\xff\xff",
                    bytes(range(8))):
            v = seed_init(tid)
            self.assertTrue(1 <= v <= MOD)


class TestHeightDraw(unittest.TestCase):
    def test_matches_reference_on_random_inputs(self):
        rng = random.Random(0x6063150)
        for _ in range(5000):
            seed = rng.randrange(0, MOD + 1)
            bound = rng.randrange(0, MOD + 1)
            count = rng.randrange(0, 40)
            self.assertEqual(height_draw(seed, bound, count),
                             _reference_height_draw(seed, bound, count))

    def test_count_at_most_one_never_advances(self):
        for count in (0, 1):
            self.assertEqual(height_draw(0x1234567, 0x100, count),
                             (1, 0x1234567, 0))

    def test_bound_zero_exhausts_or_caps(self):
        # No seed is ever < 0, so the draw always runs to the cap.
        # count 5 exhausts after 4 advances (tries 1..4).
        s = 0x1234567
        for _ in range(4):
            s = mersenne_step(s)
        self.assertEqual(height_draw(0x1234567, 0, 5), (5, s, 4))
        # count 33: tries + 1 hits 32 first.
        h, s, a = height_draw(0x1234567, 0, 33)
        self.assertEqual((h, a), (32, 31))

    def test_bound_max_succeeds_on_first_try(self):
        h, s, a = height_draw(0x1234567, MOD, 20)
        self.assertEqual((h, a), (1, 1))
        self.assertEqual(s, mersenne_step(0x1234567))

    def test_height_byte_offset(self):
        self.assertEqual(height_byte_offset(1), 0)
        self.assertEqual(height_byte_offset(2), 8)
        self.assertEqual(height_byte_offset(32), 0xF8)

    def test_geometric_shape(self):
        # With bound = 2**30 the success probability per try is ~1/2,
        # so heights should cluster at small values and never exceed 32.
        rng = random.Random(0x6063150)
        heights = [height_draw(rng.randrange(MOD + 1), 1 << 30, 32)[0]
                   for _ in range(2000)]
        self.assertTrue(all(1 <= h <= 32 for h in heights))
        n_le3 = sum(1 for h in heights if h <= 3)
        n_eq1 = sum(1 for h in heights if h == 1)
        self.assertTrue(1500 < n_le3 < 1950, n_le3)
        self.assertTrue(800 < n_eq1 < 1200, n_eq1)


class TestDescentPick(unittest.TestCase):
    def test_index_in_range_and_advances_once(self):
        rng = random.Random(0x6066B80)
        for _ in range(1000):
            seed = rng.randrange(0, MOD + 1)
            n = rng.randrange(1, 64)
            new_seed, index = descent_pick(seed, n)
            self.assertEqual(new_seed, mersenne_step(seed))
            self.assertTrue(0 <= index < n)

    def test_single_entry_always_zero(self):
        self.assertEqual(descent_pick(0x1234567, 1)[1], 0)


class TestSampleFlags(unittest.TestCase):
    def test_flag_1024_exact_gate(self):
        # Find a seed whose advance lands exactly on the magic residue.
        rng = random.Random(0x5F6B000)
        found = None
        for _ in range(100000):
            seed = rng.randrange(0, MOD + 1)
            if mersenne_step(seed) & 0x3FF == SAMPLE_MAGIC_1024:
                found = seed
                break
        self.assertIsNotNone(found)
        _, flag = sample_flag_1024(found)
        self.assertTrue(flag)

    def test_flag_1024_rate(self):
        rng = random.Random(0x5F999D0)
        hits = sum(sample_flag_1024(rng.randrange(MOD + 1))[1]
                   for _ in range(200000))
        # 1/1024 expected; allow a wide tolerance for the seeded run.
        self.assertTrue(100 < hits < 300, hits)

    def test_flag_256_exact_gate_and_rate(self):
        rng = random.Random(0x5FCA940)
        found = None
        for _ in range(10000):
            seed = rng.randrange(0, MOD + 1)
            if mersenne_step(seed) & 0xFF == 0:
                found = seed
                break
        self.assertIsNotNone(found)
        _, skip = sample_flag_256(found)
        self.assertTrue(skip)
        hits = sum(sample_flag_256(rng.randrange(MOD + 1))[1]
                   for _ in range(50000))
        self.assertTrue(100 < hits < 300, hits)


class TestSamplerStep(unittest.TestCase):
    def test_hit_iff_index_below_remaining(self):
        rng = random.Random(0x6066F20)
        for _ in range(5000):
            seed = rng.randrange(0, MOD + 1)
            nodes = rng.randrange(1, 64)
            remaining = rng.randrange(0, nodes + 1)
            new_seed, index, hit = sampler_step(seed, nodes, remaining)
            self.assertEqual(new_seed, mersenne_step(seed))
            self.assertEqual(index, mersenne_step(seed) % nodes)
            self.assertEqual(hit, index < remaining)

    def test_empty_remaining_never_hits(self):
        _, _, hit = sampler_step(0x1234567, 8, 0)
        self.assertFalse(hit)


class TestZstdGate(unittest.TestCase):
    def test_gate_iff_modulo_zero(self):
        rng = random.Random(0x60E5610)
        for _ in range(5000):
            seed = rng.randrange(0, MOD + 1)
            n = rng.randrange(1, 64)
            new_seed, run = zstd_gate(seed, n)
            self.assertEqual(run, mersenne_step(seed) % n == 0)
            self.assertEqual(new_seed, mersenne_step(seed))

    def test_divisor_one_always_runs(self):
        for seed in (1, 2, 0x1234567, MOD):
            self.assertTrue(zstd_gate(seed, 1)[1])


class TestBitmapNode(unittest.TestCase):
    def test_log2_byte_table(self):
        expected = {0: 0, 1: 0, 2: 1, 3: 1, 4: 2, 5: 2, 6: 2, 7: 2,
                    8: 3, 16: 4, 32: 5, 64: 6, 100: 6, 1000: 9}
        for count, want in expected.items():
            self.assertEqual(log2_byte(count), want, count)

    def test_start_index_and_log2(self):
        rng = random.Random(0x60F4A00)
        for _ in range(1000):
            seed = rng.randrange(0, MOD + 1)
            count = rng.randrange(1, 1000)
            new_seed, start, shift = bitmap_start(seed, count)
            self.assertEqual(new_seed, mersenne_step(seed))
            self.assertEqual(start, mersenne_step(seed) % count)
            self.assertEqual(shift, log2_byte(count))

    def test_word_count_covers_table(self):
        # The bitmap must cover table_count - 1 bits (0 .. table_count-2).
        for count in (2, 3, 4, 32, 33, 64, 100, 1000, 65536):
            words = bitmap_word_count(count)
            shift = log2_byte(count)
            covered = words * NODE_DESCRIPTOR[1] * (1 << shift)
            self.assertGreaterEqual(covered, count - 1)
            self.assertLess((words - 1) * NODE_DESCRIPTOR[1] * (1 << shift),
                            count - 1)


class TestLevelRecord(unittest.TestCase):
    def test_record_fields(self):
        rec = level_record(
            shard_index=3, predicate=True, sample_flag=True,
            stats_record=0xDEADBEEF, entry_ptr=0x1234, arg2=0x5678,
            arg3=0x9ABC, cleanable_ptr=0x7777, next_ptr=0x8888)
        self.assertEqual(rec["vtable"], LEVELITER_VTABLE)
        self.assertEqual(rec["size"], LEVELITER_RECORD_SIZE)
        self.assertEqual(rec["shard_index"], 3)
        self.assertTrue(rec["predicate"])
        self.assertTrue(rec["sample_flag"])
        self.assertEqual(rec["stats_record"], 0xDEADBEEF)
        self.assertEqual(rec["entry_ptr"], 0x1234)
        self.assertEqual(rec["path_pointer"], ONESHOT_PATH_POINTER)
        self.assertEqual(rec["arg2"], 0x5678)
        self.assertEqual(rec["arg3"], 0x9ABC)

    def test_fixed_fields(self):
        # Corrected after slopbot's limited review on PR #4156:
        # +0x70 is movabs $0xffffffffffffff (56-bit), not -1;
        # +0xc8 is u16 0x100 in both builders.
        self.assertEqual(LEVELITER_PLUS_0X70, 0x00FFFFFFFFFFFFFF)
        self.assertNotEqual(LEVELITER_PLUS_0X70, 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(LEVELITER_PLUS_0XC8, 0x100)

    def test_flag_byte_differs_per_builder(self):
        # Builder 0x5f6b000 stores the 6th argument's low byte;
        # lookup 0x5f999d0 stores u16 0x100 (low byte 0x00).
        self.assertEqual(level_record_flag_byte("builder", 0x5A), 0x5A)
        self.assertEqual(level_record_flag_byte("builder", 0x00), 0x00)
        self.assertEqual(level_record_flag_byte("lookup"), 0x00)
        with self.assertRaises(ValueError):
            level_record_flag_byte("builder")
        with self.assertRaises(ValueError):
            level_record_flag_byte("other")

    def test_oneshot_path_pointer_literal(self):
        # The stored pointer is 0x4376fd; the path string begins one
        # byte later (verified by a raw byte read of the binary).
        self.assertEqual(ONESHOT_PATH_POINTER, 0x4376FD)
        self.assertTrue(ONESHOT_PATH_STRING.endswith("oneshot.rs"))
        self.assertTrue(ONESHOT_PATH_STRING.startswith(
            "/home/ubuntu/hl/code_Mainnet/"))


if __name__ == "__main__":
    unittest.main()
