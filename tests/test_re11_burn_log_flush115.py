import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_burn_log_flush115 as t  # noqa: E402

SIZES = {0x2970eb0: 559, 0x4322d00: 559, 0x54631e0: 559, 0x29714f0: 617, 0x54635f0: 617,
         0x2972200: 398, 0x4324300: 388}


class BurnLogFlush(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.Image(t.BINARY.read_bytes())
        cls.ctx = t.Context(cls.image)
        cls.m = t.machine_for(cls.ctx)

    def cases(self, fn, n):
        for i in range(n):
            if fn in t.FLUSH:
                yield t.flush_case(fn, i)
            else:
                yield t.emit_case(fn, "burn" if fn in t.BURN else "transfer", i)

    def pool(self, fn, n=60):
        out = []
        for c in self.cases(fn, n):
            ok, got, _ = t.evaluate_one(self.ctx, self.m, c)
            self.assertTrue(ok, c["id"])
            out.append((c, got))
        return out

    def test_extents_come_from_unwind_records(self):
        for fn, size in SIZES.items():
            self.assertEqual(self.ctx.ends[fn] - fn, size)

    def test_every_body_agrees_with_the_reconstruction(self):
        for fn in SIZES:
            self.assertEqual(len(self.pool(fn)), 60)

    def test_zero_value_logs_nothing_and_value_logs_big_endian(self):
        c = t.emit_case(0x2970eb0, "burn", 3)
        c.update(spec=0x0e, f124=0, fail_at=None, args=[bytes(range(20)), bytes(32)])
        ok, got, _ = t.evaluate_one(self.ctx, self.m, c)
        self.assertTrue(ok)
        self.assertEqual(len(got["log"]), len(c["init"]))
        value = bytes(range(1, 33))
        c["args"] = [bytes(range(20)), value]
        ok, got, _ = t.evaluate_one(self.ctx, self.m, c)
        self.assertTrue(ok)
        self.assertEqual(len(got["log"]), len(c["init"]) + 1)
        self.assertIn(value[::-1], got["blocks"].values())

    def test_alloc_failures_are_the_two_distinct_panics(self):
        kinds = set()
        for i in range(400):
            c = t.emit_case(0x29714f0, "transfer", i)
            if c["fail_at"] is not None and c["spec"] >= t.SPEC_MIN and not c["f124"] and any(c["args"][-1]):
                ok, got, _ = t.evaluate_one(self.ctx, self.m, c)
                self.assertTrue(ok)
                kinds.add(got["ret"][1:])
        self.assertEqual(len(kinds), 2)

    def test_flush_sorts_and_big_lists_reach_the_sort_slot(self):
        seen = set()
        for i in range(300):
            c = t.flush_case(0x2972200, i)
            ok, got, _ = t.evaluate_one(self.ctx, self.m, c)
            self.assertTrue(ok)
            seen.update(x[0] for x in got["trace"])
        self.assertTrue({"growvec", "bigsort", "loggrow", "free"} <= seen)

    def test_wrong_reconstructions_are_detected(self):
        pools = {fn: self.pool(fn, 120) for fn in (0x2970eb0, 0x2972200)}
        for mut, fn in (("spec_ge0f", 0x2970eb0), ("no_pad", 0x2970eb0), ("swap_vt", 0x2970eb0),
                        ("sort_desc", 0x2972200), ("free_len", 0x2972200), ("ignore_items", 0x2972200)):
            hit = any(not t.compare(c, t.expected(c, self.ctx.E[fn], self.ctx.F.get(fn), frozenset({mut})), got)
                      for c, got in pools[fn])
            self.assertTrue(hit, mut)

    def test_inverted_branch_in_the_code_bytes_is_detected(self):
        fn = 0x2970eb0
        pool = [c for c, _ in self.pool(fn, 80)]
        site = next(at for _, at, _ in t.jcc_sites(self.ctx.rows[fn]))
        old = self.image.code(site, 1)[0]
        self.assertTrue(t.detect_bytes(self.ctx, pool, fn, site, old ^ 1))
        self.assertFalse(t.detect_bytes(self.ctx, pool, fn, site, old))

    def test_corrupt_inputs_are_rejected(self):
        bad = bytearray(t.BINARY.read_bytes())
        bad[1000] ^= 1
        with self.assertRaises(t.ToolError):
            t.Image(bytes(bad))
        with self.assertRaises((t.ToolError, KeyError, IndexError, ValueError)):
            t.emitter_facts(self.image, self.ctx.ends, 0x29710e0)
        with self.assertRaises(t.ToolError):
            t.ev.sweep(self.image, 0x2970eb0, self.ctx.ends[0x2970eb0] - 1)

    def test_roles_are_read_from_bytes(self):
        a, b = self.ctx.E[0x2970eb0], self.ctx.E[0x29714f0]
        self.assertEqual(a["c_ent"], b["c_ent"])
        self.assertNotEqual(a["c_lo"], b["c_lo"])
        self.assertEqual(self.ctx.F[0x2972200]["emitter"], 0x2970eb0)
        self.assertEqual(self.ctx.F[0x4324300]["emitter"], 0x4322d00)


if __name__ == "__main__":
    unittest.main()
