import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "instrumented_acquire_6ca40_115",
    Path(__file__).resolve().parents[1]
    / "tools/instrumented_acquire_6ca40_115.py",
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def make_hooks(tls_byte=0, global_nonzero=False, timer_values=()):
    calls = []
    timer = iter(timer_values)
    hooks = {
        "tls_byte": tls_byte,
        "global_nonzero": global_nonzero,
        "counter": [0],
        "prologue": lambda: calls.append("prologue"),
        "tls_getter": lambda: calls.append("tls_getter"),
        "begin": lambda record: calls.append(("begin", dict(record))),
        "now": lambda: next(timer),
        "lock": lambda: calls.append("lock"),
        "observe": lambda ctx, typ, elapsed: calls.append(
            ("observe", typ, elapsed)
        ),
    }
    return hooks, calls


def obj(ctx_byte=None, flag=True, typ=0x34):
    ctx = None if ctx_byte is None else {"byte": ctx_byte}
    return {"ctx": ctx, "flag_nonzero": flag, "type_code": typ}


class InstrumentedAcquireTests(unittest.TestCase):
    def test_fast_timer_path_full_order(self):
        hooks, calls = make_hooks(
            tls_byte=5, global_nonzero=True, timer_values=(100, 160)
        )
        out = mod.acquire(obj(ctx_byte=5), hooks)
        self.assertEqual(
            [c for c in calls if isinstance(c, str)],
            ["prologue", "tls_getter", "lock"],
        )
        # begin carries the record; now runs twice around the lock.
        self.assertEqual(calls[2][0], "begin")
        self.assertEqual(calls[2][1]["flag"], True)
        self.assertEqual(calls[2][1]["type_code"], 0x34)
        self.assertEqual(out["events"], [
            "prologue", "tls_getter", "begin", "now", "lock", "now",
            "observe",
        ])
        self.assertEqual(calls[-1], ("observe", 0x34, 60))
        self.assertEqual(out["counter"], 60)
        self.assertTrue(out["guard_dispose_on_unwind"])

    def test_fast_non_timer_type_locks_only_after_begin(self):
        hooks, calls = make_hooks(tls_byte=5, timer_values=())
        out = mod.acquire(obj(ctx_byte=9, typ=0x33), hooks)
        self.assertEqual(out["events"], ["prologue", "begin", "lock"])
        self.assertEqual(out["counter"], 0)
        self.assertFalse(out["guard_dispose_on_unwind"])

    def test_fast_zero_first_timer_skips_rest(self):
        hooks, calls = make_hooks(tls_byte=5, timer_values=(0,))
        out = mod.acquire(obj(ctx_byte=9), hooks)
        self.assertEqual(out["events"], ["prologue", "begin", "now", "lock"])
        self.assertEqual(out["counter"], 0)
        self.assertFalse(out["guard_dispose_on_unwind"])

    def test_fallback_timer_path_no_observe(self):
        hooks, calls = make_hooks(tls_byte=6, timer_values=(10, 25))
        out = mod.acquire(obj(ctx_byte=None, flag=False), hooks)
        self.assertEqual(out["events"], [
            "prologue", "begin", "now", "lock", "now",
        ])
        self.assertEqual(out["counter"], 15)
        self.assertTrue(out["guard_dispose_on_unwind"])

    def test_fallback_no_tls_flag_locks_directly(self):
        hooks, calls = make_hooks(tls_byte=4, timer_values=())
        out = mod.acquire(obj(ctx_byte=None, flag=False), hooks)
        self.assertEqual(out["events"], ["prologue", "lock"])
        self.assertEqual(out["counter"], 0)

    def test_context_byte_at_limit_falls_back(self):
        hooks, calls = make_hooks(tls_byte=5, timer_values=(7, 9))
        out = mod.acquire(obj(ctx_byte=4), hooks)
        # Byte == 4 is not > 4, so the fallback runs: no observe.
        self.assertNotIn("observe", out["events"])
        self.assertEqual(out["counter"], 2)

    def test_context_byte_above_limit_is_fast(self):
        hooks, calls = make_hooks(tls_byte=0, timer_values=(3, 8))
        out = mod.acquire(obj(ctx_byte=5), hooks)
        # Fast path even with the TLS flag clear: observe still runs,
        # the counter add does not.
        self.assertIn("observe", out["events"])
        self.assertEqual(out["counter"], 0)

    def test_tls_byte_at_limit_no_timer_in_fallback(self):
        hooks, calls = make_hooks(tls_byte=4, timer_values=())
        out = mod.acquire(obj(ctx_byte=2), hooks)
        self.assertEqual(out["events"], ["prologue", "lock"])

    def test_global_zero_skips_tls_getter(self):
        hooks, calls = make_hooks(tls_byte=5, timer_values=(1, 2))
        out = mod.acquire(obj(ctx_byte=9), hooks)
        self.assertNotIn("tls_getter", out["events"])

    def test_null_object_raises(self):
        hooks, _ = make_hooks()
        with self.assertRaises(mod.NullObjectError):
            mod.acquire(None, hooks)

    def test_null_context_with_flag_falls_back(self):
        hooks, calls = make_hooks(tls_byte=4, timer_values=())
        out = mod.acquire(obj(ctx_byte=None, flag=True), hooks)
        self.assertEqual(out["events"], ["prologue", "lock"])


if __name__ == "__main__":
    unittest.main()
