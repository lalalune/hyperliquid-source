"""Tests for the node #94 WAL flush driver model (RE-001, 0x50ebfb0).

The model pins the driver's own control flow; the handler and every
phase are injectable, so these tests drive them with recording hooks
and assert the exact gate order, collection rule, copy/stop rules,
phase order, marking rules, and teardown behavior from the evidence
packet, plus packet verification against the digest-bound binary.

Run with:
    python3 -m unittest tests.test_wal_flush_driver -v
(pytest is not installed on this VM.)
"""
import json
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from wal_flush_driver import (  # noqa: E402
    CONTEXT_INIT,
    MAIN_FILE,
    MAIN_FORMAT,
    SWEEP_FORMAT,
    Db,
    Hooks,
    Item,
    Result,
    drive_flush,
)

REPO = Path(__file__).resolve().parent.parent
PACKET = REPO / "research" / "work-items" / "RE-001-wal-flush-driver-94"
BINARY = REPO / "work" / "hl-node-94.bin"
DIGEST = ("3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575"
          "eff1c0459f")
WINDOW = 0x50EBFB0


class RecordingHooks(Hooks):
    def __init__(self):
        self.calls = []
        self.scored = []
        self.freed = []
        self.phase_e_contexts = []

    def entry_hook(self, db):
        self.calls.append("entry_hook")

    def third_log_value(self, db):
        self.calls.append("third_log_value")
        return 777

    def log(self, level, file, fmt, values):
        self.calls.append(("log", level, fmt, tuple(values)))

    def sweep(self, db):
        self.calls.append("sweep")
        return db.sweep_result

    def score(self, item):
        self.scored.append(item)
        return item.score

    def phase_a(self, db, count_slot, overflow):
        self.calls.append(("phase_a", count_slot, len(overflow)))

    def phase_b(self, db, context):
        self.calls.append("phase_b")

    def phase_c(self, db, context):
        self.calls.append("phase_c")

    def phase_d(self, db, context):
        self.calls.append("phase_d")

    def phase_e(self, db, context):
        self.calls.append("phase_e")
        self.phase_e_contexts.append(dict(context))

    def phase_f(self, db, context):
        self.calls.append("phase_f")

    def phase_g(self, db, context):
        self.calls.append("phase_g")

    def marking_phase(self, db, item, context):
        self.calls.append(("marking_phase", item))

    def handler(self, db, item, arg3, context):
        self.calls.append(("handler", item))
        return item.handler_result

    def release(self, item):
        self.calls.append(("release", item))

    def free(self, ptr):
        self.freed.append(ptr)

    def destroy_condition_variable(self, context):
        self.calls.append("destroy_cv")


def run(db, hooks=None):
    hooks = hooks or RecordingHooks()
    out = Result()
    drive_flush(out, db, "arg3", hooks)
    return out, hooks


def call_names(hooks):
    return [c if isinstance(c, str) else c[0] for c in hooks.calls]


def log_calls(hooks, level):
    return [c for c in hooks.calls
            if isinstance(c, tuple) and c[0] == "log" and c[1] == level]


class DriverTest(unittest.TestCase):
    def test_gate_a_returns_zeroed_result_without_side_effects(self):
        db = Db(wal_number=5)
        db.gate_a_flag = True
        out, hooks = run(db)
        self.assertEqual((out.code, out.subcode, out.ptr), (0, 0, None))
        self.assertEqual(hooks.calls, ["entry_hook"])

    def test_sweep_zero_reenters_main_path(self):
        db = Db(wal_number=5, c28=11)
        db.flag_4a3 = True
        db.sweep_result = 0
        out, hooks = run(db)
        self.assertFalse(db.flag_1511)
        self.assertTrue(db.gate_a_flag)
        self.assertIn(("log", 1, MAIN_FORMAT, (5, 11, 777)), hooks.calls)
        self.assertLess(hooks.calls.index("sweep"),
                        hooks.calls.index("third_log_value"))

    def test_sweep_other_value_reenters_main_path(self):
        db = Db(wal_number=5)
        db.flag_4a3 = True
        db.sweep_result = 9
        out, hooks = run(db)
        self.assertFalse(db.flag_1511)
        self.assertTrue(db.gate_a_flag)
        self.assertEqual(len(log_calls(hooks, 1)), 1)

    def test_sweep_equal_flag_clear_logs_once_and_restarts(self):
        db = Db(wal_number=5)
        db.flag_4a3 = True
        db.sweep_result = 5
        out, hooks = run(db)
        self.assertIn(("log", 2, SWEEP_FORMAT, ()), hooks.calls)
        self.assertTrue(db.flag_1511)
        # The restart skips the gate-A flag store.
        self.assertFalse(db.gate_a_flag)
        self.assertEqual(len(log_calls(hooks, 1)), 1)

    def test_sweep_equal_flag_set_returns_immediately(self):
        db = Db(wal_number=5)
        db.flag_4a3 = True
        db.flag_1511 = True
        db.sweep_result = 5
        out, hooks = run(db)
        self.assertEqual((out.code, out.subcode, out.ptr), (0, 0, None))
        self.assertEqual(hooks.calls, ["entry_hook", "sweep"])

    def test_main_log_slots_in_order(self):
        db = Db(wal_number=42, c28=1000)
        out, hooks = run(db)
        self.assertEqual(log_calls(hooks, 1),
                         [("log", 1, MAIN_FORMAT, (42, 1000, 777))])
        self.assertEqual(MAIN_FILE, "db/db_impl/db_impl_write.cc")

    def test_collection_skips_flagged_and_below_threshold(self):
        db = Db(wal_number=10)
        flagged = Item(flagged=True, score=999)
        low = Item(score=9)
        equal = Item(score=10)
        high = Item(score=50)
        db.items = [flagged, low, equal, high]
        out, hooks = run(db)
        self.assertEqual(hooks.scored, [low, equal, high])
        handled = [c[1] for c in hooks.calls
                   if isinstance(c, tuple) and c[0] == "handler"]
        self.assertEqual(handled, [equal, high])
        self.assertIn(("phase_a", 2, 0), hooks.calls)

    def test_collection_overflow_order_preserved(self):
        db = Db(wal_number=0)
        db.items = [Item(score=1) for _ in range(10)]
        out, hooks = run(db)
        handled = [c[1] for c in hooks.calls
                   if isinstance(c, tuple) and c[0] == "handler"]
        self.assertEqual(handled, db.items)  # inline 8 then overflow 2
        self.assertIn(("phase_a", 10, 2), hooks.calls)

    def test_per_item_copy_stop_and_free_rules(self):
        db = Db(wal_number=0)
        first = Item()
        first.handler_result = Result(code=0x100, subcode=7, ptr="p1")
        second = Item()
        second.handler_result = Result(code=0x1000005, subcode=3, ptr="p2")
        third = Item()
        third.handler_result = Result(code=9, subcode=1, ptr="p3")
        db.items = [first, second, third]
        out, hooks = run(db)
        # 0x100 has low byte 0, so the loop continues past the first;
        # 0x1000005 has low byte 5, so it stops there; third never runs.
        self.assertEqual((out.code, out.subcode, out.ptr),
                         (0x1000005, 3, "p2"))
        self.assertEqual(hooks.freed, ["p1"])
        self.assertEqual(first.handler_result.subcode, 0)
        self.assertEqual(second.handler_result.subcode, 0)
        self.assertEqual((first.refcount, second.refcount, third.refcount),
                         (1, 1, 0))
        handled = [c[1] for c in hooks.calls
                   if isinstance(c, tuple) and c[0] == "handler"]
        self.assertEqual(handled, [first, second])
        names = call_names(hooks)
        self.assertNotIn("phase_e", names)
        self.assertNotIn("phase_f", names)
        self.assertNotIn("marking_phase", names)

    def test_phase_order_plain_success_path(self):
        db = Db(wal_number=0)
        db.items = [Item(value900=5)]
        out, hooks = run(db)
        names = call_names(hooks)
        self.assertLess(names.index("phase_a"), names.index("handler"))
        self.assertLess(names.index("handler"), names.index("marking_phase"))
        self.assertLess(names.index("marking_phase"), names.index("phase_e"))
        self.assertLess(names.index("phase_e"), names.index("phase_f"))
        for phase in ("phase_b", "phase_c", "phase_d"):
            self.assertNotIn(phase, names)

    def test_phase_order_with_17b0_set(self):
        db = Db(wal_number=0)
        db.flag_17b0 = True
        db.items = [Item()]
        out, hooks = run(db)
        names = call_names(hooks)
        self.assertLess(names.index("phase_b"), names.index("handler"))
        self.assertLess(names.index("handler"), names.index("phase_c"))
        self.assertLess(names.index("phase_c"), names.index("marking_phase"))

    def test_phase_g_replaces_collection_and_phase_a(self):
        db = Db(wal_number=0)
        db.flag_4c7 = True
        db.flag_17b0 = True
        db.items = [Item(), Item()]
        out, hooks = run(db)
        names = call_names(hooks)
        self.assertIn("phase_g", names)
        self.assertNotIn("phase_a", names)
        self.assertNotIn("handler", names)  # empty collection: total 0
        self.assertLess(names.index("phase_b"), names.index("phase_c"))
        self.assertLess(names.index("phase_c"), names.index("phase_d"))
        self.assertLess(names.index("phase_d"), names.index("phase_e"))
        self.assertLess(names.index("phase_e"), names.index("phase_f"))

    def test_empty_collection_skips_marking_but_runs_e_and_f(self):
        db = Db(wal_number=0)
        out, hooks = run(db)
        names = call_names(hooks)
        self.assertNotIn("handler", names)
        self.assertNotIn("marking_phase", names)
        self.assertLess(names.index("phase_e"), names.index("phase_f"))

    def test_marking_rules_and_fresh_flag_read(self):
        db = Db(wal_number=0)
        positive = Item(value900=3)
        zero = Item(value900=0)
        negative = Item(value900=-2)
        db.items = [positive, zero, negative]

        class FlipHooks(RecordingHooks):
            def marking_phase(self, db, item, context):
                super().marking_phase(db, item, context)
                db.flag_4c7 = True  # flips after the first item's phase

        out, hooks = run(db, FlipHooks())
        self.assertTrue(positive.mark905 and positive.mark8f0)
        self.assertTrue(zero.mark905 and not zero.mark8f0)
        self.assertTrue(negative.mark905 and not negative.mark8f0)
        phases = [c for c in hooks.calls
                  if isinstance(c, tuple) and c[0] == "marking_phase"]
        self.assertEqual([c[1] for c in phases], [positive])
        # The post-loop chain was already decided (flag was 0 at the
        # check), so the run still ends with E and F, not D.
        names = call_names(hooks)
        self.assertNotIn("phase_d", names)
        self.assertIn("phase_e", names)
        self.assertIn("phase_f", names)

    def test_early_exit_with_17b0_runs_phase_c_then_teardown_only(self):
        db = Db(wal_number=0)
        db.flag_17b0 = True
        bad = Item()
        bad.handler_result = Result(code=1, subcode=0, ptr=None)
        db.items = [bad, Item()]
        out, hooks = run(db)
        names = call_names(hooks)
        self.assertEqual(names.count("handler"), 1)
        self.assertIn("phase_c", names)
        for phase in ("marking_phase", "phase_e", "phase_f", "phase_d"):
            self.assertNotIn(phase, names)

    def test_context_init_and_phase_e_context_values(self):
        db = Db(wal_number=0)
        db.items = [Item()]
        out, hooks = run(db)
        self.assertTrue(hooks.phase_e_contexts)
        ctx = hooks.phase_e_contexts[0]
        self.assertEqual(ctx[0x08], 1)
        self.assertEqual(ctx[0x10], 0)
        self.assertEqual(ctx[0x18], 0)
        self.assertEqual(ctx[0x20], 1.0)
        self.assertEqual(CONTEXT_INIT[0x08], 0x400000000)
        self.assertEqual(CONTEXT_INIT[0x50], 0x100)
        self.assertEqual(CONTEXT_INIT[0x60], 0x00FFFFFFFFFFFFFF)

    def test_teardown_destroys_cv_only_when_flag_byte_set(self):
        db = Db(wal_number=0)
        db.flag_17b0 = True

        class CvHooks(RecordingHooks):
            def phase_b(self, db, context):
                context[0x50] = 1  # a phase sets the teardown flag byte
                super().phase_b(db, context)

        out, hooks = run(db, CvHooks())
        self.assertIn("destroy_cv", hooks.calls)
        out2, hooks2 = run(Db(wal_number=0))
        self.assertNotIn("destroy_cv", hooks2.calls)

    def test_packet_verify_passes(self):
        proc = subprocess.run(
            [sys.executable, str(PACKET / "verify.py")],
            cwd=REPO, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("ALL CHECKS PASSED", proc.stdout)

    def test_sampled_instructions_byte_for_byte(self):
        data = BINARY.read_bytes()
        samples = {
            0x50EBFB0: bytes.fromhex("f30f1efa"),
            0x50EC61E: bytes.fromhex("e83d3f0700"),
            0x50EC2D1: bytes.fromhex("e88adfffff"),
        }
        for addr, raw in samples.items():
            off = addr - 0x1000  # executable segment mapping
            self.assertEqual(data[off:off + len(raw)], raw)

    def test_caller_sites_encode_calls_to_window(self):
        data = BINARY.read_bytes()
        for site in (0x4FD2622, 0x50EE6D1):
            off = site - 0x1000
            self.assertEqual(data[off], 0xE8)
            target = site + 5 + struct.unpack_from("<i", data, off + 1)[0]
            self.assertEqual(target, WINDOW)

    def test_records_carry_semantic_sections_only(self):
        records = json.loads((PACKET / "records.json").read_text())
        for key in ("artifact", "window", "collection", "per_item_loop",
                    "post_loop", "marking_loop", "callers"):
            self.assertIn(key, records)
        # No per-instruction mnemonic list: the packet's JSON must not
        # carry a bare mnemonic/operand instruction table.
        blob = json.dumps(records)
        self.assertNotIn("mnemonic", blob)
        self.assertEqual(records["artifact"]["sha256"], DIGEST)
        self.assertEqual(records["window"]["size_bytes"], 2599)

    def test_corruption_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "packet"
            shutil.copytree(PACKET, copy)
            records = json.loads((copy / "records.json").read_text())
            records["main_path"]["log_call"]["format"] = "tampered"
            (copy / "records.json").write_text(json.dumps(records))
            proc = subprocess.run(
                [sys.executable, str(copy / "verify.py"),
                 "--packet-dir", str(copy)],
                cwd=REPO, capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)
            shutil.rmtree(copy)
            shutil.copytree(PACKET, copy)
            text = (copy / "window.txt").read_text()
            (copy / "window.txt").write_text(
                text.replace("endbr64", "XXXXXXX", 1))
            proc = subprocess.run(
                [sys.executable, str(copy / "verify.py"),
                 "--packet-dir", str(copy)],
                cwd=REPO, capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
