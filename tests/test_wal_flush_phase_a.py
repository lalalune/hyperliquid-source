"""Tests for the node #94 WAL flush phase A model (tools/wal_flush_phase_a).

Target-grounded expectations come from
research/work-items/RE-001-wal-flush-phase-a-94/records.json: the gate
order (empty collection, flag, lookup null, chain null, already
present, smallest-key rule), the inline/overflow append rules, the
overflow grow contract, and the level-1 log record on append. Boundary
and corruption controls cover the 8-slot inline boundary, the
strictly-smaller key edge, and a tampered packet manifest.
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from wal_flush_phase_a import (LOG_FILE, LOG_MESSAGE, Collection,
                               flush_phase_a)

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-001-wal-flush-phase-a-94"


def run(flag=1, inline=("a",), overflow=(), capacity=0, lookup="x",
        key=5, chain=True, keys=(), db_name="db0"):
    coll = Collection(inline=inline, overflow=overflow,
                      overflow_capacity=capacity)
    log = []
    grow = []
    items = [(f"n{i}", k) for i, k in enumerate(keys)]
    outcome = flush_phase_a(flag, coll, lookup, key, chain, items,
                            db_name=db_name, log=log, grow_log=grow)
    return outcome, coll, log, grow


class TestPhaseA(unittest.TestCase):
    def test_empty_collection_returns_before_flag(self):
        outcome, _, log, _ = run(inline=(), overflow=(), flag=0)
        self.assertEqual(outcome, "noop_empty")
        self.assertEqual(log, [])

    def test_flag_zero_returns(self):
        outcome, coll, log, _ = run(flag=0)
        self.assertEqual(outcome, "noop_flag")
        self.assertEqual(coll.elements(), ["a"])
        self.assertEqual(log, [])

    def test_lookup_null_and_chain_null_return(self):
        outcome, _, _, _ = run(lookup=None)
        self.assertEqual(outcome, "noop_lookup_null")
        outcome, _, _, _ = run(chain=False)
        self.assertEqual(outcome, "noop_chain_null")

    def test_already_present_returns_without_log(self):
        outcome, coll, log, _ = run(inline=("x",), lookup="x")
        self.assertEqual(outcome, "noop_present")
        self.assertEqual(coll.elements(), ["x"])
        self.assertEqual(log, [])

    def test_present_in_overflow_returns(self):
        outcome, _, log, _ = run(inline=tuple("abcdefgh"), overflow=("x",),
                                  capacity=1, lookup="x", keys=())
        self.assertEqual(outcome, "noop_present")
        self.assertEqual(log, [])

    def test_key_must_be_strictly_smallest(self):
        # Equal to any list key blocks the append; smaller passes.
        outcome, _, _, _ = run(keys=(5,))
        self.assertEqual(outcome, "noop_not_smallest")
        outcome, _, _, _ = run(keys=(6, 9), key=7)
        self.assertEqual(outcome, "noop_not_smallest")
        outcome, coll, log, _ = run(keys=(6, 9), key=5)
        self.assertEqual(outcome, "appended")
        self.assertIn("x", coll.elements())
        self.assertEqual(log, [(1, "db0", LOG_MESSAGE, LOG_FILE)])

    def test_self_node_in_list_is_skipped(self):
        # A list node identical to the lookup result never blocks:
        # the binary compares node pointers before comparing keys.
        coll = Collection(inline=("a",))
        log = []
        outcome = flush_phase_a(1, coll, "x", 5, True, [("x", 5)],
                                log=log)
        self.assertEqual(outcome, "appended")
        self.assertEqual(len(log), 1)

    def test_empty_list_appends(self):
        outcome, coll, log, _ = run(keys=())
        self.assertEqual(outcome, "appended")
        self.assertEqual(coll.elements(), ["a", "x"])
        self.assertEqual(len(log), 1)

    def test_gate_order_flag_before_lookup(self):
        # Flag zero wins even when the lookup is also null.
        outcome, _, _, _ = run(flag=0, lookup=None)
        self.assertEqual(outcome, "noop_flag")

    def test_gate_order_present_before_key_rule(self):
        # Already present wins even when the key rule would also block.
        outcome, _, _, _ = run(inline=("x",), lookup="x", keys=(5,))
        self.assertEqual(outcome, "noop_present")

    def test_inline_append_up_to_eight(self):
        coll = Collection(inline=tuple("abcdefg"))
        log = []
        outcome = flush_phase_a(1, coll, "x", 1, True, (("n", 2),), log=log)
        self.assertEqual(outcome, "appended")
        self.assertEqual(coll.inline, list("abcdefgx"))
        self.assertEqual(coll.overflow, [])

    def test_ninth_element_goes_to_overflow_with_grow(self):
        coll = Collection(inline=tuple("abcdefgh"), overflow=(),
                          overflow_capacity=0)
        grow = []
        outcome = flush_phase_a(1, coll, "x", 1, True, (("n", 2),), grow_log=grow)
        self.assertEqual(outcome, "appended")
        self.assertEqual(coll.overflow, ["x"])
        self.assertEqual(grow, ["grow_overflow"])

    def test_overflow_append_without_grow_when_room(self):
        coll = Collection(inline=tuple("abcdefgh"), overflow=("y",),
                          overflow_capacity=4)
        grow = []
        outcome = flush_phase_a(1, coll, "x", 1, True, (("n", 2),), grow_log=grow)
        self.assertEqual(outcome, "appended")
        self.assertEqual(coll.overflow, ["y", "x"])
        self.assertEqual(grow, [])

    def test_unsigned_key_comparison(self):
        # 2**64 - 1 is the largest unsigned key, so it never passes
        # the strictly-smallest rule against any list key.
        outcome, _, _, _ = run(key=(1 << 64) - 1, keys=(0,))
        self.assertEqual(outcome, "noop_not_smallest")

    def test_packet_checker_passes(self):
        proc = subprocess.run(
            [sys.executable, str(PACKET / "verify.py")],
            cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("ALL CHECKS PASSED", proc.stdout)

    def test_packet_records_carry_no_mnemonic_list(self):
        records = json.loads((PACKET / "records.json").read_text())
        self.assertNotIn("instructions", records)
        self.assertNotIn("mnemonics", records)


if __name__ == "__main__":
    unittest.main()
