"""Tests for tools/zstd_stream_destructors115.py (RE-002, node #115).

2,400 deterministic cases (600 compress-live, 600 uncompress-live,
600 null-ctx, 600 ordering/size) plus targeted boundary controls. The
model is checked against INDEPENDENT expectations derived from the
binary, not against itself:

  * D1: vptr stored first (0x64d7418 compress / 0x64d7448 uncompress),
    then the engine free on the ctx slot; the holder stays live and
    the ctx slot still holds the (freed) handle -- the binary never
    nulls it.
  * D0: same two events, then sized operator delete (0x70 / 0x38);
    the holder memory is freed and any later access raises.
  * D0 does not call D1: a D0 trace has no d1 event (the steps are
    inlined).
  * Double destroy: D1-then-D1 double-frees the ctx (detected by the
    registry, never executed twice); D0-then-D1 touches freed memory.
  * Null ctx: free(NULL) is a no-op in both engine frees (verified in
    the binary: test rdi,rdi; je -> xor eax,eax; ret), so a null-ctx
    destroy succeeds with no free event beyond the null-noop record.
  * Ledger: the committed cases.tsv matches a fresh regeneration.

The engine free is the system libzstd.so.1 via ctypes on a REAL
context handle (see the tool docstring). No frame bytes are asserted:
destruction has none. Event order, vptr values, delete sizes and the
freed-state transitions are asserted: those are the destructor's
contract.
"""

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import zstd_stream_destructors115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-zstd-stream-destructors-115")


class D1Tests(unittest.TestCase):
    def test_d1_frees_ctx_and_keeps_holder(self):
        for case in m.generate_cases():
            if case["sequence"] != ["d1"] or case["ctx"] != "live":
                continue
            holder, registry = m.make_holder(case["family"])
            ctx = holder.read_ctx_slot()
            self.assertNotEqual(ctx, 0, case["id"])
            events = m.destroy_d1(holder)
            self.assertEqual(events[0],
                             ("store_vptr", hex(holder.vptr)), case["id"])
            self.assertEqual(events[1], ("free_ctx", hex(ctx)), case["id"])
            self.assertEqual(len(events), 2, case["id"])
            # Holder memory stays live after D1 ...
            self.assertEqual(holder.read_vptr(), holder.vptr, case["id"])
            # ... but the ctx slot still holds the FREED handle: the
            # binary never nulls it (a second D1 would double-free).
            self.assertEqual(holder.read_ctx_slot(), ctx, case["id"])
            self.assertEqual(registry.live_count(), 0, case["id"])

    def test_d1_vptr_values(self):
        holder, _ = m.make_holder("compress")
        self.assertEqual(holder.vptr, 0x64D7418)
        m.destroy_d1(holder)
        holder2, _ = m.make_holder("uncompress")
        self.assertEqual(holder2.vptr, 0x64D7448)
        m.destroy_d1(holder2)


class D0Tests(unittest.TestCase):
    def test_d0_frees_ctx_and_holder(self):
        for case in m.generate_cases():
            if case["sequence"] != ["d0"] or case["ctx"] != "live":
                continue
            holder, registry = m.make_holder(case["family"])
            ctx = holder.read_ctx_slot()
            size = holder.size
            events = m.destroy_d0(holder)
            self.assertEqual(events[0],
                             ("store_vptr", hex(holder.vptr)), case["id"])
            self.assertEqual(events[1], ("free_ctx", hex(ctx)), case["id"])
            self.assertEqual(events[2], ("operator_delete", size),
                             case["id"])
            self.assertEqual(len(events), 3, case["id"])
            self.assertEqual(registry.live_count(), 0, case["id"])
            # Holder memory is freed: any access raises.
            with self.assertRaises(m.UseAfterFree, msg=case["id"]):
                holder.read_vptr()
            with self.assertRaises(m.UseAfterFree, msg=case["id"]):
                holder.read_ctx_slot()

    def test_d0_delete_sizes(self):
        # The operator-delete size is the independent pin of the holder
        # size: 0x70 for compress, 0x38 for uncompress.
        holder, _ = m.make_holder("compress")
        events = m.destroy_d0(holder)
        self.assertEqual(events[2], ("operator_delete", 0x70))
        holder2, _ = m.make_holder("uncompress")
        events2 = m.destroy_d0(holder2)
        self.assertEqual(events2[2], ("operator_delete", 0x38))

    def test_d0_does_not_call_d1(self):
        # D0 inlines the D1 steps: a D0 trace carries no d1 event and
        # the vptr store still precedes the free.
        for family in ("compress", "uncompress"):
            holder, _ = m.make_holder(family)
            events = m.destroy_d0(holder)
            kinds = [e[0] for e in events]
            self.assertEqual(kinds, ["store_vptr", "free_ctx",
                                     "operator_delete"], family)
            self.assertLess(kinds.index("store_vptr"),
                            kinds.index("free_ctx"), family)


class DoubleDestroyTests(unittest.TestCase):
    def test_d1_then_d1_double_frees(self):
        for case in m.generate_cases():
            if case["sequence"] != ["d1", "d1"]:
                continue
            holder, registry = m.make_holder(case["family"])
            m.destroy_d1(holder)
            with self.assertRaises(m.DoubleFree, msg=case["id"]):
                m.destroy_d1(holder)
            self.assertEqual(registry.live_count(), 0, case["id"])

    def test_d0_then_d1_use_after_free(self):
        for case in m.generate_cases():
            if case["sequence"] != ["d0", "d1"]:
                continue
            holder, registry = m.make_holder(case["family"])
            m.destroy_d0(holder)
            with self.assertRaises(m.UseAfterFree, msg=case["id"]):
                m.destroy_d1(holder)
            self.assertEqual(registry.live_count(), 0, case["id"])


class NullCtxTests(unittest.TestCase):
    def test_null_ctx_destroy_is_noop_free(self):
        for case in m.generate_cases():
            if case["ctx"] != "null":
                continue
            holder, registry = m.make_holder(case["family"], ctx_live=False)
            self.assertEqual(holder.read_ctx_slot(), 0, case["id"])
            if case["sequence"] == ["d1"]:
                events = m.destroy_d1(holder)
                self.assertEqual(events, [
                    ("store_vptr", hex(holder.vptr)),
                    ("free_ctx", "null-noop")], case["id"])
                self.assertEqual(holder.read_vptr(), holder.vptr,
                                 case["id"])
            else:
                events = m.destroy_d0(holder)
                self.assertEqual(events, [
                    ("store_vptr", hex(holder.vptr)),
                    ("free_ctx", "null-noop"),
                    ("operator_delete", holder.size)], case["id"])
                with self.assertRaises(m.UseAfterFree, msg=case["id"]):
                    holder.read_vptr()
            self.assertEqual(registry.live_count(), 0, case["id"])


class OrderingTests(unittest.TestCase):
    def test_event_order_and_vptr(self):
        for case in m.generate_cases():
            if case["group"] != "ordering":
                continue
            events, outcome = m.replay_case(case)
            self.assertEqual(outcome, m.expected_outcome(case), case["id"])
            # vptr store is always the first event; the free is second;
            # operator delete (D0 only) is last.
            self.assertEqual(events[0][0], "store_vptr", case["id"])
            self.assertEqual(events[1][0], "free_ctx", case["id"])
            if case["sequence"] == ["d0"]:
                self.assertEqual(events[2][0], "operator_delete",
                                 case["id"])
                self.assertEqual(len(events), 3, case["id"])
            else:
                self.assertEqual(len(events), 2, case["id"])


class ReplayTests(unittest.TestCase):
    def test_all_cases_replay_to_expected_outcome(self):
        for case in m.generate_cases():
            _events, outcome = m.replay_case(case)
            self.assertEqual(outcome, m.expected_outcome(case), case["id"])

    def test_case_count_and_split(self):
        cases = m.generate_cases()
        self.assertEqual(len(cases), 2400)
        groups = {}
        for c in cases:
            groups[c["group"]] = groups.get(c["group"], 0) + 1
        self.assertEqual(groups, {"live": 1200, "null-ctx": 600,
                                  "ordering": 600})


class LedgerTests(unittest.TestCase):
    def test_cases_tsv_matches_regeneration(self):
        rows = m.cases_tsv_rows()
        text = (PACKET / "cases.tsv").read_text().splitlines()
        self.assertEqual(text[0], "id\tfamily\tctx\tsequence\t"
                         "expected_outcome\tdelete_size\tvptr\tgroup")
        self.assertEqual(len(text) - 1, 2400)
        regen = ["\t".join(str(x) for x in r) for r in rows]
        self.assertEqual(text[1:], regen)

    def test_artifact_digest(self):
        data = (m.ROOT / "artifacts" / "node" / "115" / "hl-node").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         m.ARTIFACT_SHA256)


if __name__ == "__main__":
    unittest.main()
