"""Tests for tools/vault_move_115.py (node #115 vault move core 0x44ae810 and four real helper bodies).

The binary must be present; nothing here is skipped. The tool never executes the binary.
"""
import hashlib
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import vault_move_115 as t  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "vaults-move-core-115"


class Shared:
    image = None
    lay = None
    helpers = None

    @classmethod
    def load(cls):
        if cls.image is None:
            data = t.BINARY.read_bytes()
            assert hashlib.sha256(data).hexdigest() == t.SHA256
            cls.image = t.Image(data)
            cls.lay = t.Layout(cls.image)
            cls.helpers = t.helper_cases(cls.lay)
        return cls


def owner_cases(lay, n, step=1):
    return [t.gen_case(k, lay) for k in range(0, n * step, step)]


class TestLayout(unittest.TestCase):
    def test_constants_from_bytes(self):
        s = Shared.load()
        k = s.lay.k
        self.assertEqual(k["scale"], 1e6)
        self.assertEqual(k["share"], 0.05)
        self.assertEqual(k["floor"], 1e-7)
        self.assertEqual(k["hi"], 2.0 ** 63)
        self.assertEqual(k["lo"], -(2.0 ** 63))
        self.assertLess(k["tiny_neg"], 0)
        self.assertGreater(k["min_den"], 0)

    def test_address_sets(self):
        s = Shared.load()
        self.assertEqual(len(s.lay.prot_a), 8)
        self.assertEqual(len(s.lay.prot_b), 8)
        for a in s.lay.prot_a + s.lay.prot_b:
            self.assertEqual(len(a), 20)
        self.assertEqual(len(set(s.lay.prot_a) | set(s.lay.prot_b)), 16)

    def test_call_sites_resolve_to_relocated_targets(self):
        s = Shared.load()
        self.assertEqual(s.lay.targets["avail"], 0x446bdd0)
        self.assertEqual(s.lay.targets["debit"], 0x447db40)
        self.assertEqual(s.lay.targets["cond_a"], 0x421a3c0)
        self.assertEqual(s.lay.targets["cond_b"], 0x421a520)
        self.assertEqual(s.lay.targets["ratio"], 0x14ca350)
        self.assertEqual(len(s.lay.ovf), 6)
        self.assertEqual(len(set(s.lay.ovf.values())), 5)  # vault-sum and balance-add share one location

    def test_callee_table_has_no_unclassified_call(self):
        s = Shared.load()
        rows = t.callee_rows(s.image, s.lay)
        self.assertGreaterEqual(len(rows), 20)
        self.assertEqual([r for r in rows if r[3] == "?"], [])


class TestOwner(unittest.TestCase):
    def test_cases_match_model(self):
        s = Shared.load()
        r = t.evaluate(s.image, s.lay, owner_cases(s.lay, 150, 37))
        self.assertEqual((r["n"], r["bad"]), (150, 0))

    def test_every_outcome_class_is_generated(self):
        s = Shared.load()
        seen = set()
        for c in owner_cases(s.lay, 400, 13):
            seen.add(t.outcome(t.model(c, s.lay)))
        for want in ("ok", "reject-0x16", "reject-0x17", "reject-0x9", "reject-0x2", "reject-0x2d"):
            self.assertIn(want, seen)
        self.assertTrue(any(x.startswith("panic:") for x in seen))

    def test_success_record_layout(self):
        s = Shared.load()
        for c in owner_cases(s.lay, 600, 5):
            want = t.model(c, s.lay)
            if t.outcome(want) == "ok":
                o = want["out"]
                self.assertEqual(t.u(o, 0, 8), 0x8000000000000004)
                self.assertEqual(o[0x10:0x24], c["addr"])
                self.assertEqual(t.bdouble(t.u(o, 8, 8)), c["amount"] / 1e6)
                (k, rec), = want["recs"].items()
                self.assertEqual(k, c["key"])
                self.assertEqual(rec[0x24:0x30], c["aux"])
                return
        self.fail("no successful move among the sampled cases")

    def test_every_model_mutant_is_visible(self):
        s = Shared.load()
        cases = owner_cases(s.lay, 2500, 4) + [t.gen_case(k, s.lay) for k in range(7, 2000, 200)]
        shared = t.machine(s.image)
        for mut in t.OWNER_MUTANTS:
            if mut.startswith("ratio-") or "model:" + mut in t.EQUIV:
                continue
            r = t.evaluate(s.image, s.lay, cases, mut=frozenset([mut]), stop_on_first=True, machine_=shared)
            self.assertGreater(r["bad"], 0, mut)

    def test_immediate_flip_is_detected(self):
        s = Shared.load()
        # `cmp r15, 1` at 0x44ae82d: first gate compares the mode word with exactly 1
        old = s.image.read(0x44ae82d + 3, 1)[0]
        r = t.evaluate(s.image, s.lay, owner_cases(s.lay, 300, 7), override={0x44ae82d + 3: old ^ 1}, stop_on_first=True)
        self.assertGreater(r["bad"], 0)

    def test_branch_inversion_is_detected(self):
        s = Shared.load()
        va = 0x44aec12  # jae 0x44aed88: available >= amount
        old = s.image.read(va + 1, 1)[0]
        r = t.evaluate(s.image, s.lay, owner_cases(s.lay, 600, 3), override={va + 1: old ^ 1}, stop_on_first=True)
        self.assertGreater(r["bad"], 0)

    def test_world_corruption_is_detected(self):
        s = Shared.load()
        m = t.machine(s.image)
        hit = 0
        for c in owner_cases(s.lay, 200, 11):
            got, regions, where = t.run_case(m, s.lay, dict(c, leader=t.flip_byte(c["leader"], 19)))
            if t.compare(c, s.lay, t.model(c, s.lay), got, regions, where):
                hit += 1
        self.assertGreater(hit, 0)

    def test_negative_amount_panics_after_avail_call(self):
        s = Shared.load()
        c = next(c for c in owner_cases(s.lay, 3000) if c["amount"] < 0 and t.outcome(t.model(c, s.lay)).startswith("panic:0x"))
        want = t.model(c, s.lay)
        self.assertEqual(want["calls"][-1][0], "avail")
        self.assertEqual(want["panic"], "panic:" + ":".join(
            hex(x) for x in (s.lay.panic["negative-amount"], s.lay.fmt[0], s.lay.fmt[1], s.lay.fmt[2])))
        self.assertEqual(s.lay.fmt[0], 0x2b)

    def test_out_of_range_input_is_rejected_by_evaluator(self):
        s = Shared.load()
        m = t.machine(s.image)
        c = owner_cases(s.lay, 1)[0]
        c["children"] = []
        m.reset()
        with self.assertRaises(t.ToolError):
            m.load(0x7000_0000_0000, 8)

    def test_wrong_digest_is_refused(self):
        data = bytearray(t.BINARY.read_bytes()[:8192])
        data[77] ^= 1
        with self.assertRaises(t.ToolError):
            t.Image(bytes(data))


class TestHelpers(unittest.TestCase):
    def test_helpers_match_model(self):
        s = Shared.load()
        sample = s.helpers[::17]
        r = t.eval_helpers(s.image, s.lay, sample)
        self.assertEqual(r["bad"], 0)
        self.assertGreater(r["n"], 400)

    def test_helper_mutants_visible(self):
        s = Shared.load()
        for mut in t.HELPER_MUTANTS:
            r = t.eval_helpers(s.image, s.lay, s.helpers, mut=frozenset([mut]), stop_on_first=True)
            self.assertGreater(r["bad"], 0, mut)

    def test_ratio_tiny_negative_is_clamped(self):
        s = Shared.load()
        k = s.lay.k
        ok, q = t.ratio_model(s.lay, k["tiny_neg"] / 2, 1.0)
        self.assertTrue(ok)
        self.assertEqual(q, 0.0)
        ok, _ = t.ratio_model(s.lay, k["tiny_neg"] * 2, 1.0)
        self.assertFalse(ok)

    def test_ring_search_reports_insertion_point(self):
        s = Shared.load()
        keys = [bytes([i]) * 20 for i in (2, 4, 6, 8)]
        m = t.machine(s.image)
        for probe, want in ((bytes([5]) * 20, (1, 2)), (bytes([4]) * 20, (0, 1)), (bytes([9]) * 20, (1, 4)),
                            (bytes([1]) * 20, (1, 0))):
            for head in range(5):
                c = {"helper": "ring_find", "keys": keys, "cap": 5, "head": head, "probe": probe}
                got = t.run_helper(m, s.lay, c)
                self.assertEqual((got["rax"], got["rdx"]), want)
                self.assertTrue(got["regs_ok"])

    def test_address_predicate_requires_all_twenty_bytes(self):
        s = Shared.load()
        m = t.machine(s.image)
        a = s.lay.prot_a[0]
        for i in range(20):
            b = bytearray(a)
            b[i] ^= 0x80
            self.assertEqual(t.run_helper(m, s.lay, {"helper": "cond_a", "addr": bytes(b)})["rax"], 0)
        self.assertEqual(t.run_helper(m, s.lay, {"helper": "cond_a", "addr": a})["rax"], 1)
        self.assertEqual(t.run_helper(m, s.lay, {"helper": "cond_b", "addr": a})["rax"], 0)


class TestRules(unittest.TestCase):
    """One test per rule of the reconstruction, each on a hand-built case that isolates it."""

    @staticmethod
    def base(lay, **kw):
        leader = bytes(range(1, 21))
        key = bytes(range(21, 41))
        rec = t.record(0.5, 10, 20, bytes(12))
        c = {"k": -1, "label": "rule", "mode": 2, "leader": leader, "key": key, "pol": 1, "r9": 1, "addr": bytes([9]) * 20,
             "children": [], "set_h": 0, "set_root0": False, "set_count": 0, "vseed": b"seed", "vpos": True, "vscale": 1000,
             "amount": 5, "avail": 5, "bal": 100, "aux": bytes(range(12)), "w1": 1, "w2": 2, "kind": "tree",
             "entries": {leader: rec, key: t.record(0.0, 3, -3, bytes(12))}, "map_h": 0, "ring_cap": 3, "ring_head": 1}
        c.update(kw)
        return c

    def go(self, **kw):
        s = Shared.load()
        c = self.base(s.lay, **kw)
        got, regions, where = t.run_case(t.machine(s.image), s.lay, c)
        want = t.model(c, s.lay)
        self.assertIsNone(t.compare(c, s.lay, want, got, regions, where))
        return c, want

    def test_plain_move_updates_record_and_balance(self):
        c, want = self.go()
        self.assertEqual(t.outcome(want), "ok")
        self.assertEqual(want["bal"], 100)
        rec = want["recs"][c["key"]]
        self.assertEqual((t.u(rec, 8, 8), t.i64(t.u(rec, 0x10, 8))), (3 + 5, -3 + 5))

    def test_first_gate_beats_second(self):
        c, want = self.go(mode=1, pol=0)
        self.assertEqual(t.outcome(want), "reject-0x16")

    def test_second_gate_needs_zero_policy_byte(self):
        _, want = self.go(mode=2, pol=0)
        self.assertEqual(t.outcome(want), "reject-0x17")
        _, want = self.go(mode=2, pol=0xff)
        self.assertEqual(t.outcome(want), "ok")

    def test_leader_may_move_without_gates(self):
        c = self.base(Shared.load().lay)
        _, want = self.go(mode=1, pol=0, key=c["leader"])
        self.assertEqual(t.outcome(want), "ok")

    def test_mode_gate_uses_full_qword_but_later_tests_use_low_dword(self):
        _, want = self.go(mode=0x100000001, pol=1, r9=0)
        self.assertEqual(t.outcome(want), "ok")  # not 1 as a qword -> gate 1 skipped; low dword 1 -> leader check skipped
        _, want = self.go(mode=1, pol=1, r9=0)
        self.assertEqual(t.outcome(want), "reject-0x16")

    def test_negative_vault_value_needs_set_a_address(self):
        s = Shared.load()
        a = s.lay.prot_a[0]
        c = self.base(s.lay, vpos=False, vseed=b"neg")
        c = next(self.base(s.lay, vpos=False, vseed=bytes([i])) for i in range(64)
                 if t.value_of(self.base(s.lay, vpos=False, vseed=bytes([i])), self.base(s.lay)["addr"]) < 0)
        _, want = self.go(vpos=False, vseed=c["vseed"])
        self.assertEqual(t.outcome(want), "reject-0x9")
        _, want = self.go(vpos=False, vseed=c["vseed"], addr=a)
        self.assertNotEqual(t.outcome(want), "reject-0x9")

    def test_leader_share_rejects_small_positions(self):
        leader = self.base(Shared.load().lay)["leader"]
        _, want = self.go(r9=0, entries={leader: t.record(1e-12, 0, 0, bytes(12)),
                                          self.base(Shared.load().lay)["key"]: t.record(0.0, 0, 0, bytes(12))})
        self.assertEqual(t.outcome(want), "reject-0x2")

    def test_missing_leader_record_rejects(self):
        c = self.base(Shared.load().lay)
        _, want = self.go(r9=0, entries={c["key"]: t.record(0.0, 0, 0, bytes(12))})
        self.assertEqual(t.outcome(want), "reject-0x2")

    def test_insufficient_availability_rejects_after_diagnostic(self):
        _, want = self.go(avail=4)
        self.assertEqual(t.outcome(want), "reject-0x2d")
        self.assertEqual(want["calls"][-1], ("log", 0x34))

    def test_balance_saturates_with_reporter_calls(self):
        s = Shared.load()
        c, want = self.go(bal=-(1 << 63) + 2, amount=7, avail=7)
        self.assertEqual(want["bal"], -(1 << 63) + 7)
        self.assertIn(("ovf", s.lay.ovf["balance-sub"]), want["calls"])

    def test_record_sums_saturate(self):
        s = Shared.load()
        key = self.base(s.lay)["key"]
        c, want = self.go(entries={self.base(s.lay)["leader"]: t.record(0.5, 0, 0, bytes(12)),
                                    key: t.record(0.0, t.M64 - 1, (1 << 63) - 2, bytes(12))})
        rec = want["recs"][key]
        self.assertEqual(t.u(rec, 8, 8), t.M64)
        self.assertEqual(t.u(rec, 0x10, 8), (1 << 63) - 1)

    def test_ring_variant_matches_tree_variant(self):
        s = Shared.load()
        _, a = self.go(kind="tree")
        _, b = self.go(kind="ring")
        self.assertEqual((a["out"], a["bal"], a["recs"]), (b["out"], b["bal"], b["recs"]))

    def test_parent_vault_sums_children_in_key_order(self):
        s = Shared.load()
        kids = sorted(bytes([i]) * 20 for i in (7, 3, 5))
        c, want = self.go(children=kids, set_count=3, mode=2)
        order = [x[1] for x in want["calls"] if x[0] == "value"]
        self.assertEqual(order, [c["addr"]] + kids)

    def test_set_nodes_of_every_height_are_walked(self):
        s = Shared.load()
        for n, h in ((1, 0), (11, 0), (12, 1), (60, 1), (30, 2)):
            kids = [bytes([i, 1]) + bytes(18) for i in range(n)]
            self.go(children=kids, set_count=n, set_h=h, mode=2)


class TestEvidence(unittest.TestCase):
    def test_committed_summary_is_consistent(self):
        meas = json.loads((PACKET / "measure.json").read_text())
        self.assertEqual(meas["negative_detected"] + meas["equivalent"], meas["negative_controls"])
        summary = json.loads((PACKET / "summary.json").read_text())
        self.assertEqual(summary["mismatches"], 0)
        self.assertEqual(summary["binary_sha256"], t.SHA256)
        self.assertEqual(summary["owner_cases"] + summary["helper_cases"], meas["cases"])
        rows = (PACKET / "controls.tsv").read_text().splitlines()[1:]
        self.assertEqual(len(rows), meas["negative_controls"])
        self.assertEqual(sum(1 for r in rows if r.split("\t")[1] == "yes"), meas["negative_detected"])

    def test_instruction_table_matches_bytes(self):
        s = Shared.load()
        rows = (PACKET / "instructions.tsv").read_text().splitlines()[1:]
        self.assertGreater(len(rows), 900)
        for r in rows[::7]:
            _, va, ln, raw, _ = r.split("\t")
            self.assertEqual(s.image.read(int(va, 16), int(ln)).hex(), raw)


if __name__ == "__main__":
    unittest.main()
