import hashlib
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import decimal_scaled_u64 as cpu  # noqa: E402
import order_host_checks_115 as tool  # noqa: E402

_IMAGE = None


def image():
    global _IMAGE
    if _IMAGE is None:
        _IMAGE = cpu.Image(bytearray(tool.TARGET.read_bytes()))
    return _IMAGE


class ByteFacts(unittest.TestCase):
    def test_binary_digest(self):
        self.assertEqual(hashlib.sha256(tool.TARGET.read_bytes()).hexdigest(), tool.SHA256)

    def test_bodies_are_fde_starts(self):
        for name, start in tool.BODIES:
            lo, hi = tool.body_extent(image(), start)
            self.assertEqual(lo, start, name)
            self.assertGreater(hi - lo, 100, name)

    def test_mid_function_start_is_refused(self):
        for name, start in tool.BODIES:
            with self.assertRaises(tool.ToolError, msg=name):
                tool.body_extent(image(), start + 1)

    def test_host_slots_resolve_to_the_check_bodies(self):
        for name, slot in tool.SLOT_OF.items():
            self.assertEqual(image().slots[slot], tool.START[name], name)

    def test_check_d_panic_messages_differ(self):
        self.assertNotEqual(tool.lea_target_at(image(), 0x3c4b25a), tool.lea_target_at(image(), 0x3c4b267))
        with self.assertRaises(tool.ToolError):
            tool.lea_target_at(image(), 0x3c4b1a0)


class Models(unittest.TestCase):
    def test_siphash_model_matches_bytes_on_fixed_inputs(self):
        for k0, k1, word in ((1, 2, 3), (0, 0, 0), (tool.U64, tool.U64, tool.U64), (0x0123456789abcdef, 0xfedcba9876543210, 77)):
            case = tool.Box(k0=k0, k1=k1, word=word)
            self.assertTrue(tool.sip_eval(image(), case)[0], (k0, k1, word))

    def test_siphash_model_rejects_a_wrong_key(self):
        case = tool.Box(k0=5, k1=9, word=1234)
        self.assertFalse(tool.sip_eval(image(), case, "key1")[0])

    def test_check_d_edges(self):
        def run(lo, hi, amount):
            case = tool.Box(recs=[(lo, hi)], idx=0, amount=amount)
            return tool.check_d_eval(image(), case)

        for lo, hi, amount in ((3, 3, 5), (0, 1, tool.U64 // 10), (0, 1, tool.U64 // 10 + 1), (0, 16, 1), (0, 19, 1), (0, 19, 2),
                               (0, 20, 1), (5, 4, 1), (0, 32, 1), (0, 255, 0)):
            ok, label, _, _ = run(lo, hi, amount)
            self.assertTrue(ok, (lo, hi, amount, label))
        self.assertEqual(run(0, 19, 2)[1], "d=16+ -> overflow")
        self.assertEqual(run(0, 20, 1)[1], "panic-scale-range")
        self.assertEqual(run(5, 4, 1)[1], "panic-scale-borrow")
        case = tool.Box(recs=[(0, 1)], idx=1, amount=1)
        self.assertEqual(tool.check_d_eval(image(), case)[1], "panic-index")

    def test_hashbrown_model_places_every_entry_where_the_probe_finds_it(self):
        rng = tool.Lcg(11)
        for body in ("probe_a24", "probe_b160", "probe_c120"):
            for case in tool.cases(body, 120):
                ok, label, _, _ = tool.EVAL[body](image(), case)
                self.assertTrue(ok, (body, label))

    def test_ring_twins_agree_on_the_same_case(self):
        for case in tool.cases("ring_search_16", 150):
            self.assertTrue(tool.EVAL["ring_search_16"](image(), case)[0])
            self.assertTrue(tool.EVAL["ring_search_16_twin"](image(), case)[0])

    def test_every_body_matches_its_rule(self):
        for name, _ in tool.BODIES:
            for case in tool.cases(name, 80):
                ok, label, _, _ = tool.EVAL[name](image(), case)
                self.assertTrue(ok, (name, label))


class ModelInvariants(unittest.TestCase):
    def test_rotate_left_flags_and_widths(self):
        m = tool.new_machine(image(), {})
        self.assertEqual(m.shift(0, 0x8000000000000001, 1, 64), 3)
        self.assertEqual(m.flags[0], True)
        self.assertEqual(m.shift(0, 0x80000001, 4, 32), 0x18)
        self.assertEqual(m.shift(0, 0x1234, 0, 64), 0x1234)
        self.assertEqual(m.shift(0, 1, 64 + 8, 64), 0x100)

    def test_hashbrown_control_bytes_mirror_and_hold_each_index_once(self):
        rng = tool.Lcg(3)
        for _ in range(200):
            n = rng.pick((1, 3, 6, 14, 30))
            hashes = [(rng.next() | rng.next() << 40) & tool.U64 for _ in range(n)]
            table = tool.build_table(rng, hashes, rng.pick((0, 2)))
            full = [i for i in range(table.buckets) if not table.ctrl[i] & 0x80]
            self.assertEqual(sorted(table.slot[i] for i in full), list(range(n)))
            if table.buckets >= 16:
                self.assertEqual(table.ctrl[table.buckets:], table.ctrl[:16])
            for i in full:
                self.assertEqual(table.ctrl[i], hashes[table.slot[i]] >> 57)
            self.assertIn(tool.EMPTY, table.ctrl[:table.buckets])

    def test_single_entry_maps_skip_the_hash(self):
        seen = {"check_b": 0, "check_c": 0}
        for name in seen:
            for case in tool.cases(name, 600):
                if len(case.a.keys) == 1:
                    seen[name] += 1
                    self.assertTrue(tool.EVAL[name](image(), case)[0])
        self.assertGreater(seen["check_b"], 10)
        self.assertGreater(seen["check_c"], 10)

    def test_check_a_zero_state_differs_from_absent(self):
        box = tool.Box(kind="ring", keys=[5, 9], cap=2, head=1)
        for key, want in ((5, 0), (9, 0), (7, 1)):
            case = tool.Box(box=box, vals={5: 0, 9: 0}, regs=[key], idx=0, junk=1)
            ok, label, _, m = tool.check_a_eval(image(), case)
            self.assertTrue(ok, label)
            self.assertEqual(m.get(tool.RAX, 8), want)

    def test_ring_wrap_and_tree_heights_are_exercised(self):
        labels = set()
        for case in tool.cases("map_get", 400):
            labels.add(tool.map_get_eval(image(), case)[1])
        self.assertTrue({"tree-h1 -> hit", "tree-h2 -> hit", "ring -> hit", "ring -> miss"} <= labels, labels)
        wraps = [c for c in tool.cases("ring_search_16", 200) if c.box.head + len(c.box.keys) > c.box.cap]
        self.assertGreater(len(wraps), 20)


def mk_map(keys, vals=None, sip=(11, 22)):
    mp = tool.Box(keys=list(keys), sip=sip, vals=vals or {})
    mp.table = tool.build_table(tool.Lcg(9), [tool.sip13(sip[0], sip[1], k) for k in keys], 0)
    return mp


class HandWritten(unittest.TestCase):
    """Small scenarios written out by hand, one per documented result of the bodies."""

    def check_b(self, key, a, b, tree=()):
        plan = ("leaf", sorted(tree)) if tree else None
        case = tool.Box(a=a, b=b, tree_keys=sorted(tree), plan=plan, height=0, key=key, junk=0, panic=None)
        ok, label, _, m = tool.check_b_eval(image(), case)
        self.assertTrue(ok, label)
        return m.get(tool.RAX, 8)

    def test_check_b_results_0_1_2(self):
        a = mk_map([5, 6, 7], {5: 100, 6: 200, 7: 100})
        b = mk_map([100, 300], {100: 0, 300: 0}, sip=(33, 44))
        self.assertEqual(self.check_b(9, a, b), 0)                # not in A
        self.assertEqual(self.check_b(6, a, b), 1)                # A value 200 missing from B
        self.assertEqual(self.check_b(5, a, b), 2)                # A value 100 present in B
        self.assertEqual(self.check_b(9, a, b, tree=[9, 12]), 1)  # the B-tree set short-circuits everything
        self.assertEqual(self.check_b(5, a, mk_map([])), 1)       # empty B: hit in A is enough
        self.assertEqual(self.check_b(5, mk_map([]), b), 0)       # empty A

    def check_c(self, key, a, b, c):
        case = tool.Box(a=a, b=b, c=c, key=key, panic=None)
        ok, label, _, m = tool.check_c_eval(image(), case)
        self.assertTrue(ok, label)
        return m.get(tool.RAX, 8)

    def test_check_c_compares_the_c_field_with_the_first_value(self):
        a = mk_map([1, 2], {1: 10, 2: 20})
        b = mk_map([10, 20], {10: 7, 20: 8}, sip=(5, 6))
        c = mk_map([7, 8], {7: 10, 8: 99}, sip=(7, 8))
        self.assertEqual(self.check_c(1, a, b, c), 1)            # C[7].f30 == 10
        self.assertEqual(self.check_c(2, a, b, c), 0)            # C[8].f30 == 99 != 20
        self.assertEqual(self.check_c(3, a, b, c), 0)            # A miss
        self.assertEqual(self.check_c(1, a, b, mk_map([])), 0)   # empty C

    def test_probe_distinguishes_equal_hashes_by_key(self):
        keys = [100, 200, 300]
        hashes = [0x2a << 57] * 3                                 # one h2, one start position
        case = tool.Box(keys=keys, hashes=hashes, table=tool.build_table(tool.Lcg(1), hashes, 0), key=300,
                        hash=hashes[0], kind="hit", bad=None)
        ok, label, _, m = tool.EVAL["probe_a24"](image(), case)
        self.assertTrue(ok, label)
        self.assertEqual((m.get(tool.RAX, 8), m.get(tool.RDX, 64)), (1, 2))
        case.key, case.kind = 400, "miss"
        ok, label, _, m = tool.EVAL["probe_a24"](image(), case)
        self.assertTrue(ok, label)
        self.assertEqual(m.get(tool.RAX, 8), 0)

    def test_sip_model_known_relation(self):
        self.assertNotEqual(tool.sip13(1, 2, 3), tool.sip13(1, 2, 4))
        self.assertNotEqual(tool.sip13(1, 2, 3), tool.sip13(2, 1, 3))
        self.assertEqual(tool.sip13(0, 0, 0), tool.sip13(0, 0, 0))


class NegativeControls(unittest.TestCase):
    def test_spec_flaws_are_detected(self):
        for name, flaws in tool.FLAWS.items():
            for flaw in flaws:
                hit = any(not tool.attempt(image(), name, case, flaw) for case in tool.cases(name, 400))
                self.assertTrue(hit, (name, flaw))

    def test_branch_flip_in_check_d_is_detected(self):
        img = cpu.Image(bytearray(tool.TARGET.read_bytes()))
        sites = tool.mutation_sites(img, "check_d")
        self.assertGreater(len(sites), 10)
        battery = list(tool.cases("check_d", 160))
        caught = 0
        for va, kind, new in sites[:6]:
            old = tool.patch(img, va, bytes([new]))
            try:
                caught += any(not tool.attempt(img, "check_d", case) for case in battery)
            finally:
                tool.patch(img, va, old)
        self.assertGreaterEqual(caught, 5)

    def test_corrupt_slot_index_is_a_panic_not_a_hit(self):
        found = 0
        for case in tool.cases("check_b", 400):
            if case.panic:
                found += 1
                self.assertTrue(tool.check_b_eval(image(), case)[0])
                case.panic = (case.panic[0] + 1, case.panic[1])
                self.assertFalse(tool.check_b_eval(image(), case)[0])
        self.assertGreater(found, 5)

    def test_unpopulated_state_is_refused(self):
        for body in ("check_a", "check_d"):
            m = tool.new_machine(image(), {})
            m.set_reg(tool.RDI, tool.CTX)
            m.set_reg(tool.RSI, 0)
            m.set_reg(tool.RDX, 1)
            with self.assertRaises((tool.ToolError, cpu.ToolError, KeyError, cpu.Done)):
                tool.run(m, tool.START[body])

    def test_digest_of_a_flipped_binary_differs(self):
        blob = bytearray(tool.TARGET.read_bytes())
        blob[image().file_offset(tool.START["check_d"])] ^= 1
        self.assertNotEqual(tool.digest(blob), tool.SHA256)


class Generation(unittest.TestCase):
    def test_generation_is_deterministic_and_clean(self):
        tool.DIV = 40
        try:
            with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
                m1 = tool.generate(pathlib.Path(one))
                m2 = tool.generate(pathlib.Path(two))
                self.assertEqual(m1, m2)
                self.assertEqual(m1["mismatches"], 0)
                self.assertEqual(m1["negative_controls"], m1["negative_detected"])
                for path in sorted(pathlib.Path(one).iterdir()):
                    self.assertEqual(path.read_bytes(), (pathlib.Path(two) / path.name).read_bytes(), path.name)
        finally:
            tool.DIV = 1


if __name__ == "__main__":
    unittest.main()
