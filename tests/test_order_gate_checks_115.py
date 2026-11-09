import hashlib
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import order_gate_checks_115 as t  # noqa: E402


def load_image():
    data = bytearray(t.TARGET.read_bytes())
    return t.cpu.Image(data)


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = load_image()

    def sweep_cases(self, body, count=150, flaw=None):
        return [t.EVAL[body](self.image, c, flaw)[0] for c in t.cases(body, count)]


class ByteFacts(Base):
    def test_digest(self):
        self.assertEqual(hashlib.sha256(self.image.data).hexdigest(), t.SHA256)

    def test_function_extents(self):
        for body, start in t.BODIES:
            lo, hi = t.body_extent(self.image, start)
            self.assertEqual(lo, start)
            self.assertEqual(sum(i.size for i in t.sweep(self.image, lo, hi)), hi - lo)

    def test_status_constants_read_from_bytes(self):
        found = {v for _, v in t.movw_status_constants(self.image, "market_check")}
        self.assertTrue({0x62, 0x75, 0x103, 0x1d, 0x195, 0x193, 0x192, 0x6a, 0x6b, 0x1a2} <= found)
        found = {v for _, v in t.movw_status_constants(self.image, "margin_check")}
        self.assertTrue({0xdb, 0xda, 0xd9, 0xad, 0x158, 0x1a2} <= found)

    def test_mid_function_start_is_refused(self):
        for _, start in t.BODIES:
            with self.assertRaises(t.ToolError):
                t.body_extent(self.image, start + 1)

    def test_slots_have_relative_addends(self):
        for slot in (t.SLOT_PANIC, t.SLOT_PANIC2, t.SLOT_PANIC3, t.SLOT_CHECK_A, t.SLOT_CHECK_B, t.SLOT_CHECK_C,
                     t.SLOT_CHECK_D, t.SLOT_PARSE, t.SLOT_SCALE):
            self.assertIn(slot, self.image.slots)
        self.assertNotIn(t.SLOT_MEMCMP, self.image.slots)


class Resolve(Base):
    def case(self, kind, value, idx=0, index=(0,), kinds=None):
        return t.Box(index=list(index), kinds=[kind] if kinds is None else kinds, idx=idx, value=value)

    def run_case(self, c):
        return t.resolve_actual(self.image, c)[:3]

    def test_scale_table(self):
        for kind in range(9):
            mult = 10 ** (8 - kind)
            self.assertEqual(self.run_case(self.case(kind, 7 * mult)), ("ret", 0x1a2, 7))
            self.assertEqual(self.run_case(self.case(kind, 7 * mult + 1)), ("ret", 0x6a, None) if mult > 1 else ("ret", 0x1a2, 7 * mult + 1))

    def test_kind_above_eight_refuses(self):
        for kind in (9, 10, 0x40, 0xff):
            self.assertEqual(self.run_case(self.case(kind, 100)), ("ret", 0x6a, None))

    def test_wide_values_use_the_64_bit_divide(self):
        value = (1 << 30) * 10 ** 8
        self.assertEqual(self.run_case(self.case(0, value))[:2], ("ret", 0x1a2))
        self.assertEqual(self.run_case(self.case(0, value))[2], 1 << 30)
        self.assertEqual(self.run_case(self.case(0, value + 1))[:2], ("ret", 0x6a))

    def test_index_chain_panics(self):
        how, kind, entry = self.run_case(self.case(8, 1, idx=1))
        self.assertEqual((how, kind, entry[2:4]), ("panic", "bounds", (1, 1)))
        how, kind, entry = self.run_case(self.case(8, 1, index=(3,)))
        self.assertEqual((how, kind), ("panic", "record"))

    def test_battery_matches_rule(self):
        self.assertTrue(all(self.sweep_cases("resolve")))

    def test_flaws_are_detected(self):
        for flaw in t.FLAWS["resolve"]:
            self.assertFalse(all(self.sweep_cases("resolve", 300, flaw)), flaw)


class RingSearch(Base):
    def test_battery_matches_rule(self):
        self.assertTrue(all(self.sweep_cases("ring_search_d0")))

    def test_late_flaw_is_detected(self):
        self.assertFalse(all(self.sweep_cases("ring_search_d0", 150, "late")))

    def test_wrapped_ring_found_and_absent(self):
        rng = t.Lcg(77)
        keys = sorted(t.gen_keys(rng, 4))
        box = t.Box(kind="ring", keys=keys, cap=6, head=4)
        found = t.ring_actual(self.image, t.Box(box=box, key=keys[2]))[0]
        self.assertEqual(found, (0, 2))
        absent = t.ring_actual(self.image, t.Box(box=box, key=b"\xff" * 20))[0]
        self.assertEqual(absent, (1, 4))


def market(**kw):
    box = kw.pop("box", t.Box(kind="ring", keys=[], cap=0, head=0))
    base = dict(box=box, regs=[0x11, 0x22], idx=1, key=b"\x01" * 20, amount=10, flag=0, check_a=0, check_b=0, byte228=0,
                check_c=0, entry=100, ret_rax=1, ret_rdx=50, junk=0)
    base.update(kw)
    return t.Box(**base)


class MarketCheck(Base):
    def status(self, c):
        return t.market_actual(self.image, c)[1]

    def test_ordering_of_refusals(self):
        self.assertEqual(self.status(market()), 0x1a2)
        self.assertEqual(self.status(market(amount=0, check_a=1, flag=1)), 0x62)
        self.assertEqual(self.status(market(check_a=1, flag=1)), 0x75)
        self.assertEqual(self.status(market(flag=1)), 0x103)
        self.assertEqual(self.status(market(check_b=1, byte228=1, check_c=1)), 0x195)
        self.assertEqual(self.status(market(check_b=2, byte228=1, check_c=1)), 0x193)
        self.assertEqual(self.status(market(check_b=2, byte228=0, check_c=1)), 0x192)
        self.assertEqual(self.status(market(entry=None)), 0x6a)
        self.assertEqual(self.status(market(ret_rax=0)), 0x6b)

    def test_limit_boundary_is_half_of_the_entry(self):
        self.assertEqual(self.status(market(entry=101, ret_rdx=50)), 0x1a2)
        self.assertEqual(self.status(market(entry=101, ret_rdx=51)), 0x6b)

    def test_set_membership_in_both_forms(self):
        key = b"\x05" * 20
        ring = t.Box(kind="ring", keys=[b"\x01" * 20, key], cap=3, head=2)
        self.assertEqual(self.status(market(box=ring, key=key)), 0x1d)
        self.assertEqual(self.status(market(box=ring, key=b"\x06" * 20)), 0x1a2)
        rng = t.Lcg(3)
        keys = sorted(t.gen_keys(rng, 5))
        plan = t.build_tree(rng, keys, 0)
        tree = t.Box(kind="tree", keys=keys, plan=plan, height=0)
        t.ALLOC.next = t.NODES
        self.assertEqual(self.status(market(box=tree, key=keys[3])), 0x1d)
        t.ALLOC.next = t.NODES
        self.assertEqual(self.status(market(box=tree, key=b"\x00" * 20)), 0x1a2)

    def test_register_index_panics_after_the_set_check(self):
        out = t.market_actual(self.image, market(idx=2))
        self.assertEqual(out[0], "panic")
        key = b"\x05" * 20
        ring = t.Box(kind="ring", keys=[key], cap=1, head=0)
        self.assertEqual(self.status(market(idx=2, box=ring, key=key)), 0x1d)

    def test_battery_matches_rule(self):
        self.assertTrue(all(self.sweep_cases("market_check")))

    def test_flaws_are_detected(self):
        for flaw in t.FLAWS["market_check"]:
            self.assertFalse(all(self.sweep_cases("market_check", 400, flaw)), flaw)


def bound(**kw):
    base = dict(len=5, status=0x1a2, payload=bytes(range(16)), scale_status=0x1a2, value=1000, ptr=t.VALS + 0x1000 + 0x40)
    base.update(kw)
    return t.Box(**base)


def margin(**kw):
    base = dict(a=None, b=None, a_byte=0, idx=0, flag=0, ref=500, index=[(0, 0)], kinds=[3], a_tag=1, b_tag=1)
    base.update(kw)
    return t.Box(**base)


class MarginCheck(Base):
    def result(self, c):
        out = t.margin_actual(self.image, c)
        return out[1], out[2]

    def test_no_bound_is_refused(self):
        self.assertEqual(self.result(margin()), (0xdb, None))

    def test_single_lower_bound_passes_through(self):
        status, body = self.result(margin(a=bound(), a_byte=1))
        self.assertEqual((status, body[0], body[1], body[2]), (0x1a2, 0, 1000, 1))

    def test_pair_order_follows_the_flag(self):
        a, b = bound(value=1000), bound(value=900, ptr=t.VALS + 0x2000 + 0x40, payload=bytes(range(16, 32)))
        self.assertEqual(self.result(margin(a=a, b=b, flag=1, a_byte=0))[0], 0x1a2)
        self.assertEqual(self.result(margin(a=a, b=b, flag=0, a_byte=0))[0], 0xd9)
        a2 = bound(value=900)
        b2 = bound(value=900, ptr=t.VALS + 0x2000 + 0x40, payload=bytes(range(16, 32)))
        self.assertEqual(self.result(margin(a=a2, b=b2, flag=1, a_byte=0))[0], 0xd9)

    def test_upper_only_compares_with_the_reference(self):
        b = bound(value=400, ptr=t.VALS + 0x2000 + 0x40)
        self.assertEqual(self.result(margin(b=b, flag=1, ref=500))[0], 0x1a2)
        self.assertEqual(self.result(margin(b=b, flag=0, ref=500))[0], 0xda)

    def test_first_byte_two_acts_like_no_first_bound(self):
        a = bound(value=1000)
        b = bound(value=400, ptr=t.VALS + 0x2000 + 0x40, payload=bytes(range(16, 32)))
        self.assertEqual(self.result(margin(a=a, b=b, flag=1, a_byte=2, ref=500))[0], 0x1a2)

    def test_text_length_limit(self):
        self.assertEqual(self.result(margin(a=bound(len=100)))[0], 0x1a2)
        self.assertEqual(self.result(margin(a=bound(len=101)))[0], 0x158)

    def test_zero_value_and_scale_failure_both_report_0xad(self):
        self.assertEqual(self.result(margin(a=bound(value=0)))[0], 0xad)
        self.assertEqual(self.result(margin(a=bound(scale_status=0x77)))[0], 0xad)

    def test_record_kind_borrow_panics(self):
        out = t.margin_actual(self.image, margin(a=bound(), kinds=[3, 1], index=[(0, 1)]))
        self.assertEqual((out[0], out[1]), ("panic", "borrow"))

    def test_battery_matches_rule(self):
        self.assertTrue(all(self.sweep_cases("margin_check")))

    def test_flaw_is_detected(self):
        self.assertFalse(all(self.sweep_cases("margin_check", 400, "no_flag")))


class Controls(Base):
    def test_every_branch_flip_in_resolve_is_caught(self):
        battery = list(t.cases("resolve", 130))
        sites = [s for s in t.mutation_sites(self.image, "resolve") if s[1] == "jcc-flip"]
        self.assertGreater(len(sites), 8)
        for va, _, new in sites:
            old = t.patch(self.image, va, bytes([new]))
            try:
                caught = any(not t.attempt(self.image, "resolve", c) for c in battery)
            finally:
                t.patch(self.image, va, old)
            self.assertTrue(caught, hex(va))

    def test_status_immediate_mutation_is_caught(self):
        battery = list(t.cases("market_check", 130))
        sites = [s for s in t.mutation_sites(self.image, "market_check") if s[1] == "status+1"]
        self.assertGreater(len(sites), 8)
        for va, _, new in sites:
            old = t.patch(self.image, va, bytes([new]))
            try:
                caught = any(not t.attempt(self.image, "market_check", c) for c in battery)
            finally:
                t.patch(self.image, va, old)
            self.assertTrue(caught, hex(va))

    def test_patching_restores_the_digest(self):
        va = t.START["resolve"]
        old = t.patch(self.image, va, bytes([old_byte ^ 1 for old_byte in self.image.data[self.image.file_offset(va):][:1]]))
        self.assertNotEqual(t.digest(self.image.data), t.SHA256)
        t.patch(self.image, va, old)
        self.assertEqual(t.digest(self.image.data), t.SHA256)

    def test_unpopulated_memory_is_refused(self):
        m = t.new_machine(self.image, {})
        for r, v in ((t.RDI, t.OUT), (t.RSI, 5), (t.RDX, 0), (t.RCX, t.TBL)):
            m.set_reg(r, v)
        with self.assertRaises((t.ToolError, t.cpu.ToolError, KeyError, t.cpu.Done)):
            t.run(m, t.START["resolve"])

    def test_wrong_digest_binary_is_rejected(self):
        original = t.SHA256
        t.SHA256 = "0" * 64
        try:
            with self.assertRaises(t.ToolError):
                t.generate(pathlib.Path("unused-output-folder"))
        finally:
            t.SHA256 = original
        self.assertFalse(pathlib.Path("unused-output-folder").exists())

    def test_case_streams_are_deterministic(self):
        def digest_of():
            return [(c.idx, c.flag, c.ref, tuple(c.index), tuple(c.kinds), c.a_tag, c.b_tag, c.a_byte,
                     None if c.a is None else (c.a.len, c.a.payload, c.a.value)) for c in t.cases("margin_check", 40)]
        self.assertEqual(digest_of(), digest_of())


if __name__ == "__main__":
    unittest.main()
