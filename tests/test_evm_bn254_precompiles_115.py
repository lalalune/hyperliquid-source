import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import evm_bn254_precompiles_115 as t  # noqa: E402

M64 = t.M64


def control_cases(per_target=60):
    out = []
    for target in t.TARGETS:
        s = t.Stream("test-" + target[0])
        out += [t.make_case(s, target) for _ in range(per_target)]
    return out


def hand(name, ln, limit, **kw):
    """One hand-built case for the named target."""
    target = t.ENTRIES[name]
    fam = target[2]
    c = {"target": name, "entry": target[1], "family": fam, "wrapper": target[3] is not None or target[4] is not None,
         "once": 0, "parity": 0, "alloc_fail": False, "ctx": 0x1234, "mode": "hand",
         "input": bytes((7 * i + 3) & 0xff for i in range(ln)), "limit": limit,
         "vt": ("ok", bytes(range(64))) if fam != "pair" else ("ok", 1), "cost": 0}
    if c["wrapper"]:
        if fam == "pair":
            c["w_per"], c["w_base"] = target[4], target[5]
        else:
            c["w_cost"] = target[3]
    else:
        if fam == "pair":
            c["per"], c["base"] = 34000, 45000
        else:
            c["cost"] = 150
    c.update(kw)
    return c


class Bn254Precompiles115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.Image(t.BINARY.read_bytes())
        cls.machine = t.TraceMachine(cls.image)
        cls.rows, cls.decoded, cls.consts = t.static_evidence(cls.image)
        cls.cases = control_cases()

    def run_one(self, c, mut=frozenset()):
        want = t.model(c, mut)
        got = t.run_case(self.machine, c)
        return want, got, t.compare(c, want, got, t.box_of(self.machine, c, want))

    def detected(self, mut=frozenset(), override=None):
        _, bad, _ = t.evaluate(self.image, self.cases, override=override, mut=mut, stop_on_first=True)
        return bad > 0

    # ----- input validation and static facts
    def test_wrong_digest_rejected(self):
        data = bytearray(t.BINARY.read_bytes())
        data[self.image.text["offset"] + 1] ^= 0x40
        with self.assertRaises(t.ToolError):
            t.Image(bytes(data))

    def test_code_outside_text_rejected(self):
        end = self.image.text["address"] + self.image.text["size"]
        with self.assertRaises(t.ToolError):
            self.image.code(end + 0x10, 4)
        with self.assertRaises(t.ToolError):
            self.image.code(end - 2, 4)

    def test_address_without_fde_rejected(self):
        with self.assertRaises(t.ToolError):
            t.ev.fde_rows(self.image, {t.ADD_RUN + 1})

    def test_function_extents(self):
        ends = {start: end for start, (_, end) in self.rows.items()}
        self.assertEqual(ends[0x5c15e20], 0x5c1607d)
        self.assertEqual(ends[0x5c16080], 0x5c162ad)
        self.assertEqual(ends[0x5c162b0], 0x5c165a6)
        for wrapper in (0x5c09750, 0x5c097f0, 0x5c15ba0, 0x5c15c40):
            self.assertEqual(ends[wrapper] - wrapper, 0x9a)
        for wrapper in (0x5c15ce0, 0x5c15d80):
            self.assertEqual(ends[wrapper] - wrapper, 0xa0)

    def test_got_slots_and_wrapper_constants(self):
        slots = self.consts["slots"]
        self.assertEqual(slots["add"]["word"], "0x5c15e20")
        self.assertEqual(slots["mul"]["word"], "0x5c16080")
        self.assertEqual(slots["pair"]["word"], "0x5c162b0")
        self.assertEqual(slots["memcpy-import"]["symbol"], "memcpy")
        imm = {k: {x[1] for x in v} for k, v in self.consts["immediates"].items()}
        self.assertIn("0x96", imm["0x5c09750"])
        self.assertIn("0x1f4", imm["0x5c097f0"])
        self.assertIn("0x1770", imm["0x5c15ba0"])
        self.assertIn("0x9c40", imm["0x5c15c40"])
        self.assertTrue({"0x84d0", "0xafc8"} <= imm["0x5c15ce0"])
        self.assertTrue({"0x13880", "0x186a0"} <= imm["0x5c15d80"])
        calls = {k: {x[1] for x in v} for k, v in self.consts["call_sites"].items()}
        self.assertIn("0x64eaec8", calls["0x5c09750"])
        self.assertIn("0x64eaec0", calls["0x5c15c40"])
        self.assertIn("0x64eaed0", calls["0x5c15d80"])

    def test_static_provider_is_not_initialised_in_the_file(self):
        self.assertEqual(len(bytes.fromhex(self.consts["static_initial_bytes"])), 0x18)

    # ----- reconstruction facts, each also checked against the machine code
    def test_pad_boundary_of_add_and_mul(self):
        for name, pad in (("add-run", 0x80), ("mul-run", 0x60)):
            for ln, label in ((pad - 1, "stack"), (pad, "in+0")):
                want, got, ok = self.run_one(hand(name, ln, 10_000))
                self.assertTrue(ok, (name, ln))
                vt = [e for e in want[1] if e[0].startswith("vt-")][0]
                self.assertEqual(vt[1], label)
                self.assertEqual(any(e[0] == "memcpy" for e in want[1]), label == "stack")

    def test_cost_above_limit_is_out_of_gas_before_any_provider_call(self):
        want, got, ok = self.run_one(hand("add-run", 128, 149))
        self.assertTrue(ok)
        self.assertEqual(want[1], [])
        self.assertEqual(int.from_bytes(want[0][8:16], "little"), t.OOG)
        want, got, ok = self.run_one(hand("add-run", 128, 150))
        self.assertTrue(ok)
        self.assertTrue(any(e[0] == "vt-add" for e in want[1]))

    def test_pair_check_order(self):
        # multiplication overflow wins over everything, then addition overflow, then gas, then length
        c = hand("pair-run", 384, 0, per=1 << 63, base=0)
        want, got, ok = self.run_one(c)
        self.assertTrue(ok)
        self.assertEqual(want[2], "mul-overflow")
        c = hand("pair-run", 192, 0, per=M64, base=1)
        want, got, ok = self.run_one(c)
        self.assertTrue(ok)
        self.assertEqual(want[2], "add-overflow")
        c = hand("pair-run", 193, 0, per=100, base=100)
        want, got, ok = self.run_one(c)
        self.assertTrue(ok)
        self.assertEqual(int.from_bytes(want[0][8:16], "little"), t.OOG)
        c = hand("pair-run", 193, 200, per=100, base=100)
        want, got, ok = self.run_one(c)
        self.assertTrue(ok)
        self.assertEqual(int.from_bytes(want[0][8:16], "little"), t.BAD_LEN)

    def test_pair_empty_input_uses_dangling_vector(self):
        want, got, ok = self.run_one(hand("pair-run", 0, 45000))
        self.assertTrue(ok)
        self.assertEqual([e for e in want[1] if e[0] == "vt-pair"][0][1:], (0, (), 8))
        self.assertFalse(any(e[0] in ("alloc", "dealloc") for e in want[1]))

    def test_pair_slice_descriptors(self):
        want, got, ok = self.run_one(hand("pair-run", 576, M64))
        self.assertTrue(ok)
        pairs = [e for e in want[1] if e[0] == "vt-pair"][0][2]
        self.assertEqual(pairs, ((0, 64, 64, 128), (192, 64, 256, 128), (384, 64, 448, 128)))
        self.assertIn(("dealloc", 96, 0), want[1])

    def test_low_bit_of_allocation_selects_bytes_vtable(self):
        for parity, word in ((0, t.V_EVEN), (1, t.V_ODD)):
            want, got, ok = self.run_one(hand("add-run", 128, M64, parity=parity))
            self.assertTrue(ok)
            self.assertEqual(int.from_bytes(want[0][0:8], "little"), word)

    def test_wrapper_widens_ok_and_error_results(self):
        want, got, ok = self.run_one(hand("mul-wrap-6000", 96, 6000))
        self.assertTrue(ok)
        self.assertEqual(int.from_bytes(want[0][0:8], "little"), t.OK_MARK)
        self.assertEqual(int.from_bytes(want[0][0x38:0x40], "little"), 6000)
        want, got, ok = self.run_one(hand("mul-wrap-6000", 96, 5999))
        self.assertTrue(ok)
        self.assertEqual(int.from_bytes(want[0][0:8], "little"), t.OOG)
        self.assertEqual(int.from_bytes(want[0][0x18:0x20], "little"), t.STATIC_B)
        self.assertEqual(int.from_bytes(want[0][0x50:0x58], "little"), 0x1234)
        want, got, ok = self.run_one(hand("add-wrap-150", 0, 149))
        self.assertTrue(ok)
        self.assertEqual(int.from_bytes(want[0][0x18:0x20], "little"), t.STATIC_A)

    def test_once_init_runs_before_provider_call(self):
        want, got, ok = self.run_one(hand("add-run", 10, M64, once=2))
        self.assertTrue(ok)
        kinds = [e[0] for e in want[1]]
        self.assertLess(kinds.index("once-init"), kinds.index("vt-add"))

    def test_alloc_failure_is_a_noreturn_boundary(self):
        want, got, ok = self.run_one(hand("mul-run", 96, M64, alloc_fail=True))
        self.assertTrue(ok)
        self.assertEqual(want[2], "alloc-error")

    def test_all_sampled_cases_match(self):
        total, bad, _ = t.evaluate(self.image, self.cases, machine=self.machine)
        self.assertEqual((total, bad), (len(self.cases), 0))

    # ----- negative controls
    def test_model_mutants_detected(self):
        for name in t.MODEL_MUTANTS:
            self.assertTrue(self.detected(mut=frozenset([name])), name)

    def test_code_mutants_detected(self):
        picked = [(va, byte, what) for va, byte, what in t.byte_candidates(self.decoded) if va not in t.EQUIVALENT][::7]
        self.assertGreaterEqual(len(picked), 15)
        for va, byte, what in picked:
            self.assertTrue(self.detected(override={va: byte}), what)

    def test_equivalent_mutants_are_really_unobservable(self):
        by_va = {va: byte for va, byte, _ in t.byte_candidates(self.decoded)}
        self.assertEqual(set(t.EQUIVALENT) - set(by_va), set())
        for va in t.EQUIVALENT:
            self.assertFalse(self.detected(override={va: by_va[va]}), hex(va))

    def test_corrupted_result_bytes_are_flagged(self):
        c = hand("add-wrap-500", 128, M64)
        want = t.model(c)
        got = t.run_case(self.machine, c)
        bad = bytearray(want[0])
        bad[0x38] ^= 1
        self.assertFalse(t.compare(c, (bytes(bad), want[1], want[2]), got, t.box_of(self.machine, c, want)))
        self.assertFalse(t.compare(c, (want[0], [e for e in want[1] if e[0] != "alloc"], want[2]), got, t.box_of(self.machine, c, want)))


if __name__ == "__main__":
    unittest.main()
