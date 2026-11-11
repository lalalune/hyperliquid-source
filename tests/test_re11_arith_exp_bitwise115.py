import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_arith_exp_bitwise115 as t  # noqa: E402

FAM_AR, FAM_DV, FAM_MD, FAM_EX = t.FAMILIES


class Merged115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.Image(t.BINARY.read_bytes())

    def test_families_and_handlers(self):
        self.assertEqual([f.key for f in t.FAMILIES], ["ar", "dv", "md", "ex"])
        ops = {}
        for fam in t.FAMILIES:
            for op, row in fam.handlers.items():
                self.assertNotIn(op, ops)
                ops[op] = row[0]
        self.assertEqual(sorted(ops), [0x02, 0x03, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b] + list(range(0x10, 0x1f)))
        for fam in t.FAMILIES:
            t.opcode_slots(self.image, fam.handlers)

    def test_input_controls_detected(self):
        rows = t.input_controls(self.image)
        self.assertEqual(len(rows), 12)
        self.assertTrue(all(r[3] == 1 for r in rows))

    def test_shared_divrem_slot(self):
        self.assertEqual(self.image.relative[t.DIVREM_SLOT], t.DIVREM)
        self.assertEqual(t.dv_divrem(10, 3), (3, 1))
        self.assertEqual(t.md_divrem(10, 3), (3, 1))

    def test_wrong_family_model_detected(self):
        # the SUB reconstruction applied to the MUL handler cases must not pass
        cases = [c for c in t.ar_all_cases() if c["op"] == 0x02][:200]
        swapped = t.Family("x", "x", t.AR_HANDLERS, None, lambda c, mut=frozenset(): t.ar_model(dict(c, op=0x03), mut),
                           t.ar_run_case, t.ar_compare, t.ar_outcome, None, (), (), ())
        _, bad, _ = t.evaluate(swapped, self.image, cases=cases, stop_on_first=True)
        self.assertGreater(bad, 0)


class MulSubSignextend115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.Image(t.BINARY.read_bytes())
        cls.cases = t.ar_all_cases()

    def detected(self, mut=frozenset(), override=None):
        # scan the full case list until the first mismatch, so rare paths are not sampled away
        _, bad, _ = t.evaluate(FAM_AR, self.image, override=override, mut=mut, stop_on_first=True, cases=self.cases)
        return bad > 0

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

    def test_static_constants(self):
        consts, decoded = t.ar_static_evidence(self.image)
        funcs = consts["functions"]
        self.assertEqual(len(funcs), 3)
        self.assertEqual((funcs["0x298f7f0"]["instructions"], funcs["0x298f7f0"]["fde_bytes"]), (75, 252))
        self.assertEqual((funcs["0x298f9a0"]["instructions"], funcs["0x298f9a0"]["fde_bytes"]), (24, 93))
        self.assertEqual((funcs["0x298f430"]["instructions"], funcs["0x298f430"]["fde_bytes"]), (99, 371))
        slots = consts["opcode_table_slots"]
        for op in t.AR_OPS:
            self.assertEqual(slots[f"0x6441210+{8 * op:#x}"], slots[f"0x6441f00+{8 * op:#x}"])
        self.assertEqual(slots["0x6441210+0x58"], {"opcode": "0xb", "target": "0x298f430"})
        panic = consts["signextend_panic_arm"]
        self.assertEqual((panic["got_slot"], panic["got_slot_section"]), ("0x64df870", ".got"))
        self.assertEqual(panic["rdi_lea_target"], "0x64437d8")
        self.assertEqual(sorted(decoded), sorted(t.AR_HANDLERS[op][0] for op in t.AR_OPS))

    def test_wrong_opcode_slot_rejected(self):
        saved = dict(self.image.relative)
        try:
            self.image.relative[0x6441f00 + 8 * 0x03] = 0x298f7f0
            with self.assertRaises(t.ToolError):
                t.opcode_slots(self.image, t.AR_HANDLERS)
        finally:
            self.image.relative = saved

    def test_rejects_changed_check_byte(self):
        data = bytearray(self.image.data)
        sec = self.image.text
        data[0x298f467 - sec["address"] + sec["offset"]] = 0x1e
        with self.assertRaises(t.ToolError):
            t.ar_static_evidence(t.Image(bytes(data), check=False))

    def test_rejects_extra_call(self):
        # an e8 call planted in SUB's body is not the expected call set
        data = bytearray(self.image.data)
        sec = self.image.text
        off = 0x298f9f7 - sec["address"] + sec["offset"]
        data[off:off + 5] = bytes.fromhex("e800000000")
        with self.assertRaises(t.ToolError):
            t.ar_static_evidence(t.Image(bytes(data), check=False))

    def test_reconstruction_examples(self):
        m = t.M256
        self.assertEqual(t.ar_apply(0x02, m, m), 1)  # (-1) * (-1)
        self.assertEqual(t.ar_apply(0x02, 1 << 128, 1 << 128), 0)
        self.assertEqual(t.ar_apply(0x03, 0, 1), m)  # top minus second wraps
        self.assertEqual(t.ar_apply(0x03, 5, 3), 2)
        self.assertEqual(t.ar_apply(0x0b, 0, 0x80), m ^ 0x7f)  # byte 0 negative
        self.assertEqual(t.ar_apply(0x0b, 0, 0xff7f), 0x7f)  # byte 0 positive clears the rest
        self.assertEqual(t.ar_apply(0x0b, 30, m >> 1), m)  # bit 247 set: ones above it
        self.assertEqual(t.ar_apply(0x0b, 30, (m >> 9) | t.SIGN), m >> 9)  # bit 247 clear: bits 248.. cleared
        self.assertEqual(t.ar_apply(0x0b, 31, 0x1234), 0x1234)
        self.assertEqual(t.ar_apply(0x0b, (1 << 64) + 1, 0x80), 0x80)  # upper index limbs count

    def test_bound_31_and_32_equivalent(self):
        # extending byte 31 is the identity, so a bound of 32 cannot be told apart from 31
        for x in (0, 1, t.SIGN, t.M256, t.SIGN - 1, 0x1234 << 200):
            self.assertEqual(t.ar_signextend(31, x), x)
            bit = 8 * 31 + 7
            low = (1 << (bit + 1)) - 1
            self.assertEqual(x | (t.M256 ^ low) if (x >> bit) & 1 else x & low, x)

    def test_underflow(self):
        self.assertEqual(t.ar_model({"op": 0x02, "spec": 0, "stack": [1]})["ret"], t.R_UNDERFLOW)
        self.assertEqual(t.ar_model({"op": 0x0b, "spec": 0, "stack": []})["ret"], t.R_UNDERFLOW)
        self.assertEqual(t.ar_model({"op": 0x03, "spec": 0, "stack": [1, 2]})["ret"], t.R_OK)

    def test_sample_matches(self):
        _, bad, _ = t.evaluate(FAM_AR, self.image, cases=self.cases[::4])
        self.assertEqual(bad, 0)

    def test_outcome_families_present(self):
        rows, bad, m = t.evaluate(FAM_AR, self.image, cases=self.cases)
        self.assertEqual(bad, 0)
        seen = {t.ar_outcome(c, want, got) for _, c, want, got, _ in rows}
        for want in ("MUL/zero", "MUL/fits-256", "MUL/wraps", "MUL/underflow", "SUB/zero", "SUB/no-borrow",
                     "SUB/wraps", "SIGNEXTEND/unchanged-31", "SIGNEXTEND/unchanged-big", "SIGNEXTEND/underflow"):
            self.assertIn(want, seen)
        for limb in range(4):
            self.assertIn(f"SIGNEXTEND/limb{limb}-neg", seen)
            self.assertIn(f"SIGNEXTEND/limb{limb}-pos", seen)
        _, decoded = t.ar_static_evidence(self.image)
        missed = [va for va, fm in decoded[0x298f430] if fm is not None and va not in m.seen]
        self.assertEqual(missed, [0x298f498, 0x298f49a, t.AR_PANIC_STOP, t.AR_PANIC_STOP + 7])

    def test_corrupted_stack_word_detected(self):
        c = dict(self.cases[0])
        want = t.ar_model(c)
        got = t.ar_run_case(t.Machine(self.image), c)
        self.assertTrue(t.ar_compare(c, want, got))
        bad = dict(got, stack_raw=bytes([got["stack_raw"][0] ^ 1]) + got["stack_raw"][1:])
        self.assertFalse(t.ar_compare(c, want, bad))

    def test_model_mutants_detected(self):
        for name in t.AR_MODEL_MUTANTS:
            with self.subTest(name=name):
                self.assertTrue(self.detected(mut=frozenset([name])))

    def test_code_mutants_detected(self):
        for va, byte, _ in t.AR_BYTE_MUTANTS:
            with self.subTest(va=hex(va)):
                self.assertNotEqual(self.image.code(va, 1)[0], byte)
                self.assertTrue(self.detected(override={va: byte}))


class SdivModSmod115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.Image(t.BINARY.read_bytes())
        cls.cases = t.dv_all_cases()

    def detected(self, mut=frozenset(), override=None):
        # scan the full case list until the first mismatch, so rare paths are not sampled away
        _, bad, _ = t.evaluate(FAM_DV, self.image, override=override, mut=mut, stop_on_first=True, cases=self.cases)
        return bad > 0

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

    def test_static_constants(self):
        consts, decoded, fde = t.dv_static_evidence(self.image)
        funcs = consts["functions"]
        self.assertEqual(len(funcs), 6)
        sizes = {k: (v.get("instructions"), v["fde_bytes"]) for k, v in funcs.items()}
        self.assertEqual(sizes, {"0x298fa00": (34, 130), "0x298f8f0": (43, 166), "0x298fa90": (34, 130),
                                 "0x29956c0": (113, 445), "0x2995880": (96, 354), "0x144dde0": (None, 5874)})
        slots = consts["opcode_table_slots"]
        for op in t.DV_OPS:
            self.assertEqual(slots[f"0x6441210+{8 * op:#x}"], slots[f"0x6441f00+{8 * op:#x}"])
        self.assertEqual(slots["0x6441210+0x28"], {"opcode": "0x5", "target": "0x298fa00"})
        self.assertEqual(consts["min_test_constant"]["bytes"], "00" * 15 + "80")
        recip = consts["reciprocal_table"]
        self.assertEqual((recip["entries"], recip["matches_floor_0x7fd00_div_d9"]), (256, 256))
        self.assertEqual((recip["first"], recip["last"]), (2045, 1024))
        self.assertEqual(consts["libc_imports"], {"0x64df508": "memcpy", "0x64df568": "memmove",
                                                  "0x64df750": "memset"})
        self.assertEqual(fde[t.DIVREM], (0x144dde0, 0x144f4d2))

    def test_wrong_opcode_slot_rejected(self):
        saved = dict(self.image.relative)
        try:
            self.image.relative[0x6441f00 + 8 * 0x07] = 0x298fa00
            with self.assertRaises(t.ToolError):
                t.opcode_slots(self.image, t.DV_HANDLERS)
        finally:
            self.image.relative = saved

    def test_wrong_divider_slot_rejected(self):
        saved = dict(self.image.relative)
        try:
            self.image.relative[t.DIVREM_SLOT] = t.DIVREM + 0x10
            with self.assertRaises(t.ToolError):
                t.dv_static_evidence(self.image)
        finally:
            self.image.relative = saved

    def test_rejects_changed_check_byte(self):
        data = bytearray(self.image.data)
        sec = self.image.text
        data[0x29957c7 - sec["address"] + sec["offset"]] = 0xfe
        with self.assertRaises(t.ToolError):
            t.dv_static_evidence(t.Image(bytes(data), check=False))

    def test_rejects_extra_call(self):
        # an e8 call planted over SMOD's underflow arm is not the expected call set
        data = bytearray(self.image.data)
        sec = self.image.text
        off = 0x298fb0f - sec["address"] + sec["offset"]
        data[off:off + 5] = bytes.fromhex("e800000000")
        with self.assertRaises(t.ToolError):
            t.dv_static_evidence(t.Image(bytes(data), check=False))

    def test_reconstruction_examples(self):
        m, s = t.M256, t.SIGN
        neg = lambda x: (-x) & m  # noqa: E731
        self.assertEqual(t.dv_apply(0x05, neg(7), 2), neg(3))  # truncates toward zero
        self.assertEqual(t.dv_apply(0x05, 7, neg(2)), neg(3))
        self.assertEqual(t.dv_apply(0x05, neg(7), neg(2)), 3)
        self.assertEqual(t.dv_apply(0x05, s, m), s)  # MIN / -1 = MIN
        self.assertEqual(t.dv_apply(0x05, s, 1), s)
        self.assertEqual(t.dv_apply(0x05, 5, 0), 0)
        self.assertEqual(t.dv_apply(0x07, neg(7), 2), neg(1))  # sign of the dividend
        self.assertEqual(t.dv_apply(0x07, 7, neg(2)), 1)
        self.assertEqual(t.dv_apply(0x07, s, m), 0)
        self.assertEqual(t.dv_apply(0x07, 5, 0), 0)
        self.assertEqual(t.dv_apply(0x06, neg(7), 2), 1)  # unsigned
        self.assertEqual(t.dv_apply(0x06, 5, 0), 0)
        self.assertEqual(t.dv_divrem(10, 3), (3, 1))

    def test_underflow(self):
        self.assertEqual(t.dv_model({"op": 0x05, "stack": [1]})["ret"], t.R_UNDERFLOW)
        self.assertEqual(t.dv_model({"op": 0x06, "stack": []})["ret"], t.R_UNDERFLOW)
        self.assertEqual(t.dv_model({"op": 0x07, "stack": [1, 2]})["ret"], t.R_OK)

    def test_all_cases_match_and_cover(self):
        rows, bad, m = t.evaluate(FAM_DV, self.image, cases=self.cases)
        self.assertEqual((len(rows), bad), (6000, 0))
        seen = {t.dv_outcome(c, want, got) for _, c, want, got, _ in rows}
        for want in ("SDIV/min-by-minus-one", "SDIV/min-by-one", "SDIV/zero-divisor", "SDIV/underflow",
                     "SDIV/++", "SDIV/+-", "SDIV/-+", "SDIV/--", "SMOD/zero-dividend", "SMOD/zero-divisor",
                     "SMOD/-+", "SMOD/+-", "MOD/zero-divisor", "MOD/a<b", "MOD/exact", "MOD/remainder",
                     "div_rem/n<d", "div_rem/n=d", "div_rem/n4/d4", "div_rem/n4/d1-normalised"):
            self.assertIn(want, seen)
        _, decoded, _ = t.dv_static_evidence(self.image)
        for f in (0x298fa00, 0x298f8f0, 0x298fa90, t.DV_I256_DIV, t.DV_I256_MOD):
            missed = [va for va, fm in decoded[f] if fm is not None and va not in m.seen]
            self.assertEqual(missed, [], hex(f))

    def test_corrupted_stack_word_detected(self):
        c = next(c for c in self.cases if c["op"] == 0x05 and len(c["stack"]) >= 2)
        want = t.dv_model(c)
        got = t.dv_run_case(t.PathMachine(self.image), c)
        self.assertTrue(t.dv_compare(c, want, got))
        bad = dict(got, stack_raw=bytes([got["stack_raw"][0] ^ 1]) + got["stack_raw"][1:])
        self.assertFalse(t.dv_compare(c, want, bad))

    def test_divider_guard_bytes_checked(self):
        c = next(c for c in self.cases if c["op"] == "divrem")
        want = t.dv_model(c)
        got = t.dv_run_case(t.PathMachine(self.image), c)
        self.assertTrue(t.dv_compare(c, want, got))
        self.assertFalse(t.dv_compare(c, want, dict(got, guard_ok=False)))
        self.assertFalse(t.dv_compare(c, want, dict(got, r=got["r"] ^ 1)))

    def test_overlapping_memcpy_rejected(self):
        m = t.PathMachine(self.image)
        m.add_region(t.ARG_AT, 0x40)
        m.regs[7], m.regs[6], m.regs[2] = t.ARG_AT + 8, t.ARG_AT, 16
        with self.assertRaises(t.ToolError):
            t.LIB_MODELS["memcpy"](m)

    def test_model_mutants_detected(self):
        for name in t.DV_MODEL_MUTANTS:
            with self.subTest(name=name):
                self.assertTrue(self.detected(mut=frozenset([name])))

    def test_code_mutants_detected(self):
        for va, byte, _ in t.DV_BYTE_MUTANTS:
            with self.subTest(va=hex(va)):
                self.assertNotEqual(self.image.code(va, 1)[0], byte)
                self.assertTrue(self.detected(override={va: byte}))


class AddmodMulmod115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.Image(t.BINARY.read_bytes())
        cls.cases = t.md_all_cases()

    def detected(self, mut=frozenset(), override=None):
        # scan the full case list until the first mismatch, so rare paths are not sampled away
        _, bad, _ = t.evaluate(FAM_MD, self.image, override=override, mut=mut, stop_on_first=True, cases=self.cases)
        return bad > 0

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

    def test_static_constants(self):
        consts, decoded, fde = t.md_static_evidence(self.image)
        sizes = {k: (v.get("instructions"), v["fde_bytes"]) for k, v in consts["functions"].items()}
        self.assertEqual(sizes, {"0x298fb20": (43, 182), "0x298fbe0": (44, 187), "0x29fe430": (87, 343),
                                 "0x43be000": (30, 96), "0x43bfc80": (None, 8909), "0x43c1f50": (None, 6477),
                                 "0x144dde0": (None, 5874)})
        slots = consts["opcode_table_slots"]
        for op in t.MD_OPS:
            self.assertEqual(slots[f"0x6441210+{8 * op:#x}"], slots[f"0x6441f00+{8 * op:#x}"])
        self.assertEqual(slots["0x6441210+0x40"], {"opcode": "0x8", "target": "0x298fb20"})
        self.assertEqual(slots["0x6441210+0x48"], {"opcode": "0x9", "target": "0x298fbe0"})
        self.assertEqual(consts["got_slots"], {"0x64e6dd8": "0x43bfc80", "0x64e6f50": "0x43c1f50",
                                               "0x64dfb80": "0x144dde0"})
        panics = consts["panic_helpers"]
        self.assertEqual(panics["0x64df878"]["message"], "attempt to divide by zero")
        self.assertEqual(panics["0x64df878"]["text_va"], "0x46f29b")
        self.assertEqual(consts["libc_imports"], {"0x64df508": "memcpy", "0x64df568": "memmove",
                                                  "0x64df750": "memset"})
        self.assertEqual(fde[t.MD_MULMOD_CORE], (0x43bfc80, 0x43c1f4d))

    def test_wrong_opcode_slot_rejected(self):
        saved = dict(self.image.relative)
        try:
            self.image.relative[0x6441f00 + 8 * 0x09] = 0x298fb20
            with self.assertRaises(t.ToolError):
                t.opcode_slots(self.image, t.MD_HANDLERS)
        finally:
            self.image.relative = saved

    def test_wrong_got_slot_rejected(self):
        for slot in (t.MD_MULMOD_SLOT, t.MD_REDUCE5_SLOT, t.DIVREM_SLOT, 0x64df878):
            saved = dict(self.image.relative)
            try:
                self.image.relative[slot] += 0x10
                with self.subTest(slot=hex(slot)), self.assertRaises(t.ToolError):
                    t.md_static_evidence(self.image)
            finally:
                self.image.relative = saved

    def test_rejects_changed_check_byte(self):
        data = bytearray(self.image.data)
        sec = self.image.text
        data[0x29fe55a - sec["address"] + sec["offset"]] = 0x02
        with self.assertRaises(t.ToolError):
            t.md_static_evidence(t.Image(bytes(data), check=False))

    def test_rejects_changed_panic_text(self):
        data = bytearray(self.image.data)
        name, off = self.image.section_of(0x46f29b)
        data[off] ^= 0x20
        with self.assertRaises(t.ToolError):
            t.md_panic_rows(t.Image(bytes(data), check=False))

    def test_rejects_extra_call(self):
        # an e8 call planted over MULMOD's underflow arm is not the expected call set
        data = bytearray(self.image.data)
        sec = self.image.text
        off = 0x298fc8e - sec["address"] + sec["offset"]
        data[off:off + 5] = bytes.fromhex("e800000000")
        with self.assertRaises(t.ToolError):
            t.md_static_evidence(t.Image(bytes(data), check=False))

    def test_reconstruction_examples(self):
        m = t.M256
        self.assertEqual(t.md_apply(0x08, m, m, 1), 0)
        self.assertEqual(t.md_apply(0x08, m, 1, 7), (m + 1) % 7)  # the carry is kept
        self.assertEqual(t.md_apply(0x08, m, m, m - 1), 2)
        self.assertEqual(t.md_apply(0x08, 3, 4, 7), 0)
        self.assertEqual(t.md_apply(0x08, 3, 4, 8), 7)
        self.assertEqual(t.md_apply(0x08, 5, 6, 0), 0)
        self.assertEqual(t.md_apply(0x09, m, m, 12), (m * m) % 12)  # full 512-bit product
        self.assertEqual(t.md_apply(0x09, 5, 6, 0), 0)
        self.assertEqual(t.md_addmod_core(m, 2, 10, frozenset()), ((m + 2) % 10, (m + 2) % 10))
        self.assertEqual(t.md_addmod_core(1, 2, 10, frozenset()), (3, 10))
        self.assertEqual(t.md_reduce5((1 << 256) | 5, 3), {"q": ((1 << 256) | 5) // 3, "r": ((1 << 256) | 5) % 3})
        self.assertEqual(t.md_reduce5(9, 0), {"panic": "attempt to divide by zero"})

    def test_underflow(self):
        self.assertEqual(t.md_model({"op": 0x08, "stack": [1, 2]})["ret"], t.R_UNDERFLOW)
        self.assertEqual(t.md_model({"op": 0x09, "stack": []})["ret"], t.R_UNDERFLOW)
        self.assertEqual(t.md_model({"op": 0x09, "stack": [1, 2, 3]})["ret"], t.R_OK)

    def test_all_cases_match_and_cover(self):
        rows, bad, m = t.evaluate(FAM_MD, self.image, cases=self.cases)
        self.assertEqual((len(rows), bad), (5200, 0))
        seen = {t.md_outcome(c, want, got) for _, c, want, got, _ in rows}
        for want in ("ADDMOD/carry-5-limb-div_rem", "ADDMOD/modulus-one", "ADDMOD/sum<n-unreduced", "ADDMOD/sum=n",
                     "ADDMOD/u256-div_rem", "ADDMOD/underflow", "ADDMOD/zero-modulus", "MULMOD/product<n",
                     "MULMOD/p8/n4", "MULMOD/p8/n1", "MULMOD/zero-modulus", "MULMOD/underflow",
                     "addmod_core/carry-5-limb-div_rem", "mulmod_core/zero-modulus", "reduce5/num<d",
                     "reduce5/num5/d1", "reduce5/num5/d4", "reduce5/panic-attempt-to-divide-by-zero"):
            self.assertIn(want, seen)
        _, decoded, _ = t.md_static_evidence(self.image)
        for f in (0x298fb20, 0x298fbe0, t.MD_ADDMOD_CORE):
            missed = [va for va, fm in decoded[f] if fm is not None and va not in m.seen]
            self.assertEqual(missed, [], hex(f))

    def test_corrupted_stack_word_detected(self):
        c = next(c for c in self.cases if c["op"] == 0x09 and len(c["stack"]) >= 3)
        want = t.md_model(c)
        got = t.md_run_case(t.PathMachine(self.image), c)
        self.assertTrue(t.md_compare(c, want, got))
        bad = dict(got, stack_raw=bytes([got["stack_raw"][0] ^ 1]) + got["stack_raw"][1:])
        self.assertFalse(t.md_compare(c, want, bad))

    def test_direct_guard_and_slots_checked(self):
        for kind in t.MD_DIRECT_KINDS:
            c = next(c for c in self.cases if c["op"] == kind and c.get("d", c.get("n")) not in (0, None))
            want = t.md_model(c)
            got = t.md_run_case(t.PathMachine(self.image), c)
            with self.subTest(kind=kind):
                self.assertTrue(t.md_compare(c, want, got))
                self.assertFalse(t.md_compare(c, want, dict(got, guard_ok=False)))
                key = "r" if kind == "reduce5" else "n"
                self.assertFalse(t.md_compare(c, want, dict(got, **{key: got[key] ^ 1})))

    def test_panic_boundary_is_named(self):
        c = {"op": "reduce5", "mode": "zero_n", "num": 5, "d": 0}
        got = t.md_run_case(t.PathMachine(self.image), c)
        self.assertEqual(got["panic"], "attempt to divide by zero")
        self.assertFalse(t.md_compare(c, {"q": 0, "r": 0}, got))

    def test_overlapping_memcpy_rejected(self):
        m = t.PathMachine(self.image)
        m.add_region(t.ARG_AT, 0x40)
        m.regs[7], m.regs[6], m.regs[2] = t.ARG_AT + 8, t.ARG_AT, 16
        with self.assertRaises(t.ToolError):
            t.LIB_MODELS["memcpy"](m)

    def test_model_mutants_detected(self):
        for name in t.MD_MODEL_MUTANTS:
            with self.subTest(name=name):
                self.assertTrue(self.detected(mut=frozenset([name])))

    def test_code_mutants_detected(self):
        for va, byte, _ in t.MD_BYTE_MUTANTS:
            with self.subTest(va=hex(va)):
                self.assertNotEqual(self.image.code(va, 1)[0], byte)
                self.assertTrue(self.detected(override={va: byte}))


class ExpBitwise115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.Image(t.BINARY.read_bytes())
        cls.ecases = t.ex_exp_cases()
        cls.bcases = t.ex_bit_cases()
        cls.pcases = t.ex_all_pow()
        cls.rows, cls.bad, cls.machine = t.ex_evaluate(cls.image, cases=cls.ecases + cls.bcases)
        cls.prows, cls.pbad, _ = t.ex_evaluate_pow(cls.image, machine=cls.machine, cases=cls.pcases)
        cls.consts, cls.decoded = t.ex_static_evidence(cls.image)

    def detected(self, run, cases, mut=frozenset(), override=None):
        # scan the full case list until the first mismatch, so rare paths are not sampled away
        _, bad, _ = run(self.image, override=override, mut=mut, stop_on_first=True, cases=cases)
        return bad > 0

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

    def test_static_constants(self):
        funcs = self.consts["functions"]
        self.assertEqual(len(funcs), 17)
        sizes = {k: (v["instructions"], v["calls"]) for k, v in funcs.items()
                 if k in ("0x298f6a0", "0x29fcfb0", "0x2998720", "0x2998870")}
        self.assertEqual(sizes, {"0x298f6a0": (87, 1), "0x29fcfb0": (171, 0), "0x2998720": (26, 0),
                                 "0x2998870": (145, 0)})
        self.assertEqual(sum(v["instructions"] for v in funcs.values()), 87 + 171 + 701)
        self.assertEqual(funcs["0x2998b80"]["min_spec_byte"], 5)
        self.assertEqual(funcs["0x2998790"]["min_spec_byte"], 0xd)
        slots = self.consts["opcode_table_slots"]
        self.assertEqual(len(slots), 32)
        for op in t.EX_OPS:
            self.assertEqual(slots[f"0x6441210+{8 * op:#x}"], slots[f"0x6441f00+{8 * op:#x}"])
        self.assertEqual(slots["0x6441210+0x50"], {"opcode": "0xa", "target": "0x298f6a0"})
        self.assertEqual(slots["0x6441210+0xd8"], {"opcode": "0x1b", "target": "0x2998b80"})
        self.assertEqual(self.consts["interpreter_offsets"]["gas_remaining"], "0x188")
        self.assertEqual(self.consts["host_offsets"], {"parameter_block": "0x250", "gas_per_exponent_byte": "0x18"})

    def test_wrong_opcode_slot_rejected(self):
        for where, target in ((0x6441f00 + 8 * 0x0a, 0x298f7f0), (0x6441f00 + 8 * 0x1c, 0x2998b80),
                              (0x6441210 + 8 * 0x54, 0x2998b80)):
            with self.subTest(where=hex(where)), self.assertRaises(t.ToolError):
                t.opcode_slots(t.with_slot(self.image, where, target), t.EX_HANDLERS)

    def test_rejects_changed_check_byte(self):
        for va, raw in ((0x298f75c, b"\x04"), (0x2998b86, b"\x06")):
            with self.subTest(va=hex(va)), self.assertRaises(t.ToolError):
                t.ex_static_evidence(t.with_text_patch(self.image, va, raw))

    def test_rejects_extra_call(self):
        # an e8 call planted in the helper's zero-exponent arm is not the expected (empty) call set
        patched = t.with_text_patch(self.image, 0x29fcff7, bytes.fromhex("e800000000") + b"\x90" * 4)
        with self.assertRaises(t.ToolError):
            t.ex_static_evidence(patched)

    def test_out_of_range_inputs_rejected(self):
        m = t.Machine(self.image)
        good = self.ecases[1]
        for k, bad in enumerate((dict(good, stack=[1 << 256, 1]), dict(good, spec=0x100), dict(good, gas=1 << 64),
                                 dict(good, per_byte=-1), dict(good, op=0x0b))):
            with self.subTest(k=k), self.assertRaises(t.ToolError):
                t.ex_run_case(m, bad)
        with self.assertRaises(t.ToolError):
            t.ex_run_pow(m, {"b": 1 << 256, "e": 1})

    def test_reconstruction_examples(self):
        m = t.M256
        self.assertEqual(t.ex_power(0, 0), 1)
        self.assertEqual(t.ex_power(2, 256), 0)
        self.assertEqual(t.ex_power(m, 3), m)  # (-1) ** odd
        self.assertEqual([t.ex_exp_bytes(e) for e in (1, 0xff, 0x100, m)], [1, 1, 2, 32])
        self.assertEqual(t.ex_exp_cost(0, 50), 0)
        self.assertEqual(t.ex_exp_cost(m, t.M64), t.M64)  # 32 * (2^64 - 1) saturates
        self.assertEqual(t.ex_apply(0x10, 1, 2), 1)  # LT: top < second
        self.assertEqual(t.ex_apply(0x12, m, 0), 1)  # SLT: -1 < 0
        self.assertEqual(t.ex_apply(0x1a, 31, 0x1234), 0x34)  # BYTE 31 is the least significant byte
        self.assertEqual(t.ex_apply(0x1b, 256, 3), 0)
        self.assertEqual(t.ex_apply(0x1d, 1 << 64, t.SIGN), m)  # SAR saturates to the sign
        self.assertEqual(t.ex_apply(0x1e, 0, None), 256)

    def test_model_paths(self):
        base = {"spec": 0, "per_byte": 50, "gas": 100}
        self.assertEqual(t.ex_model(dict(base, op=0x0a, stack=[5])),
                         {"ret": t.R_UNDERFLOW, "stack": [5], "n": 1, "gas": 100})
        self.assertEqual(t.ex_model(dict(base, op=0x0a, stack=[7, 0x100, 2])),
                         {"ret": t.R_OK, "stack": [7, 0], "n": 2, "gas": 0})
        # out of gas: the length is already popped, nothing else changes
        self.assertEqual(t.ex_model(dict(base, op=0x0a, gas=99, stack=[0x100, 2])),
                         {"ret": t.EX_R_OUT_OF_GAS, "stack": [0x100, 2], "n": 1, "gas": 99})
        # the spec gate wins even on an empty stack; ungated opcodes ignore the spec byte
        self.assertEqual(t.ex_model(dict(base, op=0x1b, spec=4, stack=[]))["ret"], t.EX_R_NOT_ACTIVATED)
        self.assertEqual(t.ex_model(dict(base, op=0x1b, spec=5, stack=[1]))["ret"], t.R_UNDERFLOW)
        self.assertEqual(t.ex_model(dict(base, op=0x1e, spec=0xc, stack=[1]))["ret"], t.EX_R_NOT_ACTIVATED)
        self.assertEqual(t.ex_model(dict(base, op=0x10, stack=[1, 2]))["gas"], 100)

    def test_all_cases_match(self):
        self.assertEqual(len(self.rows) + len(self.prows), 12000)
        self.assertEqual((self.bad, self.pbad), (0, 0))

    def test_outcome_families_present(self):
        seen = {t.ex_outcome(c, want, got) for _, c, want, got, _ in self.rows}
        for want in ("EXP/underflow", "EXP/zero-exponent", "EXP/out-of-gas", "EXP/out-of-gas-saturated",
                     "EXP/b32-saturated", "LT/true", "LT/false", "SLT/true", "SGT/false", "EQ/true", "ISZERO/true",
                     "BYTE/index", "BYTE/out-of-range", "SHL/saturated", "SHR/shift", "SAR/saturated-neg",
                     "SAR/shift-neg", "CLZ/zero", "CLZ/limb3", "CLZ/not-activated", "SHL/not-activated",
                     "NOT/underflow"):
            self.assertIn(want, seen)
        for k in range(1, 33):
            self.assertIn("EXP/b%02d" % k, seen)
        exact = [c for _, c, want, got, ok in self.rows if c["mode"] == "exact-gas" and got.get("gas") == 0]
        self.assertTrue(exact)  # gas equal to the cost is enough (jb, not jbe)

    def test_coverage(self):
        missed = [va for f in t.EX_CLAIMED for va, fm in self.decoded[f] if fm is not None and va not in self.machine.seen]
        self.assertEqual(missed, [0x29fd09e])  # the two-byte alignment nop before the helper's loop head only

    def test_corrupted_result_detected(self):
        for c in (self.ecases[1], self.bcases[0]):
            want = t.ex_model(c)
            got = t.ex_run_case(t.Machine(self.image), c)
            self.assertTrue(t.ex_compare(c, want, got))
            bad = dict(got, stack_raw=bytes([got["stack_raw"][0] ^ 1]) + got["stack_raw"][1:])
            self.assertFalse(t.ex_compare(c, want, bad))
            self.assertFalse(t.ex_compare(c, want, dict(got, gas=got["gas"] ^ 1)))
            self.assertFalse(t.ex_compare(c, want, dict(got, host_ok=False)))

    def test_model_mutants_detected(self):
        for names, cases in ((t.EX_EXP_MUTANTS, self.ecases), (t.EX_BIT_MUTANTS, self.bcases)):
            for name in names:
                with self.subTest(name=name):
                    self.assertTrue(self.detected(t.ex_evaluate, cases, mut=frozenset([name])))
        for name in t.EX_POW_MUTANTS:
            with self.subTest(name=name):
                self.assertTrue(self.detected(t.ex_evaluate_pow, self.pcases, mut=frozenset([name])))

    def test_code_mutants_detected(self):
        for group, run, cases in ((t.EX_EXP_BYTE_MUTANTS, t.ex_evaluate, self.ecases),
                                  (t.EX_BIT_BYTE_MUTANTS, t.ex_evaluate, self.bcases),
                                  (t.EX_POW_BYTE_MUTANTS, t.ex_evaluate_pow, self.pcases)):
            for va, byte, _ in group:
                with self.subTest(va=hex(va)):
                    self.assertNotEqual(self.image.code(va, 1)[0], byte)
                    self.assertTrue(self.detected(run, cases, override={va: byte}))


if __name__ == "__main__":
    unittest.main()
