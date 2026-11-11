import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import evm_arith_opcodes_115 as tool  # noqa: E402

M = tool.M256
IMAGE = tool.base.Image(tool.BINARY.read_bytes())
HANDLERS = tool.handler_table(IMAGE)


def case(op, stack, spec=20, gas=1_000_000, per_byte=50, fam="B"):
    return {"fam": fam, "op": op, "spec": spec, "n": len(stack), "stack": list(stack), "gas": gas,
            "per_byte": per_byte, "i": 0}


def run(c):
    m = tool.XMachine(IMAGE)
    got = tool.run_case(m, IMAGE, c, HANDLERS[(c["fam"], c["op"])])
    return got


def result_word(got, c):
    stk = got["after"]["stk"]
    return int.from_bytes(stk[32 * (got["n"] - 1):32 * got["n"]], "little")


class TableTests(unittest.TestCase):
    def test_binary_digest_is_pinned(self):
        self.assertEqual(tool.SHA256, "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
        corrupt = bytearray(IMAGE.data)
        corrupt[IMAGE.text["offset"] + 7] ^= 1
        with self.assertRaises(tool.ToolError):
            tool.base.Image(bytes(corrupt))

    def test_two_b_tables_agree_and_slot_is_opcode(self):
        for op in tool.NAMES:
            a, b = (IMAGE.relative[t + 8 * op] for t in tool.TABLES["B"])
            self.assertEqual(a, b)
        self.assertEqual(IMAGE.relative[0x6485ef8 + 8 * 0x01], 0x432d0e0)
        self.assertEqual(IMAGE.relative[0x649eea0 + 8 * 0x01], 0x546a5a0)

    def test_mismatching_tables_are_rejected(self):
        saved = tool.TABLES["B"]
        tool.TABLES["B"] = (0x6485ef8, 0x649eea0)
        try:
            with self.assertRaises(tool.ToolError):
                tool.handler_of(IMAGE, "B", 0x01)
        finally:
            tool.TABLES["B"] = saved

    def test_out_of_text_address_rejected(self):
        with self.assertRaises(tool.ToolError):
            IMAGE.code(IMAGE.text["address"] + IMAGE.text["size"] + 0x100, 4)


class ModelTests(unittest.TestCase):
    def apply(self, op, top, second=0, third=0, spec=20):
        return tool.apply_op(op, [top, second, third], spec)

    def test_arithmetic_edges(self):
        self.assertEqual(self.apply(1, M, 1), 0)
        self.assertEqual(self.apply(3, 0, 1), M)
        self.assertEqual(self.apply(4, 7, 0), 0)
        self.assertEqual(self.apply(5, 1 << 255, M), 1 << 255)
        self.assertEqual(self.apply(5, M - 6, 2), M - 2)  # -7 / 2 = -3 (truncation)
        self.assertEqual(self.apply(7, M - 6, 3), M)  # -7 % 3 = -1
        self.assertEqual(self.apply(8, M, 2, 3), 2)
        self.assertEqual(self.apply(9, M, M, 7), pow(M, 2, 7))
        self.assertEqual(self.apply(0x0a, 2, 256), 0)
        self.assertEqual(self.apply(0x0b, 0, 0x80), M - 0x7f)
        self.assertEqual(self.apply(0x0b, 31, 0x80), 0x80)

    def test_bitwise_edges(self):
        self.assertEqual(self.apply(0x1a, 31, 0xab), 0xab)
        self.assertEqual(self.apply(0x1a, 32, 0xab), 0)
        self.assertEqual(self.apply(0x1b, 255, 1), 1 << 255)
        self.assertEqual(self.apply(0x1b, 256, 1), 0)
        self.assertEqual(self.apply(0x1d, 300, 1 << 255), M)
        self.assertEqual(self.apply(0x1d, 1, M), M)
        self.assertEqual(self.apply(0x1e, 0), 256)
        self.assertEqual(self.apply(0x1e, M), 0)

    def test_gates_and_underflow(self):
        self.assertEqual(tool.model(case(0x1b, [1, 1], spec=4))[0], tool.R_NOT_ACTIVATED)
        self.assertEqual(tool.model(case(0x1b, [1, 1], spec=5))[0], tool.R_OK)
        self.assertEqual(tool.model(case(0x1e, [1], spec=12))[0], tool.R_NOT_ACTIVATED)
        self.assertEqual(tool.model(case(0x1e, [1], spec=13))[0], tool.R_OK)
        self.assertEqual(tool.model(case(0x01, [1]))[0], tool.R_UNDERFLOW)
        self.assertEqual(tool.model(case(0x08, [1, 2]))[0], tool.R_UNDERFLOW)
        self.assertEqual(tool.model(case(0x15, []))[0], tool.R_UNDERFLOW)

    def test_exp_gas(self):
        self.assertEqual(tool.exp_cost(0, 50), 0)
        self.assertEqual(tool.exp_cost(0xff, 50), 50)
        self.assertEqual(tool.exp_cost(0x100, 50), 100)
        self.assertEqual(tool.model(case(0x0a, [0x100, 2], gas=99))[0], tool.R_OOG)
        self.assertEqual(tool.model(case(0x0a, [0x100, 2], gas=100))[3], 0)


class MachineCodeTests(unittest.TestCase):
    def test_every_family_runs_add(self):
        for fam in ("B", "C"):
            c = case(0x01, [M, 2], fam=fam)
            got = run(c)
            self.assertEqual(got["ret"], ("ret", 0))
            self.assertEqual(result_word(got, c), 1)
            self.assertTrue(tool.compare(c, tool.model(c), got))

    def test_division_by_zero_and_sdiv_overflow(self):
        for op, stack, want in ((4, [0, 5], 0), (5, [M, 1 << 255], 1 << 255), (6, [0, 9], 0), (7, [3, M - 6], M)):
            c = case(op, stack)
            got = run(c)
            self.assertEqual(result_word(got, c), want, hex(op))
            self.assertTrue(tool.compare(c, tool.model(c), got))

    def test_exp_out_of_gas_pops_but_keeps_words(self):
        c = case(0x0a, [0x100, 3], gas=99)
        got = run(c)
        self.assertEqual(got["ret"], ("ret", tool.R_OOG))
        self.assertEqual(got["n"], 1)
        self.assertEqual(got["gas"], 99)
        self.assertTrue(tool.compare(c, tool.model(c), got))

    def test_shift_gate_and_clz(self):
        c = case(0x1b, [1, 1], spec=4)
        self.assertEqual(run(c)["ret"], ("ret", tool.R_NOT_ACTIVATED))
        c = case(0x1e, [1], spec=13)
        got = run(c)
        self.assertEqual(result_word(got, c), 255)

    def test_wrong_model_is_detected(self):
        c = case(0x03, [1, 2])
        got = run(c)
        self.assertTrue(tool.compare(c, tool.model(c), got))
        self.assertFalse(tool.compare(c, tool.model(c, frozenset(["swap_operands"])), got))

    def test_corrupted_code_is_detected(self):
        h = HANDLERS[("B", 0x01)]
        cases = [case(0x01, [1, 2]), case(0x01, [1])]
        self.assertFalse(tool.detects(IMAGE, h, cases))
        # change the underflow result code 0x2c (mov $0x2c,%al) of ADD
        at = next(a for a in range(h, h + 0x50) if IMAGE.code(a, 2) == b"\xb0\x2c") + 1
        self.assertTrue(tool.detects(IMAGE, h, cases, override={at: 0x2d}))

    def test_unknown_instruction_is_an_error_not_a_pass(self):
        h = HANDLERS[("B", 0x01)]
        c = case(0x01, [1, 2])
        m = tool.XMachine(IMAGE, {h: 0x0f, h + 1: 0xff})  # ud0-like bytes: unsupported
        with self.assertRaises(tool.ToolError):
            tool.run_case(m, IMAGE, c, h)


class OutputTests(unittest.TestCase):
    def test_byte_mutants_are_derived_from_decoded_handlers(self):
        decoded, info = tool.static_rows(IMAGE, HANDLERS)
        rows = tool.byte_mutants(IMAGE, HANDLERS, decoded)
        self.assertGreater(len(rows), 100)
        for fam, op, at, byte, what in rows:
            self.assertNotEqual(IMAGE.code(at, 1)[0], byte)
        self.assertEqual(info[HANDLERS[("B", 0x1b)]]["gate"], 5)
        self.assertEqual(info[HANDLERS[("C", 0x1e)]]["gate"], 13)

    def test_cases_are_deterministic(self):
        a = tool.cases_for("B", 0x0a)
        b = tool.cases_for("B", 0x0a)
        self.assertEqual(a, b)
        self.assertEqual(len(a), tool.COUNTS[0x0a])


if __name__ == "__main__":
    unittest.main()
