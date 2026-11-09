import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("evm_log_opcodes_115", ROOT / "tools" / "evm_log_opcodes_115.py")
tool = importlib.util.module_from_spec(spec)
sys.modules["evm_log_opcodes_115"] = tool
spec.loader.exec_module(tool)


def literal(n=1, fam="AB", **over):
    """A hand-written case: 4 memory words at base 0, plenty of gas, schedule 8 / 375 / 3 / 512."""
    c = {"k": -1, "n": n, "fam": fam, "mode": -1, "odd": 0, "base": 0, "mem_words": 4, "cell_len": 128, "cell_cap": 4096,
         "flag": 0, "static": 0, "addr": bytes(range(1, 21)), "c30": 8, "c38": 375, "c50": 3, "c58": 512,
         "log_cap": 4, "log_len": 1, "alloc_fail": 0, "offset": 0, "length": 0, "gas": 100000,
         "membuf": bytes(range(128)), "stack": []}
    c.update(over)
    c["mem_cost"] = tool.mem_cost(c["mem_words"], c["c50"], c["c58"])
    return c


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.Image(tool.BINARY.read_bytes())
        cls.ext = tool.extents(cls.image)
        cls.sh = tool.Shell(cls.image, tool.Machine(cls.image))

    def real(self, c):
        return tool.run_handler(self.sh, c, tool.HANDLERS[c["fam"]][c["n"]])

    def both(self, c):
        got, want = self.real(c), tool.model_handler(c, self.sh)
        self.assertEqual(tool.diff(got, want), [])
        return got


class StaticEvidence(Fixture):
    def test_tables_extents_and_constants(self):
        tool.static_checks(self.image, self.ext)

    def test_log_slots_are_shared_by_tables_a_and_b(self):
        for i in range(5):
            self.assertEqual(self.image.word(tool.TABLES["A"] + 8 * (0xa0 + i)),
                             self.image.word(tool.TABLES["B"] + 8 * (0xa0 + i)))
            self.assertNotEqual(self.image.word(tool.TABLES["C"] + 8 * (0xa0 + i)),
                                self.image.word(tool.TABLES["A"] + 8 * (0xa0 + i)))

    def test_every_function_decodes_linearly(self):
        for f in tool.ALL_FUNCS:
            rows = tool.sweep(self.image, f, self.ext[f])
            self.assertEqual(sum(fm["len"] for _, fm in rows), self.ext[f] - f)

    def test_wrong_slot_is_refused(self):
        bad = dict(tool.HANDLERS)
        saved = tool.HANDLERS["AB"]
        tool.HANDLERS["AB"] = (saved[1],) + saved[1:]
        try:
            with self.assertRaises(tool.ToolError):
                tool.static_checks(self.image, self.ext)
        finally:
            tool.HANDLERS["AB"] = saved


class Scenarios(Fixture):
    def test_log0_empty_data_records_static_vtable(self):
        got = self.both(literal(0, stack=[0, 0], gas=1000))
        self.assertEqual(got["status"], 0)
        self.assertEqual(got["gas"], 1000)
        self.assertEqual(got["log_len"], 2)

    def test_log2_charges_length_and_topics(self):
        c = literal(2, stack=[7, 9, 10, 3], gas=5000)  # offset 3, length 10, topics 9 then 7
        got = self.both(c)
        self.assertEqual(got["gas"], 5000 - 10 * 8 - 2 * 375)
        self.assertEqual(got["status"], 0)

    def test_topics_are_big_endian(self):
        c = literal(1, stack=[0x0102030405060708090a0b0c0d0e0f10 << 128, 4, 0])
        got = self.both(c)
        heap_topic = (0x0102030405060708090a0b0c0d0e0f10 << 128).to_bytes(32, "big")
        s = tool.fresh_state(c, self.sh)
        tool.log_model(1, "AB", s)
        self.assertEqual(bytes(s["alloc_mem"][16:48]), heap_topic)
        self.assertEqual(got["status"], 0)

    def test_static_call_refused_before_the_stack_is_read(self):
        got = self.both(literal(3, static=1, stack=[]))
        self.assertEqual(got["status"], tool.RET_STATIC)

    def test_underflow_codes(self):
        self.assertEqual(self.both(literal(1, stack=[5]))["status"], tool.RET_UNDERFLOW)
        self.assertEqual(self.both(literal(4, stack=[1, 2, 4, 0], gas=9999))["status"], tool.RET_UNDERFLOW)

    def test_wide_length_is_value_too_big(self):
        self.assertEqual(self.both(literal(0, stack=[1 << 64, 0]))["status"], tool.RET_BIG)

    def test_gas_edge(self):
        need = 5 * 8 + 375
        self.assertEqual(self.both(literal(1, stack=[1, 5, 0], gas=need))["status"], 0)
        self.assertEqual(self.both(literal(1, stack=[1, 5, 0], gas=need - 1))["status"], tool.RET_GAS)

    def test_memory_expansion_charge(self):
        c = literal(0, stack=[200, 40], mem_words=0, cell_len=0, membuf=b"", gas=10000)  # words 8
        got = self.both(c)
        self.assertEqual(got["words"], 8)
        self.assertEqual(got["cost"], tool.mem_cost(8, 3, 512))
        self.assertEqual(got["cell_len"], 256)

    def test_memory_out_of_gas_still_stores_the_new_size(self):
        c = literal(0, stack=[200, 40], mem_words=0, cell_len=0, membuf=b"", gas=200 * 8 + 5)
        got = self.both(c)
        self.assertEqual(got["status"], tool.RET_MEMGAS)
        self.assertEqual(got["words"], 8)

    def test_family_c_matches_family_ab(self):
        for n in range(5):
            a = self.both(literal(n, "AB", stack=[3, 7, 11, 1, 2][:n] + [4, 2]))
            b = self.both(literal(n, "C", stack=[3, 7, 11, 1, 2][:n] + [4, 2]))
            self.assertEqual(a["status"], b["status"])
            self.assertEqual(a["gas"], b["gas"])

    def test_log_vector_grows_when_full(self):
        got = self.both(literal(0, stack=[0, 0], log_cap=2, log_len=2))
        self.assertEqual(got["log_cap"], 4)
        self.assertEqual(got["events"][-1][0], "grow")

    def test_allocation_failure_is_reported(self):
        got = self.both(literal(1, stack=[1, 5, 0], alloc_fail=1))
        self.assertEqual(got["status"], ("alloc", 5))


class Sampled(Fixture):
    def test_sample_of_generated_cases(self):
        for k in range(0, 600, 3):
            c = tool.make_case(k, self.sh)
            self.assertEqual(tool.diff(self.real(c), tool.model_handler(c, self.sh)), [], f"case {k}")

    def test_sample_of_resize_cases(self):
        for k in range(0, 400, 2):
            c = tool.make_resize_case(k, self.sh)
            got = tool.run_resize(self.sh, c, c["words"])
            self.assertEqual(tool.diff(got, tool.model_resize(c, self.sh, c["words"])), [], f"resize {k}")

    def test_every_handler_and_status_class_is_reached(self):
        seen = set()
        for k in range(0, 800):
            c = tool.make_case(k, self.sh)
            got = self.real(c)
            seen.add((c["fam"], c["n"], got["status"] if isinstance(got["status"], int) else got["status"][0]))
        for fam in ("AB", "C"):
            for n in range(5):
                for status in (0, tool.RET_STATIC, tool.RET_UNDERFLOW, tool.RET_GAS):
                    self.assertIn((fam, n, status), seen)


class NegativeControls(Fixture):
    def digests(self, cases, mut=frozenset()):
        return [tool.digest(tool.model_handler(c, self.sh, mut)) for c in cases]

    def test_each_model_mutant_class_is_caught(self):
        cases = [tool.make_case(k, self.sh) for k in range(900)]
        real = [tool.digest(self.real(c)) for c in cases]
        for name in ("topics_reversed", "words_floor", "gas_le", "drop_missing", "flag_not_restored", "vt_swapped"):
            self.assertNotEqual(self.digests(cases, frozenset((name,))), real, name)
        self.assertEqual(self.digests(cases), real)

    def test_corrupt_status_immediate_is_caught(self):
        f = tool.HANDLERS["AB"][0]
        rows = tool.sweep(self.image, f, self.ext[f])
        va, fm = next((v, x) for v, x in rows if 0xb0 <= x["op"] <= 0xb7 and x["imm"] == 0x2c)
        mach = tool.Machine(self.image)
        shm = tool.Shell(self.image, mach)
        c = literal(0, stack=[5], gas=100)
        good = tool.run_handler(shm, c, f)
        mach.cache = {}
        bad = tool.run_handler(shm, c, f, override={va + 1: 0x24})
        self.assertNotEqual(tool.digest(good), tool.digest(bad))

    def test_corrupted_binary_digest_is_refused(self):
        with self.assertRaises(tool.ToolError):
            tool.Image(self.image.data[:-1] + bytes([self.image.data[-1] ^ 1]))

    def test_non_function_start_is_refused(self):
        with self.assertRaises(tool.ToolError):
            tool.fde_rows(self.image, {tool.HANDLERS["AB"][0] + 1})

    def test_out_of_range_read_is_refused(self):
        with self.assertRaises(tool.ToolError):
            self.image.read(0x10, 8)

    def test_code_outside_text_is_refused(self):
        with self.assertRaises(tool.ToolError):
            self.image.code(0x10, 4)

    def test_wrong_model_constants_are_caught(self):
        saved = tool.EMPTY_VT["AB"]
        tool.EMPTY_VT["AB"] = saved + 8
        try:
            c = literal(0, stack=[0, 0])
            self.assertNotEqual(tool.diff(self.real(c), tool.model_handler(c, self.sh)), [])
        finally:
            tool.EMPTY_VT["AB"] = saved


if __name__ == "__main__":
    unittest.main()
