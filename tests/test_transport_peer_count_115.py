import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import transport_peer_count_115 as tool  # noqa: E402


class PeerCountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.subject = tool.Subject(cls.image)
        cls.cases = list(tool.case_stream(400))

    def fixed(self, variant, entries, members, state=0, **kw):
        case = tool.Case(variant, entries, members, state, **kw)
        return case, tool.run_case(self.subject, case, 1)

    def test_binary_digest_is_checked(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(tool.BINARY, "00" * 32)

    def test_bodies_decode_to_exact_ends(self):
        self.assertEqual(len(self.subject.count), 252)
        self.assertEqual(len(self.subject.step), 126)
        last = max(self.subject.count)
        self.assertEqual(self.subject.count[last].next, tool.COUNT_FN[1])
        with self.assertRaises(tool.EvidenceError):
            tool.decode_range(self.image, tool.COUNT_FN[0], tool.COUNT_FN[1] - 1)

    def test_reader_lock_word_and_wake(self):
        # one reader plus a waiter flag: the release sees 0x12 and asks for one wake
        case, out = self.fixed("deque", [], [], 0x02, cap=1)
        self.assertEqual(out.key(), ("return", 0, (("wake", tool.ARC + 0x10),)))
        case, out = self.fixed("deque", [], [], 0x10, cap=1)
        self.assertEqual(out.key(), ("return", 0, ()))
        # a writer bit forces the slow path and the call stops there with the documented arguments
        case, out = self.fixed("deque", [], [], 0x08, cap=1)
        self.assertEqual(out.key(), ("slow-lock", 0, (("slow", tool.ARC + 0x10, 0, 1000000000),)))

    def test_counts_entries_missing_from_the_member_set(self):
        a, b, c = b"\x00\x00\x00\x01", b"\x01\x00\x00\x00", b"\xff\xff\xff\xff"
        _, out = self.fixed("deque", [a, b, c, a], [b], 0x10, cap=6, head=4)
        self.assertEqual(out.value, 3)
        _, out = self.fixed("map", [], [a, c], 0x10, map_keys=[a, b, c])
        self.assertEqual(out.value, 1)
        _, out = self.fixed("map", [], [], 0x10, map_keys=[a, b, c])
        self.assertEqual(out.value, 3)

    def test_byte_order_of_the_member_search(self):
        # 0x01000000 and 0x00000001 differ only in word order; a little endian member set must not match
        _, out = self.fixed("deque", [b"\x01\x00\x00\x00"], [b"\x00\x00\x00\x01"], 0x10, cap=2)
        self.assertEqual(out.value, 1)
        _, out = self.fixed("deque", [b"\x01\x00\x00\x00"], [b"\x01\x00\x00\x00"], 0x10, cap=2)
        self.assertEqual(out.value, 0)

    def test_wrapped_deque_and_head_beyond_capacity(self):
        keys = [bytes([i, 0, 0, 0]) for i in range(1, 6)]
        _, out = self.fixed("deque", keys, keys[:2], 0x10, cap=6, head=4)
        self.assertEqual(out.value, 3)
        _, out = self.fixed("deque", keys, keys[:2], 0x10, cap=6, head=9)
        self.assertEqual(out.value, 3)

    def test_tall_btree_walk(self):
        case = [c for c in self.cases if c.tall == 8][0]
        out = tool.run_case(self.subject, case, 4)
        self.assertEqual(out.key(), tool.spec(case))
        self.assertGreater(out.steps, 20000)

    def test_cases_match_rule_list(self):
        result = tool.verify_stream(self.subject, self.cases)
        self.assertEqual(result["checked"], 400)
        self.assertEqual(result["mismatches"], 0)
        self.assertEqual(set(result["kinds"]), {"return", "slow-lock"})

    def test_every_wrong_rule_list_is_caught(self):
        for flaw in tool.SPEC_FLAWS:
            caught = False
            for index, case in enumerate(self.cases):
                got = tool.run_case(self.subject, case, index)
                if tool.spec(case, flaw) != got.key():
                    caught = True
                    break
            self.assertTrue(caught, flaw)

    def test_edited_bytes_are_caught(self):
        budgets = [tool.run_case(self.subject, c, i).steps for i, c in enumerate(self.cases)]
        flips = list(tool.flip_patches(self.subject))
        erases = list(tool.erase_patches(self.subject))
        self.assertGreaterEqual(len(flips), 40)
        self.assertEqual(len(erases), 2)
        for label, patch in flips[:6] + erases:
            mutant = tool.Subject(self.image, patch)
            result = tool.verify_stream(mutant, self.cases, stop_first=True, budgets=budgets)
            self.assertGreater(result["mismatches"], 0, label)

    def test_boundaries_are_refused(self):
        for label, refused in tool.boundary_controls(self.image):
            self.assertTrue(refused, label)

    def test_unknown_import_is_a_fault(self):
        self.subject.machine.fresh()
        with self.assertRaises(tool.Fault):
            self.subject.machine.step_import(0x64E0000)

    def test_memory_and_tree_builders(self):
        keys = [i.to_bytes(4, "big") for i in range(1, 60)]
        rng = tool.lcg(5)
        root = tool.build_tree(keys, tool.pick_height(len(keys)), rng)
        order = []

        def walk(node):
            for j, child in enumerate(node.children):
                walk(child)
                if j < len(node.keys):
                    order.append(node.keys[j])
            if not node.children:
                order.extend(node.keys)

        walk(root)
        self.assertEqual(order, keys)
        with self.assertRaises(tool.Fault):
            tool.Memory().read(0x1000, 4)


class DecoderAndMachineTests(unittest.TestCase):
    def one(self, raw):
        return tool.decode(bytes(raw) + bytes(16), 0, 0)

    def machine(self):
        m = tool.Machine(None, None)
        m.fresh()
        return m

    def test_decoder_forms_used_by_the_bodies(self):
        row = self.one([0xF0, 0x48, 0x0F, 0xB1, 0x0A])
        self.assertEqual((row.op, row.lock, row.size), ("cmpxchg", True, 5))
        row = self.one([0x41, 0x0F, 0xC8 | 1])
        self.assertEqual((row.op, row.width), ("bswap", 4))
        row = self.one([0x48, 0xF7, 0xD9])
        self.assertEqual(row.op, "neg")
        row = self.one([0x0F, 0x1F, 0x44, 0x00, 0x00])
        self.assertEqual((row.op, row.size), ("nop", 5))
        row = self.one([0x75, 0xFE])
        self.assertEqual((row.op, row.cc, row.target), ("jcc", "ne", 0))
        row = self.one([0x48, 0x05, 0xF0, 0, 0, 0])
        self.assertEqual((row.op, row.a, row.b), ("add", ("r", 0), ("i", 0xF0)))

    def test_decoder_refuses_unknown_forms(self):
        for raw in ([0x0F, 0xA2], [0xF7, 0xD0], [0xFF, 0xE0], [0x06]):
            with self.assertRaises(tool.EvidenceError):
                self.one(raw)

    def test_flags_of_subtract_and_borrow(self):
        m = self.machine()
        self.assertEqual(m.alu("sub", 1, 2, 4), 0xFFFFFFFF)
        self.assertEqual((m.f["c"], m.f["s"], m.f["z"], m.f["o"]), (1, 1, 0, 0))
        self.assertEqual(m.alu("sbb", 5, 5, 8), 0xFFFFFFFFFFFFFFFF)
        m.alu("cmp", 0x8000000000000000, 1, 8)
        self.assertEqual(m.f["o"], 1)
        self.assertTrue(m.cond("g") is False and m.cond("a"))

    def test_negate_sets_overflow_only_for_the_niche(self):
        m = self.machine()
        m.alu("sub", 0, tool.NICHE, 8)
        self.assertEqual(m.f["o"], 1)
        m.alu("sub", 0, 5, 8)
        self.assertEqual(m.f["o"], 0)

    def test_locked_exchange_add_and_compare_exchange(self):
        m = self.machine()
        m.mem.map(0x1000, 16)
        m.mem.put(0x1000, 0x30, 8)
        m.regs[1] = 0xFFFFFFFFFFFFFFF0
        row = tool.Insn(0, 5, "xadd", a=("m", None, None, 1, 0x1000), b=("r", 1), width=8, lock=True)
        m.step(row)
        self.assertEqual((m.mem.u(0x1000, 8), m.regs[1]), (0x20, 0x30))
        m.regs[0], m.regs[2] = 0x20, 0x99
        row = tool.Insn(0, 5, "cmpxchg", a=("m", None, None, 1, 0x1000), b=("r", 2), width=8, lock=True)
        m.step(row)
        self.assertEqual(m.mem.u(0x1000, 8), 0x99)
        m.regs[0] = 1
        m.step(row)
        self.assertEqual((m.regs[0], m.f["z"]), (0x99, 0))

    def test_partial_register_writes_keep_upper_bits(self):
        m = self.machine()
        m.regs[2] = 0x1122334455667788
        m.put(("r", 2), 0xAB, 1, None)
        self.assertEqual(m.regs[2], 0x11223344556677AB)
        m.put(("r", 2), 0xCDEF, 2, None)
        self.assertEqual(m.regs[2], 0x112233445566CDEF)
        m.put(("r", 2), 0x1, 4, None)
        self.assertEqual(m.regs[2], 1)

    def test_memory_faults_and_stack(self):
        m = self.machine()
        m.push(0xDEADBEEF)
        self.assertEqual(m.pop(), 0xDEADBEEF)
        with self.assertRaises(tool.Fault):
            m.mem.put(0x10, 1, 8)
        m.mem.map(0x2000 - 4, 8)
        m.mem.put(0x2000 - 4, 0x0102030405060708, 8)
        self.assertEqual(m.mem.read(0x2000 - 4, 8), bytes([8, 7, 6, 5, 4, 3, 2, 1]))


if __name__ == "__main__":
    unittest.main()
