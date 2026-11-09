"""Tests for tools/evm_stack_memory_opcodes_115.py (node #115 stack, memory, jump and environment opcode handlers).

The binary must be present; nothing here is skipped. The tool never executes the binary.
"""
import hashlib
import pathlib
import random
import shutil
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import evm_stack_memory_opcodes_115 as t  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "evm-stack-memory-opcodes-115"
GENERATED = ("cases.tsv", "controls.tsv", "equivalent-mutants.tsv", "handlers.tsv", "measure.json", "slots.tsv")


class Shared:
    image = None
    machine = None
    rows = None

    @classmethod
    def load(cls):
        if cls.image is None:
            data = t.BINARY.read_bytes()
            assert hashlib.sha256(data).hexdigest() == t.SHA256
            cls.image = t.base.Image(data)
            cls.machine = t.Machine(cls.image)
            cls.rows = t.static_rows(cls.image)
        return cls


def blank(op, **over):
    rng = random.Random(7)
    c = t.base_case(rng, op, 0, "B1")
    c.update(over)
    return c


def put_words(c, items):
    t.stack_set(c, items)
    return c


class ModelTests(unittest.TestCase):
    """Hand-checked EVM semantics of the reconstruction itself."""

    def test_push_reads_big_endian_and_advances_pc(self):
        code = bytes([0x12, 0x34]) + bytes(0x1fe)
        c = blank(0x61, code=code, pcoff=0, pc=t.CODE, len=3)
        want = t.model(c)
        self.assertEqual(want["ret"], 0)
        self.assertEqual(want["len"], 4)
        self.assertEqual(int.from_bytes(want["stack"][96:128], "little"), 0x1234)
        self.assertEqual(want["pc"], t.CODE + 2)

    def test_push_overflow_boundary(self):
        self.assertEqual(t.model(blank(0x60, len=0x3ff))["ret"], 0)
        self.assertEqual(t.model(blank(0x60, len=0x400))["ret"], 0x2d)
        self.assertEqual(t.model(blank(0x60, len=0x401))["ret"], 0x2d)

    def test_push0_needs_spec_ten(self):
        self.assertEqual(t.model(blank(0x5f, spec=9, len=0))["ret"], 0x2b)
        self.assertEqual(t.model(blank(0x5f, spec=10, len=0))["ret"], 0)

    def test_dup_and_swap_stack_effect(self):
        c = put_words(blank(0x82, len=3), {0: 11, 1: 22, 2: 33})
        want = t.model(c)
        self.assertEqual(want["len"], 4)
        self.assertEqual(int.from_bytes(want["stack"][96:128], "little"), 11)
        self.assertEqual(t.model(blank(0x82, len=2))["ret"], 0x2d)
        c = put_words(blank(0x91, len=3), {0: 11, 1: 22, 2: 33})
        want = t.model(c)
        self.assertEqual([int.from_bytes(want["stack"][32 * i:32 * i + 32], "little") for i in range(3)], [33, 22, 11])
        self.assertEqual(t.model(blank(0x91, len=2))["ret"], 0x2c)

    def test_jump_uses_bitmap_and_code_length(self):
        bitmap = bytes([0b0000_0100]) + bytes(0xff)
        c = put_words(blank(0x56, len=1, ana_len=16, bitmap=bitmap, start=t.CODE), {0: 2})
        want = t.model(c)
        self.assertEqual((want["ret"], want["len"], want["pc"]), (0, 0, t.CODE + 2))
        for dest in (3, 16, 1 << 64):
            c = put_words(blank(0x56, len=1, ana_len=16, bitmap=bitmap, start=t.CODE), {0: dest})
            self.assertEqual(t.model(c)["ret"], 0x2a, dest)

    def test_jumpi_pops_two_and_skips_target_check_when_not_taken(self):
        bitmap = bytes(0x100)
        c = put_words(blank(0x57, len=2, ana_len=16, bitmap=bitmap), {1: 5, 0: 0})
        want = t.model(c)
        self.assertEqual((want["ret"], want["len"]), (0, 0))
        c = put_words(blank(0x57, len=2, ana_len=16, bitmap=bitmap), {1: 5, 0: 1})
        self.assertEqual(t.model(c)["ret"], 0x2a)
        self.assertEqual(t.model(blank(0x57, len=1))["ret"], 0x2c)

    def test_pc_pushes_offset_before_the_opcode(self):
        c = blank(0x58, len=0, start=t.CODE, pc=t.CODE + 10)
        self.assertEqual(int.from_bytes(t.model(c)["stack"][:32], "little"), 9)
        c = blank(0x58, len=0, start=t.CODE, pc=t.CODE)
        self.assertEqual(t.model(c)["boundary"], ("panic", 0x6486ac8))
        self.assertEqual(t.model(dict(c, table="C"))["boundary"], ("panic", 0x64a9d28))

    def test_mstore_then_mload_round_trip(self):
        c = put_words(blank(0x52, len=2, words=0, base=32, borrow=0), {1: 64, 0: 0xAABBCC})
        want = t.model(c)
        self.assertEqual(want["events"], [("expand", 3)])
        self.assertEqual(want["words"], 3)
        self.assertEqual(want["mem"][96:128], (0xAABBCC).to_bytes(32, "big"))
        self.assertEqual(want["borrow"], 0)
        c2 = put_words(blank(0x51, len=1, words=3, base=32, buf=want["mem"]), {0: 64})
        self.assertEqual(int.from_bytes(t.model(c2)["stack"][:32], "little"), 0xAABBCC)

    def test_mstore8_writes_low_byte(self):
        c = put_words(blank(0x53, len=2, words=1, base=0), {1: 5, 0: 0x1ff})
        want = t.model(c)
        self.assertEqual(want["mem"][5], 0xff)
        self.assertEqual(want["mem"][4], c["buf"][4])

    def test_mload_rejects_wide_offset_and_pop_order(self):
        c = put_words(blank(0x51, len=1), {0: 1 << 64})
        self.assertEqual(t.model(c)["ret"], 0x24)
        c = put_words(blank(0x52, len=2), {1: 1 << 64, 0: 1})
        want = t.model(c)
        self.assertEqual((want["ret"], want["len"]), (0x24, 0))

    def test_expansion_failure_is_reported(self):
        c = put_words(blank(0x51, len=1, words=0), {0: 400 * 32})
        want = t.model(c)
        self.assertEqual(want["ret"], t.EXPAND_FAIL)
        self.assertEqual(want["events"], [("expand", 401)])

    def test_environment_fields(self):
        host = bytearray(0x400)
        host[0x258:0x260] = (4242).to_bytes(8, "little")
        c = blank(0x46, spec=5, host=bytes(host), len=0)
        self.assertEqual(t.model(c)["ret"], 0x2b)
        c = blank(0x46, spec=6, host=bytes(host), len=0)
        self.assertEqual(int.from_bytes(t.model(c)["stack"][:32], "little"), 4242)
        interp = bytearray(0x400)
        interp[0x78:0x8c] = bytes(range(1, 21))
        c = blank(0x30, interp=bytes(interp), len=0)
        self.assertEqual(int.from_bytes(t.model(c)["stack"][:32], "little"), int.from_bytes(bytes(range(1, 21)), "big"))

    def test_status_only_opcodes(self):
        self.assertEqual(t.model(blank(0x00))["ret"], 1)
        self.assertEqual(t.model(blank(0xfe))["ret"], 0x29)
        self.assertEqual(t.model(blank(0x4c))["ret"], 0x26)

    def test_unknown_opcode_is_rejected(self):
        with self.assertRaises(t.ToolError):
            t.model(blank(0xf0))


class EvaluatorTests(unittest.TestCase):
    def test_extended_decoder_forms(self):
        bt = t.decode(bytes.fromhex("440fa3c6") + bytes(12), 0)
        self.assertEqual((bt["op"], bt["len"]), (0x0fa3, 4))
        por = t.decode(bytes.fromhex("660febc1") + bytes(12), 0)
        self.assertEqual((por["op"], por["len"]), (0x0feb, 4))
        mov = t.decode(bytes.fromhex("440f50c1") + bytes(12), 0)
        self.assertEqual((mov["op"], mov["len"]), (0x0f50, 4))

    def test_bt_sets_carry_from_bit_index(self):
        Shared.load()
        m = t.Machine(Shared.image)
        m.reset()
        m.regs[6], m.regs[8] = 0b100, 2
        form = t.decode(bytes.fromhex("440fa3c6") + bytes(12), 0)
        m.cache[0] = form
        m.step(0)
        self.assertTrue(m.cf)
        m.regs[8] = 3
        m.step(0)
        self.assertFalse(m.cf)

    def test_sbb_immediate_uses_carry(self):
        Shared.load()
        m = t.Machine(Shared.image)
        m.reset()
        m.regs[1], m.cf = 5, True
        m.cache[0] = t.decode(bytes.fromhex("4883d9ff") + bytes(12), 0)  # sbb $-1,%rcx
        m.step(0)
        self.assertEqual(m.regs[1], 5 + 1 - 1)


class BinaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Shared.load()

    def test_hash_gate(self):
        with self.assertRaises(t.ToolError):
            t.base.Image(Shared.image.data[:-1] + bytes([Shared.image.data[-1] ^ 1]))

    def test_table_slots_for_known_opcodes(self):
        table = t.handler_table(Shared.image)
        self.assertEqual(table[0x60]["B1"], 0x43325e0)
        self.assertEqual(table[0x60]["B1"], table[0x60]["B2"])
        self.assertEqual(table[0x60]["C"], 0x50b5790)
        self.assertEqual(table[0x56]["C"], 0x546c1d0)
        self.assertEqual(table[0x51]["B1"], 0x4333850)

    def test_handler_set_is_complete_and_unique(self):
        rows = Shared.rows
        self.assertEqual(len(rows), 186)
        self.assertEqual(sum(len(r[2]) for r in rows), 279)
        ops = {o for r in rows for _, o in r[2]}
        self.assertEqual(ops, set(t.OPS))

    def test_every_handler_matches_the_model(self):
        total = 0
        for addr, size, slots, calls in Shared.rows:
            n, det = t.sweep_handler(Shared.machine, Shared.image, addr, slots[0][1], slots[0][0], scale=0.2)
            self.assertFalse(det, hex(addr))
            total += n
        self.assertGreater(total, 2000)

    def test_c_family_uses_its_own_panic_messages(self):
        addr, _, table = t.handler_of(Shared.rows, 0x58, ("C",))
        self.assertEqual(table, "C")
        case = blank(0x58, len=0, start=t.CODE, pc=t.CODE, table="C")
        got = t.run_case(Shared.machine, Shared.image, addr, case, None)
        self.assertEqual(got["boundary"], ("panic", 0x64a9d28))

    def test_mutants_are_detected(self):
        for name, op in (("push_limit", 0x60), ("jump_no_bitmap", 0x56), ("mload_little", 0x51),
                         ("mstore8_end_off", 0x53), ("jumpi_inverted", 0x57), ("swap_wrong_index", 0x93)):
            addr, _, table = t.handler_of(Shared.rows, op, ("B1",))
            n, det = t.sweep_handler(Shared.machine, Shared.image, addr, op, table, mut=frozenset([name]))
            self.assertTrue(det, name)

    def test_corrupted_code_byte_is_detected(self):
        addr, size, table = t.handler_of(Shared.rows, 0x80, ("B1",))
        insns = t.base.sweep(Shared.image, addr, addr + size)
        va, form = insns[1]  # cmp against the stack depth limit
        where = va + form["len"] - 1
        old = Shared.image.code(where, 1)[0]
        n, det = t.sweep_handler(Shared.machine, Shared.image, addr, 0x80, table, override={where: old ^ 1})
        self.assertTrue(det)

    def test_wrong_handler_address_is_detected(self):
        a, _, table = t.handler_of(Shared.rows, 0x80, ("B1",))
        b, _, _ = t.handler_of(Shared.rows, 0x81, ("B1",))
        n, det = t.sweep_handler(Shared.machine, Shared.image, a, 0x80, table, run_addr=b)
        self.assertTrue(det)

    def test_all_negative_controls_are_accounted_for(self):
        ctl = t.run_controls(Shared.image, Shared.machine, Shared.rows)
        self.assertGreaterEqual(len(ctl), 30)
        self.assertTrue(all(r[5] in ("detected", "equivalent") for r in ctl))


class PacketTests(unittest.TestCase):
    def test_generated_files_match_packet(self):
        if not PACKET.exists():
            self.fail("evidence folder is missing")
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "out"
            measure = t.generate(out)
            self.assertEqual(measure["mismatches"], 0)
            self.assertEqual(measure["negative_detected"] + measure["equivalent"], measure["negative_controls"])
            for name in GENERATED:
                self.assertEqual((out / name).read_bytes(), (PACKET / name).read_bytes(), name)

    def test_manifest_lists_every_file(self):
        listed = {}
        for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ", 1)
            listed[name] = digest
        files = sorted(p.name for p in PACKET.iterdir() if p.name != "MANIFEST.sha256")
        self.assertEqual(sorted(listed), files)
        for name in files:
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), listed[name], name)


if __name__ == "__main__":
    unittest.main()
