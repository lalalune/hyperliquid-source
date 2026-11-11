import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_journal115 as j  # noqa: E402


class Journal115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = j.Image(j.BINARY.read_bytes())
        cls.rev = j.pool("rev", j.REVERT[0], 400)
        cls.wr = j.pool("wr", j.WRITE[0], 600)

    def rev_detects(self, mut=frozenset(), override=None, copy=None):
        _, bad, _ = j.eval_revert(self.image, copy or j.REVERT[0], self.rev, override, mut, stop=True)
        return bad > 0

    def wr_detects(self, mut=frozenset(), override=None):
        _, bad, _ = j.eval_write(self.image, j.WRITE[0], self.wr, override, mut, stop=True)
        return bad > 0

    def test_wrong_digest_rejected(self):
        data = bytearray(j.BINARY.read_bytes())
        data[self.image.text["offset"] + 3] ^= 0x10
        with self.assertRaises(j.ToolError):
            j.Image(bytes(data))

    def test_code_outside_text_rejected(self):
        end = self.image.text["address"] + self.image.text["size"]
        with self.assertRaises(j.ToolError):
            self.image.code(end + 0x10, 4)

    def test_all_three_revert_copies_match(self):
        for copy in j.REVERT:
            _, bad, m = j.eval_revert(self.image, copy, j.pool("rev", copy, 300))
            self.assertEqual(bad, 0, hex(copy))
            self.assertGreater(len(m.seen), 90)

    def test_write_matches(self):
        out, bad, _ = j.eval_write(self.image, j.WRITE[0], self.wr)
        self.assertEqual(bad, 0)
        kinds = {(k, tuple(sorted({e[0] for e in ev}))) for _, k, _, ev, _, _ in out}
        self.assertIn(("panic", ()), kinds)
        self.assertIn(("ret", ("grow", "slow")), kinds)

    def test_static_constants(self):
        consts, _ = j.static_evidence(self.image)
        self.assertEqual(consts["revert_copy_byte_differences_vs_0x29710e0"]["0x4322f30"],
                         ["0xb8", "0xb9", "0xba", "0xbb", "0x14e", "0x14f", "0x150", "0x151"])
        self.assertEqual(consts["revert_got_slots"]["0x29710e0"]["applier"], "0x64e6d68")
        self.assertEqual(consts["revert_got_slots"]["0x29710e0"]["dealloc"], "0x64df4a0")
        self.assertEqual(consts["write_got_slots"]["seed"], "0x64dfa78")

    def test_call_site_roles_refuse_other_bodies(self):
        # 0x4323110 is the lookup-calling sibling of the write body, not a copy of it
        with self.assertRaises(j.ToolError):
            j.write_slots(self.image, 0x4323110)
        with self.assertRaises(j.ToolError):
            j.revert_slots(self.image, 0x29712c0)

    def test_model_mutants_detected(self):
        for name in j.REV_MUTANTS:
            self.assertTrue(self.rev_detects(mut=frozenset([name])), name)
        for name in j.WR_MUTANTS:
            self.assertTrue(self.wr_detects(mut=frozenset([name])), name)

    def test_code_byte_mutants_detected(self):
        # first-jcc flips in the revert and write bodies, one in a sibling revert copy
        lo = j.REVERT[0]
        for va in j.jcc_flip_sites(self.image, lo, lo, lo + 0x19b)[:4]:
            self.assertTrue(self.rev_detects(override={va: self.image.code(va, 1)[0] ^ 1}), hex(va))
        copy = j.REVERT[2]
        va = j.jcc_flip_sites(self.image, copy, copy, copy + 0x19b)[0]
        self.assertTrue(self.rev_detects(override={va: self.image.code(va, 1)[0] ^ 1}, copy=copy))
        base = j.WRITE[0]
        for va in j.jcc_flip_sites(self.image, base, base, base + 0x1ed)[:6]:
            self.assertTrue(self.wr_detects(override={va: self.image.code(va, 1)[0] ^ 1}), hex(va))

    def test_range_checks_on_model_inputs(self):
        # a checkpoint above the log length must leave the logs alone, below it must cut them
        c = dict(self.rev[0], nlogs=2, ck=(5, 0, 0), jlen=0, journal=[], water=0, depth=0)
        ev, state = j.model_revert(c)
        self.assertEqual((ev, state["nlogs"], state["depth"]), ([], 2, 0))
        c = dict(c, logs=[{"cap": 3, "ptr": 0x1000, "data": 7, "len": 9, "fill": bytes(0x50)}] * 2, ck=(1, 0, 0))
        ev, state = j.model_revert(c)
        self.assertEqual((ev, state["nlogs"]), ([("dealloc", 0x1000, 96, 0), ("drop", 1, 7, 9)], 1))


if __name__ == "__main__":
    unittest.main()
