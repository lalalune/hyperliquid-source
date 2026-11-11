import itertools
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_code_object_prep115 as tool  # noqa: E402

IMAGE = tool.Image(tool.BINARY.read_bytes())
CASES = list(itertools.islice(tool.case_stream(), 0, 12000, 3))


class StaticEvidence(unittest.TestCase):
    def test_extents_calls_and_slots(self):
        consts, decoded = tool.static_evidence(IMAGE)
        self.assertEqual(consts["functions"]["0x54793e0"]["fde_bytes"], 596)
        self.assertEqual(consts["functions"]["0x433c700"]["fde_bytes"], 291)
        self.assertEqual(consts["functions"]["0x4ef7e50"]["fde_bytes"], 349)
        self.assertEqual(consts["direct_calls"]["0x433c700"]["0x433c77a"], "0x3d48830")
        self.assertEqual(consts["direct_calls"]["0x54793e0"]["0x5479472"], "0x4ef7e50")
        self.assertEqual(consts["got_slots"]["0x64e6458"], "0x43c8ec0")
        self.assertEqual(tool.EMPTY_HASH.hex(), consts["empty_code_hash"])

    def test_empty_hash_is_keccak_of_nothing(self):
        self.assertEqual(IMAGE.read(tool.CONST_LO, 16) + IMAGE.read(tool.CONST_HI, 16), tool.EMPTY_HASH)

    def test_wrong_digest_refused(self):
        bad = bytearray(IMAGE.data)
        bad[IMAGE.text["offset"] + 3] ^= 0x40
        with self.assertRaises(tool.ToolError):
            tool.Image(bytes(bad))

    def test_address_outside_text_refused(self):
        with self.assertRaises(tool.ToolError):
            IMAGE.code(IMAGE.text["address"] + IMAGE.text["size"] + 0x40, 8)


class Reconstruction(unittest.TestCase):
    def test_cases_match_machine_code(self):
        n, bad, _ = tool.evaluate(IMAGE, cases=CASES)
        self.assertEqual((n, bad), (len(CASES), 0))

    def test_inc_trap_rule(self):
        self.assertFalse(tool.inc_traps(0x7fff_ffff_ffff_ffff))
        self.assertTrue(tool.inc_traps(tool.M64))
        self.assertTrue(tool.inc_traps(tool.M64 - 1))
        self.assertFalse(tool.inc_traps(0))
        self.assertTrue(tool.inc_traps(0x8000_0000_0000_0000))

    def test_probe_wraps_to_group_zero_on_small_tables(self):
        ctrl = bytearray(b"\x11" * 4 + b"\x11" * 4 + b"\xff" * 12)
        ctrl[2] = 0xff
        ctrl[6] = 0xff
        self.assertEqual(tool.probe(ctrl, 3, 3, frozenset()), 2)

    def test_entry_hash_and_probe_model(self):
        key = bytes(range(32))
        tab = {"cap": 16, "ctrl": bytearray(b"\xff" * 32), "buckets": bytearray(16 * 40), "secret": 5}
        self.assertEqual(tool.entry_find(tab, key, 9)[0], None)
        h = tool.key_hash(key, 5, 9)
        idx = tool.probe(tab["ctrl"], 15, h, frozenset())
        tool.set_ctrl(tab["ctrl"], 15, idx, h >> 57)
        pos = 16 * 40 - 40 * (idx + 1)
        tab["buckets"][pos:pos + 32] = key
        self.assertEqual(tool.entry_find(tab, key, 9), (idx, h))
        self.assertIsNone(tool.entry_find(tab, bytes(32), 9)[0])
        self.assertNotEqual(tool.key_hash(key, 5, 9), tool.key_hash(key, 6, 9))

    def test_empty_slot_hash_default_path(self):
        c = next(x for x in CASES if x["hash"] == tool.EMPTY_HASH and x["acc70"] == 0 and x["reent"] is None)
        want = tool.model(c)
        self.assertEqual(want[0] in ("ok", "ud2"), True)
        self.assertEqual(tool.run_case(tool.build_machine(IMAGE), c), want)


class NegativeControls(unittest.TestCase):
    def test_model_mutants_detected(self):
        for name in tool.MODEL_MUTANTS:
            n, bad, _ = tool.evaluate(IMAGE, mut=frozenset([name]), stop_on_first=True, cases=CASES)
            self.assertGreater(bad, 0, name)

    def test_code_mutants_detected(self):
        _, decoded = tool.static_evidence(IMAGE)
        mutants = tool.jcc_mutants(decoded)
        self.assertGreaterEqual(len(mutants), 20)
        for f, va, pos, byte in mutants[::4]:
            n, bad, _ = tool.evaluate(IMAGE, override={pos: byte}, stop_on_first=True, cases=CASES)
            self.assertGreater(bad, 0, hex(va))

    def test_corrupted_hash_byte_is_detected(self):
        c = next(x for x in CASES if x["func"] == tool.HOT and x["acc70"] == 0 and x["hash"] != tool.EMPTY_HASH)
        want = tool.model(c)
        m = tool.build_machine(IMAGE)
        got = tool.run_case(m, dict(c, hash=bytes([c["hash"][0] ^ 1]) + c["hash"][1:]))
        self.assertNotEqual(want, got)


if __name__ == "__main__":
    unittest.main()
