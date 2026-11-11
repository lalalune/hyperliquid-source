import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re11_access_list115 as t  # noqa: E402


class AccessList115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = t.Image(t.BINARY.read_bytes())
        t.EMPTY_CTRL = cls.image.word(t.TEMPLATE)
        t.SEED_AT = cls.image.word(t.SEED_GOT)
        cls.loader = t.loader_cases()
        cls.direct = t.direct_cases()

    def run_loader(self, cases, mut=frozenset(), override=None):
        m = t.Machine(self.image, override)
        bad = 0
        for c in cases:
            try:
                bad += not t.compare_loader(t.loader_model(c, mut), t.run_loader(m, c))
            except t.ToolError:
                bad += 1
        return bad

    def run_direct(self, cases, mut=frozenset(), override=None):
        m = t.Machine(self.image, override)
        bad = 0
        for c in cases:
            try:
                bad += t.direct_model(c, mut) != t.run_direct(m, c)
            except t.ToolError:
                bad += 1
        return bad

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
        consts, decoded = t.static_evidence(self.image)
        self.assertEqual(consts["slots"]["byte_hasher"]["target"], "0x1770830")
        self.assertEqual(consts["slots"]["lazy_init"]["target"], "0x1770b40")
        self.assertEqual(consts["global_seed_block"]["address"], "0x64ffe90")
        self.assertEqual(consts["global_seed_block"]["section"], ".bss")
        self.assertEqual(consts["empty_table_template"]["empty_group_bytes"], "ff" * 16)
        self.assertEqual(consts["insert_counter_constant"]["words"][1], "0xffffffffffffffff")
        self.assertEqual(consts["functions"]["0x2668a20"]["fde_end"], "0x2668e7a")
        self.assertEqual(sorted(decoded), sorted(t.FUNCS))

    def test_sample_matches(self):
        self.assertEqual(self.run_loader(self.loader[::25]), 0)
        self.assertEqual(self.run_direct(self.direct[::9]), 0)

    def test_foldhash_lengths(self):
        g = [0x1234567 * (k + 3) for k in range(6)]
        self.assertIsNone(t.bytes_hash(bytes(15), 1, g))
        for n in (16, 32, 128, 129, 256, 257, 1000):
            c = {"fn": "bytes", "data": bytes(range(256)) * 4, "seed": 99, "g": g}
            c["data"] = c["data"][:n]
            self.assertEqual(t.run_direct(t.Machine(self.image), c), t.direct_model(c))

    def test_key_byte_order(self):
        word = bytes(range(32))
        self.assertEqual(t.key_limbs(word), word[::-1])

    def test_model_mutants_detected(self):
        for name in ("map_seed_raw", "pad_zero", "seed_no_chain", "add_full", "no_bswap", "addr_swap"):
            with self.subTest(name=name):
                self.assertGreater(self.run_loader(self.loader[:60], mut=frozenset([name])), 0)
        for name in ("medium_ge32", "prefix_one", "no_rol"):
            with self.subTest(name=name):
                self.assertGreater(self.run_direct(self.direct, mut=frozenset([name])), 0)

    def test_code_mutants_detected(self):
        for va, byte in ((0x2668ac9, 0x45), (0x2668b73, 0x28), (0x2a3190f, 0x38), (0x2a3198d, 0xfe)):
            with self.subTest(va=hex(va)):
                self.assertNotEqual(self.image.code(va, 1)[0], byte)
                self.assertGreater(self.run_loader(self.loader[:60], override={va: byte}), 0)
        for va, byte in ((0x24b70a6, 0x05), (0x1770881, 0x20), (0x177099a, 0x7f)):
            with self.subTest(va=hex(va)):
                self.assertNotEqual(self.image.code(va, 1)[0], byte)
                self.assertGreater(self.run_direct(self.direct, override={va: byte}), 0)


if __name__ == "__main__":
    unittest.main()
