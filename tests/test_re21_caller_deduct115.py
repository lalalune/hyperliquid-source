import hashlib
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re21_caller_deduct115 as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-021-caller-deduct-115"
M64 = tool.M64


def base_case(**kw):
    c = {"skip_code": 0, "code": (0, 0), "skip_nonce": 0, "tx_nonce": 5, "nonce": 5,
         "balance": 1000, "payer": (tool.OK_TAG, 400), "flags": 0, "kind": 1,
         "address": bytes(range(1, 21)), "cap": 1, "len": 1}
    c.update(kw)
    return c


class CallerDeduct115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = tool.BINARY.read_bytes()
        cls.image = tool.Image(cls.data)
        cls.consts, cls.rows = tool.static_evidence(cls.image)

    def test_wrong_digest_is_rejected(self):
        bad = bytearray(self.data)
        bad[0x29a1d84] ^= 1
        with self.assertRaises(tool.ToolError):
            tool.Image(bytes(bad))

    def test_static_facts_from_bytes(self):
        a, b = self.consts["drivers"]["A"], self.consts["drivers"]["B"]
        self.assertEqual(a["fde"][0], "0x29a1290")
        self.assertIn(["0x29a1d84", "0x2973440"], a["calls"])
        self.assertIn(["0x2963553", "0x2973440"], b["calls"])
        self.assertEqual([t for _, t in a["journal_tag_stores"]], [2, 3, 2, 6])
        self.assertEqual([t for _, t in b["journal_tag_stores"]], [2, 3, 2, 6])
        self.assertEqual(sum(1 for c in a["calls"] if c[1].startswith("slot")), 4)
        self.assertEqual(self.consts["journal_entry_stride"], 0x58)

    def test_out_of_range_and_unsupported(self):
        t = self.image.text
        with self.assertRaises(tool.ToolError):
            self.image.code(t["address"] + t["size"] + 0x100, 4)
        with self.assertRaises(tool.ToolError):
            self.image.read(0x10, 8)
        with self.assertRaises(tool.ToolError):
            tool.decode(bytes([0xd9, 0xee]) + bytes(14), 0)
        with self.assertRaises(tool.ToolError):
            tool.fde_of(self.image, 0x10)

    def test_reference_values(self):
        out = tool.model(base_case())
        self.assertEqual(out[0], "ok")
        self.assertEqual([t for t, _ in out[3]], [2, 3, 6])
        self.assertEqual((out[4], out[5], out[6]), (400, 6, 4))
        self.assertEqual(tool.model(base_case(tx_nonce=6))[:2], ("reject", 9))
        self.assertEqual(tool.model(base_case(tx_nonce=4))[:2], ("reject", 10))
        self.assertEqual(tool.model(base_case(tx_nonce=M64, nonce=M64))[:2], ("reject", 8))
        self.assertEqual(tool.model(base_case(code=(3, 0)))[:2], ("reject", 5))
        self.assertEqual(tool.model(base_case(code=(3, 1)))[0], "ok")
        sat = tool.model(base_case(tx_nonce=M64, nonce=M64, skip_nonce=1))
        self.assertEqual((sat[5], [t for t, _ in sat[3]]), (M64, [2, 3]))

    def test_real_code_matches_model_on_reference_cases(self):
        m = tool.Fragment(self.image)
        for driver in tool.DRIVERS:
            for c in (base_case(), base_case(tx_nonce=6), base_case(code=None),
                      base_case(payer=(6, 0)), base_case(skip_nonce=1, tx_nonce=0, nonce=M64)):
                self.assertEqual(tool.run_case(m, driver, c), tool.expected(driver, c), (driver, c))

    def test_controls_are_detected(self):
        for name in ("swap_9_10", "bump_wraps", "journal_new_balance", "touch_always"):
            for driver in tool.DRIVERS:
                _, bad, _ = tool.evaluate(self.image, driver, mut=frozenset([name]), stop_on_first=True)
                if bad:
                    break
            self.assertEqual(bad, 1, name)
        driver, va, byte, _ = tool.BYTE_MUTANTS[0]
        _, bad, _ = tool.evaluate(self.image, driver, override={va: byte}, stop_on_first=True)
        self.assertEqual(bad, 1)

    def test_packet_files_regenerate_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = tool.generate(pathlib.Path(tmp))
            self.assertEqual(summary["mismatches"], 0)
            nc = summary["negative_controls"]
            self.assertEqual(nc["detected"], nc["total"])
            produced = sorted(p.name for p in pathlib.Path(tmp).iterdir())
            for name in produced:
                self.assertEqual(hashlib.sha256((pathlib.Path(tmp) / name).read_bytes()).hexdigest(),
                                 hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), name)
            manifest = (PACKET / "MANIFEST.sha256").read_text().split()
            self.assertEqual(sorted(manifest[1::2]), sorted(produced + ["README.md"]))
            for digest, name in zip(manifest[0::2], manifest[1::2]):
                self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)


if __name__ == "__main__":
    unittest.main()
