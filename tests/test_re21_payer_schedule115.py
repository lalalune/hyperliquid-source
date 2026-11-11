import hashlib
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re21_payer_schedule115 as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-021-payer-schedule-115"


class PayerSchedule115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = tool.BINARY.read_bytes()
        cls.image = tool.Image(cls.data)
        cls.fdes = tool.fde_rows(cls.image, {tool.CTOR, tool.PAYER, tool.COST})
        cls.consts, cls.listing = tool.static_evidence(cls.image, cls.fdes)

    def test_wrong_digest_is_rejected(self):
        bad = bytearray(self.data)
        bad[0x2972440] ^= 1
        with self.assertRaises(tool.ToolError):
            tool.Image(bytes(bad))

    def test_static_facts_from_bytes(self):
        self.assertEqual(self.fdes[tool.CTOR], (0x5be2560, 0x5be29c7))
        self.assertEqual(self.fdes[tool.PAYER], (0x2973440, 0x29738de))
        self.assertEqual(self.consts["relocated_slots"]["memset"]["import"], "memset")
        self.assertEqual(self.consts["relocated_slots"]["panic_mul_overflow"]["target"], "0x1681dc0")
        self.assertTrue(self.consts["unwrap_message"]["text"].startswith("effective balance is always smaller"))
        imms = {(r["fn"], r["insn"]): r["imm"] for r in self.consts["compare_immediates"]}
        self.assertEqual(imms[("ctor", "0x5be287e")], "0xc")
        self.assertEqual(imms[("payer", "0x2973524")], "0x3")

    def test_unsupported_and_out_of_range(self):
        with self.assertRaises(tool.ToolError):
            tool.decode(bytes([0xd9, 0xee]) + bytes(14), 0)  # x87 is outside the supported subset
        with self.assertRaises(tool.ToolError):
            self.image.read(0x10, 8)  # below every file-backed section
        with self.assertRaises(tool.ToolError):
            tool.fde_rows(self.image, {tool.PAYER + 1})
        m = tool.Machine(self.image)
        with self.assertRaises(tool.ToolError):
            m.store(0x1234, 8, 0)  # not a writable region

    def test_reference_values(self):
        w = tool.schedule_words(13)
        self.assertEqual((w[0xf0], w[0xf8], w[0x100], w[0x108], w[0x120], w[0x128], w[0xe8]),
                         (4, 4, 10, 21000, 21000, 32000, 25000))
        self.assertEqual(tool.cost(w, tool.BLAKE_INPUT, False, 0, 0, 0), [21876, 0, 0, 23190])
        tx = tool.tx_bytes(21000, 10, 5, 0)
        self.assertEqual(tool.payer(210004, tx, tool.ctx_bytes())["tag"], 6)
        self.assertEqual(tool.payer(210005, tx, tool.ctx_bytes())["value"], 5)

    def test_real_code_matches_model_and_controls_are_detected(self):
        result = tool.evaluate(self.image, consts=self.consts)
        self.assertEqual(result["bad"], 0)
        self.assertEqual(len(result["modes"]), 257)
        self.assertGreater(len(result["payer"]), 3000)
        self.assertEqual(len(result["compose"]), 256 * len(tool.COMPOSE_INPUTS))
        for name in ("mode14-as-13", "aux-unsaturated", "clamp-missing", "cost-uses-mode13"):
            self.assertEqual(tool.evaluate(self.image, mut=frozenset([name]), consts=self.consts,
                                           stop_on_first=True)["bad"], 1, name)
        for va, x in tool.CODE_MUTANTS[:1] + tool.CODE_MUTANTS[6:7]:
            old = self.image.code(va, 1)[0]
            self.assertEqual(tool.evaluate(self.image, override={va: old ^ x}, consts=self.consts,
                                           stop_on_first=True)["bad"], 1)

    def test_packet_files_regenerate_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool.generate(tmp)
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
