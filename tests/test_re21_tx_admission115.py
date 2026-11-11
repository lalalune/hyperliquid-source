import hashlib
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re21_tx_admission115 as tool  # noqa: E402

PACKET = ROOT / "research" / "work-items" / "RE-021-tx-admission-115"


class TxAdmission115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = tool.BINARY.read_bytes()
        cls.image = tool.Image(cls.data)
        cls.fdes = tool.fde_rows(cls.image, {tool.VALIDATE, tool.ADMIT, tool.COST})
        cls.consts, cls.listing = tool.static_evidence(cls.image, cls.fdes)

    def test_wrong_digest_is_rejected(self):
        bad = bytearray(self.data)
        bad[0x2b91c1c] ^= 1
        with self.assertRaises(tool.ToolError):
            tool.Image(bytes(bad))

    def test_static_constants_from_bytes(self):
        b = self.consts["boundaries"]
        self.assertEqual((b["gas_cap"], b["initcode"], b["initcode_rev14"], b["floor_revision_gt"]),
                         (1 << 24, 0xc000, 0x10000, 11))
        self.assertEqual(self.consts["jump_table"]["targets"],
                         ["0x2b92cea", "0x2b92ce1", "0x2b92de1", "0x2b92e9e", "0x2b92d65"])
        self.assertEqual(self.consts["relocated_slots"]["cost_callee"]["target"], "0x5be0720")
        self.assertEqual(self.fdes[tool.VALIDATE], (0x2b92c10, 0x2b93026))

    def test_unsupported_and_out_of_range(self):
        with self.assertRaises(tool.ToolError):
            tool.decode(bytes([0x0f, 0x0b]) + bytes(14), 0)  # ud2 is outside the supported subset
        with self.assertRaises(tool.ToolError):
            self.image.read(0x10, 8)  # below every file-backed section
        with self.assertRaises(tool.ToolError):
            tool.fde_rows(self.image, {tool.VALIDATE + 1})
        with self.assertRaises(tool.ToolError):
            tool.Mem(bytes(tool.CTX_SIZE), bytes(32)).record_byte(tool.LIST_AT, 32)

    def test_reference_values(self):
        sched = dict(tool.MODE13_SCHEDULE)
        blake = (12).to_bytes(4, "big") + bytes(208) + b"\x01"
        self.assertEqual(tool.cost(sched, blake, False, 0, 0, 0), [21876, 0, 0, 23190])
        ctx = tool._base_ctx(15, 2)
        self.assertEqual(tool.validate(tool.Mem(ctx, bytes(32)))["tag"], 0x25)

    def test_real_code_matches_model_and_controls_are_detected(self):
        result = tool.evaluate(self.image, consts=self.consts)
        self.assertEqual(result["bad"], 0)
        self.assertGreater(len(result["validate"]), 4500)
        self.assertGreater(len(result["path"]), 1500)
        for name in ("fee-cap-le", "blob-max-ge", "floor-from-rev11", "drop-auth-term"):
            self.assertEqual(tool.evaluate(self.image, mut=frozenset([name]), consts=self.consts,
                                           stop_on_first=True)["bad"], 1, name)
        for va, old, new in tool.CODE_MUTANTS[:2]:
            self.assertEqual(self.image.code(va, 1)[0], old)
            self.assertEqual(tool.evaluate(self.image, override={va: new}, consts=self.consts,
                                           stop_on_first=True)["bad"], 1)

    def test_packet_files_regenerate_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool.generate(tmp)
            produced = sorted(p.name for p in pathlib.Path(tmp).iterdir())
            for name in produced:
                self.assertEqual(hashlib.sha256((pathlib.Path(tmp) / name).read_bytes()).hexdigest(),
                                 hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), name)
            manifest = (PACKET / "MANIFEST.sha256").read_text().split()
            for digest, name in zip(manifest[0::2], manifest[1::2]):
                self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)


if __name__ == "__main__":
    unittest.main()
