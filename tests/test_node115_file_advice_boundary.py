"""Target-grounded positive proof and byte-corruption rejection controls."""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("file_advice_proof", ROOT / "research/work-items/RE-001-node115-file-advice-boundary/verify.py")
proof = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proof)


class FileAdviceBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / proof.TARGET).read_bytes()
        cls.image = proof.Image(cls.data)

    def corrupt(self, va, pattern):
        changed = bytearray(self.data)
        off = self.image.offset(va, len(pattern))
        changed[off:off + len(pattern)] = pattern
        with self.assertRaises(ValueError):
            proof.structure(changed)

    def test_actual_authenticated_target_and_tools(self):
        result, decoded = proof.verify(ROOT / proof.TARGET)
        self.assertEqual(result["function_bytes"], 204)
        self.assertEqual(result["fde_matches"], 1)
        self.assertEqual(len(result["selector_to_advice"]), 5)
        self.assertIn("6021557:", decoded)

    def test_mutated_advice_immediate(self):
        self.corrupt(0x602154d, b"\x05")

    def test_mutated_body_gate(self):
        self.corrupt(proof.START, b"\x90")

    def test_mutated_jump_table(self):
        self.corrupt(proof.TABLE, b"\x00\x00\x00\x00")

    def test_mutated_thunk_target(self):
        self.corrupt(0x601ed45, b"\x00\x00\x00\x00")

    def test_mutated_plt_slot(self):
        self.corrupt(0x63f1682, b"\x00\x00\x00\x00")

    def test_mutated_relocation_type(self):
        section = self.image.named[".rela.plt"]
        import struct
        for off in range(section[4], section[4] + section[5], 24):
            if struct.unpack_from("<Q", self.data, off)[0] == 0x64ee790:
                changed = bytearray(self.data)
                changed[off + 8] = 0
                with self.assertRaisesRegex(ValueError, "JUMP_SLOT"):
                    proof.structure(changed)
                return
        self.fail("required relocation absent")

    def test_mutated_machine(self):
        changed = bytearray(self.data); changed[18] = 0
        with self.assertRaisesRegex(ValueError, "x86-64"):
            proof.structure(changed)


if __name__ == "__main__":
    unittest.main()
