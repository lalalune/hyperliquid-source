"""Real digest-bound static replay and field-level corruption controls; no target execution."""
import importlib.util
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-001-node115-block-reader-corruption-boundary"
spec = importlib.util.spec_from_file_location("block_reader_boundary", PACKET / "replay.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = ROOT / m.TARGET
        cls.data = bytearray(cls.target.read_bytes())
        m.authenticate(cls.data)
        cls.frames = subprocess.run(["readelf", "--debug-dump=frames", str(cls.target)], check=True, capture_output=True, text=True).stdout

    def test_real_target(self):
        result = m.verify_content(self.data, self.frames)
        self.assertEqual(result["call_target"], "0x2698f40")
        self.assertEqual(result["branch_taken"], "0x2b2c0a0")
        self.assertFalse(result["captured_target_executed"])

    def corrupt(self, offset, message, mask=1):
        # Skip only the outer digest gate so controls exercise the relevant inner proof.
        old = self.data[offset]
        try:
            self.data[offset] ^= mask
            with self.assertRaisesRegex(ValueError, message):
                m.verify_content(self.data, self.frames)
        finally:
            self.data[offset] = old

    def test_location_reference_corruption(self):
        self.corrupt(m.Elf(self.data).offset(m.ANCHOR + 3, 1), "instruction sequence")

    def test_rcx_preservation_corruption(self):
        self.corrupt(m.Elf(self.data).offset(0x2b2c077, 1), "instruction sequence", mask=3)

    def test_call_target_corruption(self):
        self.corrupt(m.Elf(self.data).offset(m.CALL + 1, 1), "instruction sequence")

    def test_branch_target_corruption(self):
        self.corrupt(m.Elf(self.data).offset(m.BRANCH + 1, 1), "instruction sequence")

    def test_location_layout_corruption(self):
        self.corrupt(m.Elf(self.data).offset(m.LOCATION + 8, 1), "length/line/column")

    def test_relocation_corruption(self):
        _, offset = m.Elf(self.data).relative(m.LOCATION)
        self.corrupt(offset + 16, "relocation addend")

    def test_source_corruption(self):
        self.corrupt(m.Elf(self.data).offset(0x4422bd, 1), "source path")

    def test_caller_fde_control(self):
        with self.assertRaisesRegex(ValueError, "caller FDE"):
            m.verify_content(self.data, self.frames.replace("pc=0000000002b2be60..0000000002b2c4f1", "pc=0000000002b2be60..0000000002b2c078"))

    def test_callee_fde_control(self):
        with self.assertRaisesRegex(ValueError, "callee entry FDE"):
            m.verify_content(self.data, self.frames.replace("pc=0000000002698f40..00000000026990ca", "pc=0000000002698f41..00000000026990ca"))

    def test_digest_gate(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            m.authenticate(b"not the pinned node")

    def test_unmapped_va(self):
        with self.assertRaisesRegex(ValueError, "PT_LOAD"):
            m.Elf(self.data).offset(0xffffffffffffffff, 1)


if __name__ == "__main__":
    unittest.main()
